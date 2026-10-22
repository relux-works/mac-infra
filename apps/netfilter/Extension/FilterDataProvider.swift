import Foundation
import Darwin
import Network
import NetworkExtension
import Security
import os

private let flowLogger = Logger(subsystem: "works.relux.mac-infra.netfilter", category: "flow")

private func endpointParts(_ endpoint: Network.NWEndpoint?) -> (host: String?, port: Int?) {
    guard let endpoint else { return (nil, nil) }
    switch endpoint {
    case let .hostPort(host, port):
        return ("\(host)", Int(port.rawValue))
    default:
        return (nil, nil)
    }
}

private let isoFormatter: ISO8601DateFormatter = {
    let f = ISO8601DateFormatter()
    f.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
    return f
}()

class FilterDataProvider: NEFilterDataProvider {

    override func startFilter(completionHandler: @escaping (Error?) -> Void) {
        let settings = NEFilterSettings(rules: [], defaultAction: .filterData)
        apply(settings) { error in
            completionHandler(error)
        }
    }

    override func stopFilter(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        completionHandler()
    }

    override func handleNewFlow(_ flow: NEFilterFlow) -> NEFilterNewFlowVerdict {
        if let json = Self.eventJSON(for: flow) {
            flowLogger.info("\(json, privacy: .public)")
        }
        return .allow()
    }

    private static func eventJSON(for flow: NEFilterFlow) -> String? {
        let null = NSNull()
        let observedAt = Date()
        var event: [String: Any] = [:]
        event["ts"] = isoFormatter.string(from: observedAt)
        event["flow_id"] = flow.identifier.uuidString
        event["direction"] = flow.direction == .inbound ? "inbound" : "outbound"
        event["remote_hostname"] = null
        event["remote_host"] = null
        event["remote_port"] = null
        event["local_port"] = null
        event["proto"] = null

        if let socketFlow = flow as? NEFilterSocketFlow {
            switch socketFlow.socketProtocol {
            case IPPROTO_TCP: event["proto"] = "tcp"
            case IPPROTO_UDP: event["proto"] = "udp"
            default: event["proto"] = Int(socketFlow.socketProtocol)
            }
            if let name = socketFlow.remoteHostname { event["remote_hostname"] = name }
            let remote = endpointParts(socketFlow.remoteFlowEndpoint)
            if let h = remote.host { event["remote_host"] = h }
            if let p = remote.port { event["remote_port"] = p }
            let local = endpointParts(socketFlow.localFlowEndpoint)
            if let p = local.port { event["local_port"] = p }
        }

        let appToken = flow.sourceAppAuditToken
        let app = resolve(auditToken: appToken, observedAt: observedAt)
        event["app_signing_id"] = app.signingID ?? null
        event["app_team_id"] = app.teamID ?? null
        event["app_path"] = app.path ?? null
        event["app_pid"] = app.pid.map { Int($0) } ?? null
        event["app_signing_status"] = app.status.rawValue
        event["app_identity_source"] = app.source.rawValue

        event["via_process_path"] = null
        if let procToken = flow.sourceProcessAuditToken, procToken != appToken {
            event["via_process_path"] = resolve(auditToken: procToken, observedAt: observedAt).path ?? null
        }

        guard JSONSerialization.isValidJSONObject(event),
              let data = try? JSONSerialization.data(withJSONObject: event, options: [.sortedKeys]) else {
            return nil
        }
        return String(data: data, encoding: .utf8)
    }
}
