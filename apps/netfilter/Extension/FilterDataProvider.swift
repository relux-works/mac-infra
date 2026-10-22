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

    /// Bytes a watched flow passes between two data callbacks: no payload is
    /// kept, the callback only keeps the flow reachable for a kill.
    static let passWindow = 1 << 20

    override func startFilter(completionHandler: @escaping (Error?) -> Void) {
        EnforcementState.shared.provider = self
        EnforcementState.shared.reloadProtectList()
        ControlService.start()
        let settings = NEFilterSettings(rules: [], defaultAction: .filterData)
        apply(settings) { error in
            completionHandler(error)
        }
    }

    override func stopFilter(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        completionHandler()
    }

    override func handleNewFlow(_ flow: NEFilterFlow) -> NEFilterNewFlowVerdict {
        let (json, facts) = Self.event(for: flow)
        if let json {
            flowLogger.info("\(json, privacy: .public)")
        }
        guard let socketFlow = flow as? NEFilterSocketFlow else { return .allow() }
        switch EnforcementState.shared.decide(id: flow.identifier.uuidString, facts: facts, flow: socketFlow) {
        case .allow:
            return .allow()
        case .drop(let rule):
            EnforcementState.shared.logAction(["op": "blocked_new", "rule_id": rule.id, "flow_id": flow.identifier.uuidString, "app": facts.appPath ?? facts.signingID ?? "unknown", "host": facts.hostname ?? facts.remoteIP ?? "unknown", "ok": true])
            return .drop()
        case .watch:
            return .filterDataVerdict(withFilterInbound: true, peekInboundBytes: 1, filterOutbound: true, peekOutboundBytes: 1)
        }
    }

    override func handleInboundData(from flow: NEFilterFlow, readBytesStartOffset offset: Int, readBytes: Data) -> NEFilterDataVerdict {
        NEFilterDataVerdict(passBytes: readBytes.count + Self.passWindow, peekBytes: 1)
    }

    override func handleOutboundData(from flow: NEFilterFlow, readBytesStartOffset offset: Int, readBytes: Data) -> NEFilterDataVerdict {
        NEFilterDataVerdict(passBytes: readBytes.count + Self.passWindow, peekBytes: 1)
    }

    override func handleInboundDataComplete(for flow: NEFilterFlow) -> NEFilterDataVerdict {
        EnforcementState.shared.closed(id: flow.identifier.uuidString)
        return .allow()
    }

    override func handleOutboundDataComplete(for flow: NEFilterFlow) -> NEFilterDataVerdict {
        EnforcementState.shared.closed(id: flow.identifier.uuidString)
        return .allow()
    }

    private static func event(for flow: NEFilterFlow) -> (String?, FlowFacts) {
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

        let remoteHost = event["remote_host"] as? String
        let isIP = remoteHost.map { IPv4Address($0) != nil || IPv6Address($0) != nil } ?? false
        let facts = FlowFacts(appPath: app.path, signingID: app.signingID, hostname: event["remote_hostname"] as? String,
                              remoteIP: isIP ? remoteHost : nil, remotePort: event["remote_port"] as? Int)
        guard JSONSerialization.isValidJSONObject(event),
              let data = try? JSONSerialization.data(withJSONObject: event, options: [.sortedKeys]) else {
            return (nil, facts)
        }
        return (String(data: data, encoding: .utf8), facts)
    }
}
