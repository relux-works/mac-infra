import Foundation
import Darwin
import Network
import NetworkExtension
import Security
import os

private let flowLogger = Logger(subsystem: "works.relux.mac-infra.netfilter", category: "flow")

private struct AppIdentity {
    var signingID: String?
    var teamID: String?
    var path: String?
    var pid: Int32?
}

private func auditToken(from data: Data?) -> audit_token_t? {
    guard let data, data.count == MemoryLayout<audit_token_t>.size else { return nil }
    var token = audit_token_t()
    withUnsafeMutableBytes(of: &token) { $0.copyBytes(from: data) }
    return token
}

private func identity(of data: Data?) -> AppIdentity {
    var result = AppIdentity()
    guard let data, let token = auditToken(from: data) else { return result }
    result.pid = audit_token_to_pid(token)

    let tokenData = data as CFData
    var code: SecCode?
    let attrs = [kSecGuestAttributeAudit: tokenData] as CFDictionary
    guard SecCodeCopyGuestWithAttributes(nil, attrs, [], &code) == errSecSuccess, let code else {
        return result
    }
    var staticCode: SecStaticCode?
    guard SecCodeCopyStaticCode(code, [], &staticCode) == errSecSuccess, let staticCode else {
        return result
    }
    var info: CFDictionary?
    if SecCodeCopySigningInformation(staticCode, SecCSFlags(rawValue: kSecCSSigningInformation), &info) == errSecSuccess,
       let dict = info as? [String: Any] {
        result.signingID = dict[kSecCodeInfoIdentifier as String] as? String
        result.teamID = dict[kSecCodeInfoTeamIdentifier as String] as? String
    }
    var url: CFURL?
    if SecCodeCopyPath(staticCode, [], &url) == errSecSuccess, let url {
        result.path = (url as URL).path
    }
    return result
}

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
        var event: [String: Any] = [:]
        event["ts"] = isoFormatter.string(from: Date())
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
        let app = identity(of: appToken)
        event["app_signing_id"] = app.signingID ?? null
        event["app_team_id"] = app.teamID ?? null
        event["app_path"] = app.path ?? null
        event["app_pid"] = app.pid.map { Int($0) } ?? null

        event["via_process_path"] = null
        if let procToken = flow.sourceProcessAuditToken, procToken != appToken {
            event["via_process_path"] = identity(of: procToken).path ?? null
        }

        guard JSONSerialization.isValidJSONObject(event),
              let data = try? JSONSerialization.data(withJSONObject: event, options: [.sortedKeys]) else {
            return nil
        }
        return String(data: data, encoding: .utf8)
    }
}
