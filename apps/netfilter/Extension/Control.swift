import Foundation
import NetworkExtension
import Security
import os

private let actionLogger = Logger(subsystem: "works.relux.mac-infra.netfilter", category: "action")

/// The extension's enforcement state, shared by the filter callbacks and the
/// control service. All engine access goes through the lock.
final class EnforcementState: @unchecked Sendable {
    static let shared = EnforcementState()

    private let lock = NSLock()
    private var engine = Engine<NEFilterSocketFlow>(capacity: 4096, protect: nil)
    weak var provider: NEFilterDataProvider?

    /// Verifies ownership, modes and link constraints of the file and its
    /// ancestors before decoding. A refused list disables enforcement.
    func reloadProtectList() {
        var protect: ProtectList?
        var status: [String: Any] = ["op": "protect_list", "path": ProtectList.defaultPath]
        do {
            protect = try ProtectList.load(path: ProtectList.defaultPath, expectedOwnerUID: 0, rootDirectory: "/")
            status["ok"] = true
            status["entries"] = protect?.entries.count ?? 0
        } catch {
            status["ok"] = false
            status["error"] = "\(error)"
        }
        lock.lock()
        engine.protect = protect
        lock.unlock()
        logAction(status)
    }

    func decide(id: String, facts: FlowFacts, flow: NEFilterSocketFlow) -> NewFlowDecision {
        lock.lock()
        defer { lock.unlock() }
        return engine.decideNewFlow(id: id, facts: facts, handle: flow, now: Date())
    }

    func closed(id: String) {
        lock.lock()
        engine.flowClosed(id: id)
        lock.unlock()
    }

    func handle(_ request: ControlRequest) -> ControlResponse {
        if request.op != .list { reloadProtectList() }
        lock.lock()
        var victims: [NEFilterSocketFlow] = []
        let response = engine.handle(request, now: Date()) { victims.append($0) }
        lock.unlock()
        // Drops run outside the lock: a drop may complete the flow at once,
        // and its completion callback takes the lock again.
        for flow in victims {
            provider?.update(flow, using: .drop(), for: .any)
        }
        var entry: [String: Any] = ["op": request.op.rawValue, "actor": request.actor, "ok": response.ok, "killed": response.killed.count]
        if let error = response.error { entry["error"] = error }
        if let rule = response.rule { entry["rule_id"] = rule.id; entry["expiry"] = ISO8601DateFormatter().string(from: rule.expiry) }
        if let flowID = request.flowID { entry["flow_id"] = flowID }
        if let t = request.target { entry["target"] = ["app": t.app ?? "", "host": t.host ?? "", "port": t.port ?? 0] }
        logAction(entry)
        return response
    }

    /// Every applied or refused action goes to the unified log (category
    /// "action"); the watcher reconciles these lines with the journal.
    func logAction(_ entry: [String: Any]) {
        var entry = entry
        entry["ts"] = ISO8601DateFormatter().string(from: Date())
        guard let data = try? JSONSerialization.data(withJSONObject: entry, options: [.sortedKeys]),
              let json = String(data: data, encoding: .utf8) else { return }
        actionLogger.notice("\(json, privacy: .public)")
    }
}

@objc protocol NetFilterControlXPC {
    func handle(_ request: Data, reply: @escaping (Data) -> Void)
}

/// XPC control service on the extension's NEMachServiceName. Only the
/// NetFilter app of the same team may connect; without a readable team or
/// service name the service does not start, so nothing can be blocked.
final class ControlService: NSObject, NSXPCListenerDelegate, NetFilterControlXPC {
    private static var running: ControlService?
    private let listener: NSXPCListener

    private init(listener: NSXPCListener) {
        self.listener = listener
    }

    static func start() {
        guard running == nil,
              let ne = Bundle.main.object(forInfoDictionaryKey: "NetworkExtension") as? [String: Any],
              let machName = ne["NEMachServiceName"] as? String,
              let team = ownTeamID() else {
            EnforcementState.shared.logAction(["op": "control_service", "ok": false, "error": "no service name or team"])
            return
        }
        let listener = NSXPCListener(machServiceName: machName)
        listener.setConnectionCodeSigningRequirement("anchor apple generic and certificate leaf[subject.OU] = \"\(team)\" and identifier \"works.relux.mac-infra.netfilter\"")
        let service = ControlService(listener: listener)
        listener.delegate = service
        listener.resume()
        running = service
        EnforcementState.shared.logAction(["op": "control_service", "ok": true])
    }

    private static func ownTeamID() -> String? {
        var code: SecCode?
        var staticCode: SecStaticCode?
        var info: CFDictionary?
        guard SecCodeCopySelf([], &code) == errSecSuccess, let code,
              SecCodeCopyStaticCode(code, [], &staticCode) == errSecSuccess, let staticCode,
              SecCodeCopySigningInformation(staticCode, SecCSFlags(rawValue: kSecCSSigningInformation), &info) == errSecSuccess,
              let dict = info as? [String: Any] else { return nil }
        return dict[kSecCodeInfoTeamIdentifier as String] as? String
    }

    func listener(_ listener: NSXPCListener, shouldAcceptNewConnection connection: NSXPCConnection) -> Bool {
        connection.exportedInterface = NSXPCInterface(with: NetFilterControlXPC.self)
        connection.exportedObject = self
        connection.resume()
        return true
    }

    func handle(_ request: Data, reply: @escaping (Data) -> Void) {
        let response: ControlResponse
        if request.count > 16384 {
            response = .refused(EnforcementError.invalidTarget("request too large"))
        } else if let decoded = try? JSONDecoder().decode(ControlRequest.self, from: request) {
            response = EnforcementState.shared.handle(decoded)
        } else {
            response = .refused(EnforcementError.invalidTarget("undecodable request"))
        }
        reply((try? JSONEncoder().encode(response)) ?? Data(#"{"ok":false,"error":"encode"}"#.utf8))
    }
}
