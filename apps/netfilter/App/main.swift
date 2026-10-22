import Foundation
import NetworkExtension
import SystemExtensions

let extensionID = "works.relux.mac-infra.netfilter.extension"
let usage = """
usage: NetFilter activate|deactivate|enable|disable|remove|status
       NetFilter kill --actor A (--flow ID | [--app PATH|ID] [--host NAME|IP] [--port N])
       NetFilter block --actor A [--app PATH|ID] [--host NAME|IP] [--port N] --for SECONDS
       NetFilter unblock --actor A --rule ID
       NetFilter list --actor A
"""

func finish(_ line: String, code: Int32) -> Never {
    print(line)
    fflush(stdout)
    exit(code)
}

final class RequestDelegate: NSObject, OSSystemExtensionRequestDelegate {
    let verb: String
    init(verb: String) { self.verb = verb }

    func request(_ request: OSSystemExtensionRequest,
                 actionForReplacingExtension existing: OSSystemExtensionProperties,
                 withExtension ext: OSSystemExtensionProperties) -> OSSystemExtensionRequest.ReplacementAction {
        .replace
    }

    func requestNeedsUserApproval(_ request: OSSystemExtensionRequest) {
        print("\(verb): needs user approval in System Settings > General > Login Items & Extensions > Network Extensions (waiting)")
        fflush(stdout)
    }

    func request(_ request: OSSystemExtensionRequest, didFinishWithResult result: OSSystemExtensionRequest.Result) {
        switch result {
        case .completed:
            finish("\(verb): ok (completed)", code: 0)
        case .willCompleteAfterReboot:
            finish("\(verb): ok (will complete after reboot)", code: 0)
        @unknown default:
            finish("\(verb): ok (result \(result.rawValue))", code: 0)
        }
    }

    func request(_ request: OSSystemExtensionRequest, didFailWithError error: Error) {
        let ns = error as NSError
        finish("\(verb): failed: \(ns.domain) \(ns.code) \(ns.localizedDescription)", code: 1)
    }
}

var systemExtensionDelegate: RequestDelegate?

func submit(activate: Bool) {
    let verb = activate ? "activate" : "deactivate"
    let delegate = RequestDelegate(verb: verb)
    systemExtensionDelegate = delegate
    let request = activate
        ? OSSystemExtensionRequest.activationRequest(forExtensionWithIdentifier: extensionID, queue: .main)
        : OSSystemExtensionRequest.deactivationRequest(forExtensionWithIdentifier: extensionID, queue: .main)
    request.delegate = delegate
    OSSystemExtensionManager.shared.submitRequest(request)
}

func withManager(_ verb: String, _ body: @escaping (NEFilterManager) -> Void) {
    let manager = NEFilterManager.shared()
    manager.loadFromPreferences { error in
        if let error {
            let ns = error as NSError
            finish("\(verb): failed: load \(ns.domain) \(ns.code) \(ns.localizedDescription)", code: 1)
        }
        body(manager)
    }
}

func save(_ manager: NEFilterManager, verb: String, okLine: String) {
    manager.saveToPreferences { error in
        if let error {
            let ns = error as NSError
            finish("\(verb): failed: save \(ns.domain) \(ns.code) \(ns.localizedDescription)", code: 1)
        }
        finish(okLine, code: 0)
    }
}

func enableFilter() {
    withManager("enable") { manager in
        let config = NEFilterProviderConfiguration()
        config.filterSockets = true
        config.filterPackets = false
        config.filterBrowsers = false
        manager.providerConfiguration = config
        manager.localizedDescription = "mac-infra NetFilter (observe-only flow logger)"
        manager.isEnabled = true
        save(manager, verb: "enable", okLine: "enable: ok (filter configuration saved, isEnabled=true)")
    }
}

func disableFilter() {
    withManager("disable") { manager in
        manager.isEnabled = false
        save(manager, verb: "disable", okLine: "disable: ok (isEnabled=false)")
    }
}

func removeFilter() {
    withManager("remove") { manager in
        manager.removeFromPreferences { error in
            if let error {
                let ns = error as NSError
                finish("remove: failed: \(ns.domain) \(ns.code) \(ns.localizedDescription)", code: 1)
            }
            finish("remove: ok (configuration removed)", code: 0)
        }
    }
}

func status() {
    withManager("status") { manager in
        let configured = manager.providerConfiguration != nil
        finish("status: configured=\(configured) enabled=\(manager.isEnabled) description=\(manager.localizedDescription ?? "nil")", code: 0)
    }
}

@objc protocol NetFilterControlXPC {
    func handle(_ request: Data, reply: @escaping (Data) -> Void)
}

func usageExit() -> Never {
    FileHandle.standardError.write(Data((usage + "\n").utf8))
    exit(2)
}

/// Builds a control request from `--key value` options; any unknown, repeated
/// or missing option is a usage error.
func controlRequest(_ op: ControlRequest.Op, _ options: ArraySlice<String>) -> ControlRequest {
    var values: [String: String] = [:]
    var it = options.makeIterator()
    while let key = it.next() {
        guard ["--actor", "--flow", "--app", "--host", "--port", "--for", "--rule"].contains(key),
              values[key] == nil, let value = it.next() else { usageExit() }
        values[key] = value
    }
    guard let actor = values["--actor"] else { usageExit() }
    var port: Int?
    if let p = values["--port"] {
        guard let n = Int(p) else { usageExit() }
        port = n
    }
    let target = (values["--app"] != nil || values["--host"] != nil || port != nil)
        ? Target(app: values["--app"], host: values["--host"], port: port) : nil
    var duration: Double?
    if let d = values["--for"] {
        guard let n = Double(d) else { usageExit() }
        duration = n
    }
    switch op {
    case .kill: guard (values["--flow"] == nil) != (target == nil), duration == nil, values["--rule"] == nil else { usageExit() }
    case .block: guard target != nil, duration != nil, values["--flow"] == nil, values["--rule"] == nil else { usageExit() }
    case .unblock: guard values["--rule"] != nil, target == nil, duration == nil, values["--flow"] == nil else { usageExit() }
    case .list: guard values.count == 1 else { usageExit() }
    }
    return ControlRequest(op: op, flowID: values["--flow"], target: target, durationSeconds: duration, ruleID: values["--rule"], actor: actor)
}

/// Sends one request to the extension's control service and prints its JSON
/// answer; exit 0 only when the extension reports ok.
func control(_ request: ControlRequest) {
    let extInfo = Bundle.main.bundleURL.appendingPathComponent("Contents/Library/SystemExtensions/\(extensionID).systemextension/Contents/Info.plist")
    guard let plist = NSDictionary(contentsOf: extInfo) as? [String: Any],
          let ne = plist["NetworkExtension"] as? [String: Any],
          let machName = ne["NEMachServiceName"] as? String,
          let body = try? JSONEncoder().encode(request) else {
        finish(#"{"ok":false,"error":"embedded extension Info.plist unreadable"}"#, code: 1)
    }
    let connection = NSXPCConnection(machServiceName: machName, options: .privileged)
    connection.remoteObjectInterface = NSXPCInterface(with: NetFilterControlXPC.self)
    connection.resume()
    let proxy = connection.remoteObjectProxyWithErrorHandler { error in
        let ns = error as NSError
        finish(#"{"ok":false,"error":"control service unreachable: \#(ns.domain) \#(ns.code)"}"#, code: 1)
    } as? NetFilterControlXPC
    guard let proxy else { finish(#"{"ok":false,"error":"no control proxy"}"#, code: 1) }
    proxy.handle(body) { data in
        let ok = (try? JSONDecoder().decode(ControlResponse.self, from: data))?.ok ?? false
        finish(String(decoding: data, as: UTF8.self), code: ok ? 0 : 1)
    }
}

let args = CommandLine.arguments.dropFirst()
guard let command = args.first else { usageExit() }
if let op = ControlRequest.Op(rawValue: command) {
    control(controlRequest(op, args.dropFirst()))
    dispatchMain()
}
guard args.count == 1 else { usageExit() }

switch command {
case "activate": submit(activate: true)
case "deactivate": submit(activate: false)
case "enable": enableFilter()
case "disable": disableFilter()
case "remove": removeFilter()
case "status": status()
default:
    FileHandle.standardError.write(Data((usage + "\n").utf8))
    exit(2)
}

dispatchMain()
