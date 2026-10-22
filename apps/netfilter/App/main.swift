import Foundation
import NetworkExtension
import SystemExtensions

let extensionID = "works.relux.mac-infra.netfilter.extension"
let usage = "usage: NetFilter activate|deactivate|enable|disable|remove|status"

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

let args = CommandLine.arguments.dropFirst()
guard args.count == 1, let command = args.first else {
    FileHandle.standardError.write(Data((usage + "\n").utf8))
    exit(2)
}

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
