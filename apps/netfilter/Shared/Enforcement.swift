import Foundation

// Enforcement logic of the kill path (spec-kill-path.md on
// STORY-261023-qbc86k): protect-list, time-bounded block rules, the bounded
// table of killable flows, and the control messages. Pure Swift, so it is
// tested outside the system extension.

/// The facts of one flow that matching uses.
public struct FlowFacts: Codable, Equatable, Sendable {
    public var appPath: String?
    public var signingID: String?
    public var hostname: String?
    public var remoteIP: String?
    public var remotePort: Int?

    public init(appPath: String?, signingID: String?, hostname: String?, remoteIP: String?, remotePort: Int?) {
        self.appPath = appPath
        self.signingID = signingID
        self.hostname = hostname?.lowercased()
        self.remoteIP = remoteIP
        self.remotePort = remotePort
    }
}

public enum EnforcementError: Error, Equatable, CustomStringConvertible {
    case noProtectList
    case invalidProtectList(String)
    case invalidTarget(String)
    case protected(String)
    case unknownRule(String)
    case unknownFlow(String)

    public var description: String {
        switch self {
        case .noProtectList: return "protect-list missing: enforcement is disabled"
        case .invalidProtectList(let why): return "protect-list invalid: \(why)"
        case .invalidTarget(let why): return "invalid target: \(why)"
        case .protected(let why): return "target is protected: \(why)"
        case .unknownRule(let id): return "unknown rule \(id)"
        case .unknownFlow(let id): return "unknown or no longer killable flow \(id)"
        }
    }
}

/// Root-owned list of flows that are never killed, blocked or slowed: they
/// are allowed at once. Each entry has exactly one matcher.
public struct ProtectList: Equatable, Sendable {
    public struct Entry: Codable, Equatable, Sendable {
        public var appPath: String?
        public var appPathPrefix: String?
        public var signingID: String?
        public var hostSuffix: String?
        public var reason: String

        enum CodingKeys: String, CodingKey {
            case appPath = "app_path", appPathPrefix = "app_path_prefix", signingID = "signing_id", hostSuffix = "host_suffix", reason
        }
    }

    public static let schema = "mac-infra.netfilter-protect/v1"
    public static let defaultPath = "/Library/Application Support/works.relux.mac-infra.netfilter/protect.json"
    public var entries: [Entry]

    struct File: Codable {
        var schema: String
        var entries: [Entry]
    }

    /// Decodes a protect-list strictly: known schema, at least one entry, each
    /// with exactly one non-empty matcher and a reason; unknown keys refused.
    public static func decode(_ data: Data) throws -> ProtectList {
        guard data.count <= 65536 else { throw EnforcementError.invalidProtectList("larger than 64 KiB") }
        guard let raw = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              Set(raw.keys) == ["schema", "entries"],
              let rawEntries = raw["entries"] as? [[String: Any]] else {
            throw EnforcementError.invalidProtectList("expected {schema, entries}")
        }
        let allowed: Set<String> = ["app_path", "app_path_prefix", "signing_id", "host_suffix", "reason"]
        for e in rawEntries where !Set(e.keys).isSubset(of: allowed) {
            throw EnforcementError.invalidProtectList("unknown entry key")
        }
        let file: File
        do { file = try JSONDecoder().decode(File.self, from: data) } catch {
            throw EnforcementError.invalidProtectList("undecodable")
        }
        guard file.schema == schema else { throw EnforcementError.invalidProtectList("schema") }
        guard !file.entries.isEmpty else { throw EnforcementError.invalidProtectList("no entries") }
        for e in file.entries {
            let matchers = [e.appPath, e.appPathPrefix, e.signingID, e.hostSuffix].compactMap { $0 }
            guard matchers.count == 1, !matchers[0].isEmpty, !e.reason.isEmpty else {
                throw EnforcementError.invalidProtectList("each entry needs exactly one matcher and a reason")
            }
        }
        return ProtectList(entries: file.entries)
    }

    /// The reason a flow is protected, or nil.
    public func protects(_ f: FlowFacts) -> String? {
        for e in entries {
            if let p = e.appPath, f.appPath == p { return e.reason }
            if let p = e.appPathPrefix, let path = f.appPath, path.hasPrefix(p) { return e.reason }
            if let s = e.signingID, f.signingID == s { return e.reason }
            if let h = e.hostSuffix?.lowercased(), let name = f.hostname, name == h || name.hasSuffix("." + h) { return e.reason }
        }
        return nil
    }
}

/// What a kill or block applies to. App is a path or a signing id; host is a
/// hostname or an IP literal. At least one of app and host is required.
public struct Target: Codable, Equatable, Sendable {
    public var app: String?
    public var host: String?
    public var port: Int?

    public init(app: String?, host: String?, port: Int?) {
        self.app = app
        self.host = host?.lowercased()
        self.port = port
    }

    public func validate() throws {
        guard (app?.isEmpty == false) || (host?.isEmpty == false) else { throw EnforcementError.invalidTarget("needs app or host") }
        if let port, !(1...65535).contains(port) { throw EnforcementError.invalidTarget("port out of range") }
        if (app?.count ?? 0) > 1024 || (host?.count ?? 0) > 253 { throw EnforcementError.invalidTarget("too long") }
    }

    public func matches(_ f: FlowFacts) -> Bool {
        if let app, f.appPath != app && f.signingID != app { return false }
        if let host, f.hostname != host && f.remoteIP != host { return false }
        if let port, f.remotePort != port { return false }
        return true
    }

    /// Facts that stand for the target itself, to check it against the
    /// protect-list before any rule exists.
    func asFacts() -> FlowFacts {
        let isIP = host.map { IPv4Address($0) != nil || $0.contains(":") } ?? false
        return FlowFacts(appPath: app, signingID: app, hostname: isIP ? nil : host, remoteIP: isIP ? host : nil, remotePort: port)
    }
}

private struct IPv4Address {
    init?(_ s: String) {
        let parts = s.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count == 4, parts.allSatisfy({ UInt8($0) != nil }) else { return nil }
    }
}

/// A block of new matching flows that ends by itself at expiry.
public struct BlockRule: Codable, Equatable, Sendable {
    public var id: String
    public var target: Target
    public var expiry: Date
}

/// Upper bound of one block; longer blocks need a new decision.
public let maxBlockDuration: TimeInterval = 24 * 3600

/// In-memory block rules. They never persist: an extension restart clears them.
public struct RuleSet: Sendable {
    public private(set) var rules: [BlockRule] = []

    public init() {}

    public mutating func add(_ target: Target, duration: TimeInterval, now: Date, protect: ProtectList?, id: String = UUID().uuidString) throws -> BlockRule {
        guard let protect else { throw EnforcementError.noProtectList }
        try target.validate()
        guard duration > 0, duration <= maxBlockDuration else { throw EnforcementError.invalidTarget("duration must be in (0, 24h]") }
        if let why = protect.protects(target.asFacts()) { throw EnforcementError.protected(why) }
        let rule = BlockRule(id: id, target: target, expiry: now.addingTimeInterval(duration))
        rules.append(rule)
        return rule
    }

    public mutating func remove(_ id: String) throws -> BlockRule {
        guard let i = rules.firstIndex(where: { $0.id == id }) else { throw EnforcementError.unknownRule(id) }
        return rules.remove(at: i)
    }

    /// The active rule matching a new flow; expired rules are dropped first.
    /// Protected flows never match.
    public mutating func prune(now: Date) { rules.removeAll { $0.expiry <= now } }

    public mutating func match(_ f: FlowFacts, now: Date, protect: ProtectList?) -> BlockRule? {
        prune(now: now)
        guard let protect, protect.protects(f) == nil else { return nil }
        return rules.first { $0.target.matches(f) }
    }
}

/// Bounded table of killable flows, oldest evicted first.
public struct FlowRegistry<Handle>: @unchecked Sendable {
    public struct Item {
        public var id: String
        public var facts: FlowFacts
        public var handle: Handle
    }

    public let capacity: Int
    private var order: [String] = []
    private var items: [String: Item] = [:]
    public private(set) var evicted = 0

    public init(capacity: Int) { self.capacity = capacity }

    public var count: Int { items.count }

    public mutating func register(id: String, facts: FlowFacts, handle: Handle) {
        if items[id] == nil { order.append(id) }
        items[id] = Item(id: id, facts: facts, handle: handle)
        while items.count > capacity, let oldest = order.first {
            order.removeFirst()
            if items.removeValue(forKey: oldest) != nil { evicted += 1 }
        }
    }

    public mutating func remove(id: String) {
        if items.removeValue(forKey: id) != nil { order.removeAll { $0 == id } }
    }

    public func item(id: String) -> Item? { items[id] }

    public func matching(_ target: Target) -> [Item] { order.compactMap { items[$0] }.filter { target.matches($0.facts) } }
}

/// One control request from the signed CLI to the extension.
public struct ControlRequest: Codable, Equatable, Sendable {
    public enum Op: String, Codable, Sendable { case kill, block, unblock, list }
    public var op: Op
    public var flowID: String?
    public var target: Target?
    public var durationSeconds: Double?
    public var ruleID: String?
    public var actor: String

    enum CodingKeys: String, CodingKey { case op, flowID = "flow_id", target, durationSeconds = "duration_seconds", ruleID = "rule_id", actor }
}

/// The extension's answer. ok=false carries the refusal reason.
public struct ControlResponse: Codable, Equatable, Sendable {
    public var ok: Bool
    public var error: String?
    public var killed: [FlowFacts]
    public var rule: BlockRule?
    public var rules: [BlockRule]
    public var killableFlows: Int

    enum CodingKeys: String, CodingKey { case ok, error, killed, rule, rules, killableFlows = "killable_flows" }

    public static func refused(_ e: Error) -> ControlResponse {
        ControlResponse(ok: false, error: "\(e)", killed: [], rule: nil, rules: [], killableFlows: 0)
    }
}

/// What happens to a new flow.
public enum NewFlowDecision: Equatable, Sendable {
    /// Enforcement is off (no protect-list) or the flow is protected: allow
    /// at once, never killable, no data callbacks.
    case allow(reason: String)
    /// An active block matches: drop.
    case drop(rule: BlockRule)
    /// Keep the flow under data filtering so a later kill can drop it.
    case watch
}

/// The kill path's state machine. The extension supplies the drop action;
/// everything else is decided here.
public struct Engine<Handle>: @unchecked Sendable {
    public var registry: FlowRegistry<Handle>
    public var rules = RuleSet()
    public var protect: ProtectList?

    public init(capacity: Int, protect: ProtectList?) {
        registry = FlowRegistry(capacity: capacity)
        self.protect = protect
    }

    public mutating func decideNewFlow(id: String, facts: FlowFacts, handle: Handle, now: Date) -> NewFlowDecision {
        guard let protect else { return .allow(reason: "enforcement disabled: no protect-list") }
        if let why = protect.protects(facts) { return .allow(reason: "protected: \(why)") }
        if let rule = rules.match(facts, now: now, protect: protect) { return .drop(rule: rule) }
        registry.register(id: id, facts: facts, handle: handle)
        return .watch
    }

    public mutating func flowClosed(id: String) { registry.remove(id: id) }

    public mutating func handle(_ req: ControlRequest, now: Date, drop: (Handle) -> Void) -> ControlResponse {
        do {
            guard !req.actor.isEmpty, req.actor.count <= 128 else { throw EnforcementError.invalidTarget("actor required") }
            var resp = ControlResponse(ok: true, error: nil, killed: [], rule: nil, rules: [], killableFlows: 0)
            switch req.op {
            case .kill:
                guard let protect else { throw EnforcementError.noProtectList }
                var victims: [FlowRegistry<Handle>.Item] = []
                if let id = req.flowID {
                    guard req.target == nil, let item = registry.item(id: id) else { throw EnforcementError.unknownFlow(id) }
                    if let why = protect.protects(item.facts) { throw EnforcementError.protected(why) }
                    victims = [item]
                } else if let target = req.target {
                    try target.validate()
                    if let why = protect.protects(target.asFacts()) { throw EnforcementError.protected(why) }
                    victims = registry.matching(target).filter { protect.protects($0.facts) == nil }
                } else {
                    throw EnforcementError.invalidTarget("kill needs flow_id or target")
                }
                for v in victims {
                    drop(v.handle)
                    registry.remove(id: v.id)
                }
                resp.killed = victims.map(\.facts)
            case .block:
                guard let target = req.target, let seconds = req.durationSeconds else { throw EnforcementError.invalidTarget("block needs target and duration_seconds") }
                resp.rule = try rules.add(target, duration: seconds, now: now, protect: protect)
            case .unblock:
                guard let id = req.ruleID else { throw EnforcementError.invalidTarget("unblock needs rule_id") }
                resp.rule = try rules.remove(id)
            case .list:
                break
            }
            rules.prune(now: now)
            resp.rules = rules.rules
            resp.killableFlows = registry.count
            return resp
        } catch {
            return .refused(error)
        }
    }
}
