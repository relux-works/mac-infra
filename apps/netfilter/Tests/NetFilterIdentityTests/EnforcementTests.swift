import Foundation
import Testing
@testable import NetFilterIdentity

private let protectJSON = """
{"schema":"mac-infra.netfilter-protect/v1","entries":[
 {"app_path_prefix":"/opt/homebrew/Cellar/sing-box/","reason":"multi-tun upstream"},
 {"app_path":"/Users/alexis/.local/bin/a2a","reason":"a2a CLI"},
 {"host_suffix":"matrix.relux.works","reason":"Matrix"}]}
"""
private let protect = try! ProtectList.decode(Data(protectJSON.utf8))
private let now = Date(timeIntervalSince1970: 1_800_000_000)

private func facts(_ app: String, _ host: String?, _ port: Int = 443, ip: String = "203.0.113.7") -> FlowFacts {
    FlowFacts(appPath: app, signingID: nil, hostname: host, remoteIP: ip, remotePort: port)
}

// The protect-list decoder admits the documented shape and refuses unknown
// keys, a wrong schema, entries with zero or two matchers or without a
// reason, an empty list and oversize files.
@Test func protectListDecoding() throws {
    #expect(protect.entries.count == 3)
    let bad = [
        #"{"schema":"mac-infra.netfilter-protect/v1","entries":[{"app_path":"/x","reason":"r","extra":1}]}"#,
        #"{"schema":"v0","entries":[{"app_path":"/x","reason":"r"}]}"#,
        #"{"schema":"mac-infra.netfilter-protect/v1","entries":[{"app_path":"/x","host_suffix":"y","reason":"r"}]}"#,
        #"{"schema":"mac-infra.netfilter-protect/v1","entries":[{"reason":"r"}]}"#,
        #"{"schema":"mac-infra.netfilter-protect/v1","entries":[{"app_path":"/x","reason":""}]}"#,
        #"{"schema":"mac-infra.netfilter-protect/v1","entries":[]}"#,
        #"{"schema":"mac-infra.netfilter-protect/v1","entries":[{"app_path":"/x","reason":"r"}],"more":true}"#,
    ]
    for json in bad {
        #expect(throws: EnforcementError.self) { try ProtectList.decode(Data(json.utf8)) }
    }
    #expect(throws: EnforcementError.self) { try ProtectList.decode(Data(repeating: 32, count: 70000)) }
}

// Matching: exact path, path prefix and host suffix on a label boundary
// protect; a look-alike host ("evilmatrix…") and other apps do not.
@Test func protectListMatching() {
    #expect(protect.protects(facts("/opt/homebrew/Cellar/sing-box/1.13.3/bin/sing-box", nil)) == "multi-tun upstream")
    #expect(protect.protects(facts("/Users/alexis/.local/bin/a2a", nil)) == "a2a CLI")
    #expect(protect.protects(facts("/usr/bin/curl", "matrix.relux.works")) == "Matrix")
    #expect(protect.protects(facts("/usr/bin/curl", "sync.matrix.relux.works")) == "Matrix")
    #expect(protect.protects(facts("/usr/bin/curl", "evilmatrix.relux.works")) == nil)
    #expect(protect.protects(facts("/opt/homebrew/bin/sing-box-fake", nil)) == nil)
}

// Positive: a watched flow is killed by tuple and by id: the drop action runs
// for it, the response lists it, and it leaves the table.
@Test func killDropsWatchedFlows() {
    var e = Engine<String>(capacity: 16, protect: protect)
    #expect(e.decideNewFlow(id: "f1", facts: facts("/tmp/evil", "bad.example"), handle: "h1", now: now) == .watch)
    #expect(e.decideNewFlow(id: "f2", facts: facts("/tmp/evil", "bad.example", 8443), handle: "h2", now: now) == .watch)
    #expect(e.decideNewFlow(id: "f3", facts: facts("/usr/bin/curl", "github.com"), handle: "h3", now: now) == .watch)
    var dropped: [String] = []
    let r1 = e.handle(ControlRequest(op: .kill, flowID: nil, target: Target(app: "/tmp/evil", host: "bad.example", port: 443), actor: "sysadmin"), now: now) { dropped.append($0) }
    #expect(r1.ok && dropped == ["h1"] && r1.killed.count == 1 && r1.killableFlows == 2)
    let r2 = e.handle(ControlRequest(op: .kill, flowID: "f3", actor: "sysadmin"), now: now) { dropped.append($0) }
    #expect(r2.ok && dropped == ["h1", "h3"] && r2.killableFlows == 1)
}

// Negative: without a protect-list enforcement is off: new flows are allowed
// unwatched and every kill or block is refused, with no drop.
@Test func noProtectListMeansNoEnforcement() {
    var e = Engine<String>(capacity: 16, protect: nil)
    #expect(e.decideNewFlow(id: "f", facts: facts("/tmp/evil", "bad.example"), handle: "h", now: now) == .allow(reason: "enforcement disabled: no protect-list"))
    var dropped = 0
    for req in [ControlRequest(op: .kill, target: Target(app: "/tmp/evil", host: nil, port: nil), actor: "a"),
                ControlRequest(op: .block, target: Target(app: "/tmp/evil", host: nil, port: nil), durationSeconds: 60, actor: "a")] {
        let r = e.handle(req, now: now) { _ in dropped += 1 }
        #expect(!r.ok && r.error == "\(EnforcementError.noProtectList)")
    }
    #expect(dropped == 0 && e.rules.rules.isEmpty)
}

// Negative: protected flows are allowed at once and never watched; a kill or
// block aimed at a protected target is refused; a flow that became protected
// after it was watched is skipped by a tuple kill and refused by id.
@Test func protectedFlowsAreNeverKilled() {
    var e = Engine<String>(capacity: 16, protect: protect)
    let tunnel = facts("/opt/homebrew/Cellar/sing-box/1.13.3/bin/sing-box", "fastus.example")
    #expect(e.decideNewFlow(id: "t", facts: tunnel, handle: "ht", now: now) == .allow(reason: "protected: multi-tun upstream"))
    var dropped = 0
    for req in [ControlRequest(op: .kill, target: Target(app: nil, host: "matrix.relux.works", port: nil), actor: "a"),
                ControlRequest(op: .block, target: Target(app: "/Users/alexis/.local/bin/a2a", host: nil, port: nil), durationSeconds: 60, actor: "a")] {
        let r = e.handle(req, now: now) { _ in dropped += 1 }
        #expect(!r.ok && (r.error ?? "").hasPrefix("target is protected"))
    }
    #expect(e.decideNewFlow(id: "w", facts: facts("/usr/bin/curl", "chat.example"), handle: "hw", now: now) == .watch)
    e.protect?.entries.append(.init(appPath: nil, appPathPrefix: nil, signingID: nil, hostSuffix: "chat.example", reason: "late"))
    let byTuple = e.handle(ControlRequest(op: .kill, target: Target(app: "/usr/bin/curl", host: nil, port: nil), actor: "a"), now: now) { _ in dropped += 1 }
    #expect(byTuple.ok && byTuple.killed.isEmpty)
    let byID = e.handle(ControlRequest(op: .kill, flowID: "w", actor: "a"), now: now) { _ in dropped += 1 }
    #expect(!byID.ok)
    #expect(dropped == 0)
}

// Blocks drop new matching flows until expiry and stop matching after it;
// they are capped at 24 h, refused without an actor, and removable; an
// unknown rule id is refused. Non-matching flows are still watched (control).
@Test func blocksExpireAndAreBounded() {
    var e = Engine<String>(capacity: 16, protect: protect)
    let r = e.handle(ControlRequest(op: .block, target: Target(app: "/tmp/evil", host: nil, port: nil), durationSeconds: 600, actor: "sysadmin"), now: now) { _ in }
    guard r.ok, let rule = r.rule else { Issue.record("block refused: \(r)"); return }
    #expect(e.decideNewFlow(id: "a", facts: facts("/tmp/evil", "x.example"), handle: "h", now: now.addingTimeInterval(599)) == .drop(rule: rule))
    #expect(e.decideNewFlow(id: "b", facts: facts("/usr/bin/curl", "x.example"), handle: "h", now: now.addingTimeInterval(599)) == .watch)
    #expect(e.decideNewFlow(id: "c", facts: facts("/tmp/evil", "x.example"), handle: "h", now: now.addingTimeInterval(600)) == .watch)
    #expect(e.rules.rules.isEmpty)
    let tooLong = e.handle(ControlRequest(op: .block, target: Target(app: "/tmp/evil", host: nil, port: nil), durationSeconds: maxBlockDuration + 1, actor: "a"), now: now) { _ in }
    let noActor = e.handle(ControlRequest(op: .block, target: Target(app: "/tmp/evil", host: nil, port: nil), durationSeconds: 60, actor: ""), now: now) { _ in }
    let noTarget = e.handle(ControlRequest(op: .block, target: Target(app: nil, host: nil, port: nil), durationSeconds: 60, actor: "a"), now: now) { _ in }
    #expect(!tooLong.ok && !noActor.ok && !noTarget.ok && e.rules.rules.isEmpty)
    let again = e.handle(ControlRequest(op: .block, target: Target(app: "/tmp/evil", host: nil, port: nil), durationSeconds: 60, actor: "a"), now: now) { _ in }
    let removed = e.handle(ControlRequest(op: .unblock, ruleID: again.rule?.id, actor: "a"), now: now) { _ in }
    let unknown = e.handle(ControlRequest(op: .unblock, ruleID: "nope", actor: "a"), now: now) { _ in }
    #expect(removed.ok && e.rules.rules.isEmpty && !unknown.ok)
}

// Fail-safe: with no control request ever received, no flow is dropped.
// Watching is bounded: the table keeps the newest flows and counts evictions.
@Test func failSafeAndBoundedTable() {
    var e = Engine<Int>(capacity: 3, protect: protect)
    for i in 0..<5 {
        #expect(e.decideNewFlow(id: "f\(i)", facts: facts("/usr/bin/curl", "h\(i).example"), handle: i, now: now) == .watch)
    }
    #expect(e.registry.count == 3 && e.registry.evicted == 2 && e.registry.item(id: "f0") == nil && e.registry.item(id: "f4") != nil)
}
