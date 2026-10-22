import Darwin
import Foundation
import Testing
@testable import NetFilterIdentity

private func ownAuditToken() throws -> Data {
    var token = audit_token_t()
    var count = mach_msg_type_number_t(MemoryLayout<audit_token_t>.size / MemoryLayout<natural_t>.size)
    let rc = withUnsafeMutablePointer(to: &token) {
        $0.withMemoryRebound(to: integer_t.self, capacity: Int(count)) {
            task_info(mach_task_self_, task_flavor_t(TASK_AUDIT_TOKEN), $0, &count)
        }
    }
    try #require(rc == KERN_SUCCESS)
    return withUnsafeBytes(of: &token) { Data($0) }
}

private func ownExecutablePath() -> String {
    var buffer = [CChar](repeating: 0, count: Int(MAXPATHLEN) * 4)
    _ = proc_pidpath(getpid(), &buffer, UInt32(buffer.count))
    return String(cString: buffer)
}

private func spawn(_ path: String, _ args: [String]) throws -> Process {
    let p = Process()
    p.executableURL = URL(fileURLWithPath: path)
    p.arguments = args
    try p.run()
    return p
}

// Positive control for the token route: this ad-hoc linked test binary is
// identified through its own audit token with its real path and the adhoc
// label (the class sing-box belongs to).
@Test func ownAuditTokenResolves() throws {
    let id = resolve(auditToken: try ownAuditToken(), observedAt: Date())
    #expect(id.source == .auditToken)
    #expect(id.path == ownExecutablePath())
    #expect(id.status == .adhoc)
    #expect(id.pid == getpid())
}

// Positive control for the pid fallback, mirroring curl: a running Apple
// platform binary resolves to its path, signing id and the signed label.
// The curl binary itself is checked through the path classifier.
@Test func pidFallbackResolvesSignedPlatformBinary() throws {
    let sleeper = try spawn("/bin/sleep", ["30"])
    defer { sleeper.terminate(); sleeper.waitUntilExit() }
    let id = resolve(pid: sleeper.processIdentifier, observedAt: Date())
    #expect(id == AppIdentity(signingID: "com.apple.sleep", teamID: nil, path: "/bin/sleep", pid: sleeper.processIdentifier, status: .signed, source: .pidPath))
    let curl = classify(path: "/usr/bin/curl")
    #expect(curl.id == "com.apple.curl" && curl.status == .signed)
}

// The previously failing binaries on this Mac (Homebrew sing-box is ad-hoc,
// the Codex CLI is team-signed) now get a label; skipped where absent. A
// running sing-box (root) also resolves by pid to its path.
@Test(.enabled(if: FileManager.default.fileExists(atPath: "/opt/homebrew/bin/sing-box")))
func singBoxIsLabelledAdhoc() throws {
    #expect(classify(path: "/opt/homebrew/bin/sing-box").status == .adhoc)
    let pgrep = Process()
    pgrep.executableURL = URL(fileURLWithPath: "/usr/bin/pgrep")
    pgrep.arguments = ["-x", "sing-box"]
    let out = Pipe()
    pgrep.standardOutput = out
    try pgrep.run()
    pgrep.waitUntilExit()
    if let pid = Int32(String(decoding: out.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self).split(separator: "\n").first ?? "") {
        let id = resolve(pid: pid, observedAt: Date())
        #expect(id.path?.hasSuffix("/sing-box") == true && id.status == .adhoc && id.source == .pidPath)
    }
}

private let codexCLI = "/opt/homebrew/lib/node_modules/@openai/codex/node_modules/@openai/codex-darwin-arm64/vendor/aarch64-apple-darwin/bin/codex"
@Test(.enabled(if: FileManager.default.fileExists(atPath: codexCLI)))
func codexCLIIsLabelledSigned() {
    let facts = classify(path: codexCLI)
    #expect(facts.id == "codex" && facts.team != nil && facts.status == .signed)
}

// Unsigned code is labelled unsigned; an unreadable path is unverified,
// never signed.
@Test func unsignedAndUnreadablePaths() throws {
    let dir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(at: dir) }
    let script = dir.appendingPathComponent("plain.sh")
    try Data("#!/bin/sh\nexit 0\n".utf8).write(to: script)
    #expect(classify(path: script.path).status == .unsigned)
    #expect(classify(path: dir.appendingPathComponent("missing").path).status == .unverified)
}

// Negative: a pid that exited before the lookup gives a typed unresolved
// with no path; so does a live pid whose process started after the flow
// was observed (pid reuse), and a missing or malformed token.
@Test func goneOrReusedPidsAreUnresolved() throws {
    let done = try spawn("/usr/bin/true", [])
    done.waitUntilExit()
    let gone = resolve(pid: done.processIdentifier, observedAt: Date())
    #expect(gone == AppIdentity.unresolved(pid: done.processIdentifier))

    let sleeper = try spawn("/bin/sleep", ["30"])
    defer { sleeper.terminate(); sleeper.waitUntilExit() }
    let reused = resolve(pid: sleeper.processIdentifier, observedAt: Date(timeIntervalSinceNow: -60))
    #expect(reused.path == nil && reused.status == .unresolved)

    #expect(resolve(auditToken: nil, observedAt: Date()) == .unresolved(pid: nil))
    #expect(resolve(auditToken: Data([1, 2, 3]), observedAt: Date()) == .unresolved(pid: nil))
}
