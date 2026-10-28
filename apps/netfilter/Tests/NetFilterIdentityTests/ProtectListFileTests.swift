import Darwin
import Foundation
import Testing
@testable import NetFilterIdentity

private let fileJSON = #"{"schema":"mac-infra.netfilter-protect/v1","entries":[{"host_suffix":"matrix.relux.works","reason":"Matrix"}]}"#

private struct FileTrustCase: Sendable {
    let name: String
    let reason: String?
}

// The filesystem case table mirrors TestProtectListFileTrust in Go.
private let fileTrustCases: [FileTrustCase] = [
    // Positive: a valid 0644 file under safe ancestors loads and decodes.
    .init(name: "valid", reason: nil),
    // Negative: the explicit expected uid applies to the root anchor too.
    .init(name: "wrong_owner", reason: "protect-list directory not owned by root"),
    // Negative: group-writable files cannot enable enforcement.
    .init(name: "group_writable", reason: "protect-list is group/world writable"),
    // Negative: world-writable files cannot enable enforcement.
    .init(name: "world_writable", reason: "protect-list is group/world writable"),
    // Negative: a file symlink cannot enable enforcement.
    .init(name: "symlink", reason: "protect-list path component is a symlink"),
    // Negative: a second hard link cannot enable enforcement.
    .init(name: "hard_link", reason: "protect-list link count is not 1"),
    // Negative: a symlink ancestor cannot redirect the read.
    .init(name: "ancestor_symlink", reason: "protect-list path component is a symlink"),
    // Negative: a group-writable ancestor cannot enable enforcement.
    .init(name: "ancestor_group_writable", reason: "protect-list directory is group/world writable"),
    // Negative: a world-writable ancestor cannot enable enforcement.
    .init(name: "ancestor_world_writable", reason: "protect-list directory is group/world writable"),
    // Negative: the root anchor itself must have safe mode bits.
    .init(name: "root_writable", reason: "protect-list directory is group/world writable"),
    // Negative: a regular file cannot serve as an ancestor directory.
    .init(name: "ancestor_file", reason: "protect-list path component is not a directory"),
    // Negative: set-uid files cannot enable enforcement.
    .init(name: "setuid", reason: "protect-list has set-uid, set-gid or sticky bit"),
    // Negative: set-gid files cannot enable enforcement.
    .init(name: "setgid", reason: "protect-list has set-uid, set-gid or sticky bit"),
    // Negative: sticky files cannot enable enforcement.
    .init(name: "sticky", reason: "protect-list has set-uid, set-gid or sticky bit"),
    // Negative: a FIFO is refused without blocking on a writer.
    .init(name: "fifo", reason: "protect-list is not a regular file"),
    // Negative: a directory at the file path cannot enable enforcement.
    .init(name: "directory", reason: "protect-list is not a regular file"),
    // Negative: a missing file still leaves enforcement off.
    .init(name: "missing", reason: "protect-list missing (enforcement off)"),
]

@Test(arguments: fileTrustCases)
private func protectListFileTrust(_ testCase: FileTrustCase) throws {
    let fm = FileManager.default
    let root = fm.temporaryDirectory.appendingPathComponent("protect-list-\(UUID().uuidString)")
    try fm.createDirectory(at: root, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
    defer { try? fm.removeItem(at: root) }
    let dir = root.appendingPathComponent("safe")
    let file = dir.appendingPathComponent("protect.json")
    try fm.createDirectory(at: dir, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o755])
    try Data(fileJSON.utf8).write(to: file)
    try posixOK(chmod(file.path, 0o644))
    var uid = getuid()
    switch testCase.name {
    case "wrong_owner": uid += 1
    case "group_writable": try posixOK(chmod(file.path, 0o664))
    case "world_writable": try posixOK(chmod(file.path, 0o646))
    case "setuid": try posixOK(chmod(file.path, 0o4644))
    case "setgid": try posixOK(chmod(file.path, 0o2644))
    case "sticky": try posixOK(chmod(file.path, 0o1644))
    case "hard_link": try posixOK(link(file.path, dir.appendingPathComponent("other.json").path))
    case "symlink":
        let real = file.path + ".real"
        try posixOK(rename(file.path, real))
        try posixOK(symlink(real, file.path))
    case "ancestor_symlink":
        let real = dir.path + ".real"
        try posixOK(rename(dir.path, real))
        try posixOK(symlink(real, dir.path))
    case "ancestor_group_writable": try posixOK(chmod(dir.path, 0o775))
    case "ancestor_world_writable": try posixOK(chmod(dir.path, 0o757))
    case "root_writable": try posixOK(chmod(root.path, 0o775))
    case "ancestor_file":
        try posixOK(rename(dir.path, dir.path + ".real"))
        try Data().write(to: dir)
    case "fifo", "directory", "missing":
        try fm.removeItem(at: file)
        if testCase.name == "fifo" { try posixOK(mkfifo(file.path, 0o644)) }
        if testCase.name == "directory" { try fm.createDirectory(at: file, withIntermediateDirectories: false) }
    default: break
    }
    var loaded: ProtectList?
    var refusal: String?
    do {
        loaded = try ProtectList.load(path: "/safe/protect.json", expectedOwnerUID: uid, rootDirectory: root.path)
    } catch { refusal = "\(error)" }
    #expect(refusal == testCase.reason)
    if testCase.reason == nil {
        #expect(loaded?.entries.count == 1)
        #expect(loaded?.protects(FlowFacts(appPath: nil, signingID: nil, hostname: "sync.matrix.relux.works", remoteIP: nil, remotePort: nil)) == "Matrix")
    } else {
        #expect(loaded == nil)
        var engine = Engine<String>(capacity: 1, protect: loaded)
        let result = engine.handle(ControlRequest(op: .kill, target: Target(app: "/tmp/evil", host: nil, port: nil), actor: "a"), now: Date()) { _ in Issue.record("refused list caused a drop") }
        #expect(!result.ok && result.error == "\(EnforcementError.noProtectList)")
    }
}

private func posixOK(_ result: Int32) throws {
    guard result == 0 else { throw NSError(domain: NSPOSIXErrorDomain, code: Int(errno)) }
}

// The trusted-file reader preserves the 64 KiB boundary and still rejects invalid content.
@Test private func protectListFileContent() throws {
    let fm = FileManager.default
    let root = fm.temporaryDirectory.appendingPathComponent("protect-list-\(UUID().uuidString)")
    try fm.createDirectory(at: root, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
    defer { try? fm.removeItem(at: root) }
    let file = root.appendingPathComponent("protect.json")
    let cases: [(String, String?)] = [
        // Positive: trailing JSON whitespace up to exactly 64 KiB is admitted.
        (fileJSON + String(repeating: " ", count: 65536 - fileJSON.utf8.count), nil),
        // Negative: one byte beyond the limit returns no list.
        (fileJSON + String(repeating: " ", count: 65537 - fileJSON.utf8.count), "protect-list invalid: larger than 64 KiB"),
        // Negative: safe filesystem metadata does not bypass strict decoding.
        ("not JSON", "protect-list invalid: expected {schema, entries}"),
    ]
    for (body, reason) in cases {
        try Data(body.utf8).write(to: file)
        try posixOK(chmod(file.path, 0o644))
        var loaded: ProtectList?
        var refusal: String?
        do { loaded = try ProtectList.load(path: "/protect.json", expectedOwnerUID: getuid(), rootDirectory: root.path) }
        catch { refusal = "\(error)" }
        #expect(refusal == reason)
        if reason == nil { #expect(loaded?.entries.count == 1) }
        else { #expect(loaded == nil) }
    }
}
