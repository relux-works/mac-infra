import Darwin
import Foundation
import Security

/// How trustworthy the reported signing identity is.
public enum SigningStatus: String, Sendable {
    /// Signed with a certificate (Apple platform or a team).
    case signed
    /// Ad-hoc signature only (no certificate), e.g. Homebrew builds.
    case adhoc
    /// The code has no signature at all.
    case unsigned
    /// The path is known but its signature could not be read.
    case unverified
    /// The process could not be identified; no path is reported.
    case unresolved
}

/// Where the identity came from.
public enum IdentitySource: String, Sendable {
    /// The kernel-verified audit token (pid and pid version checked by Security).
    case auditToken = "audit_token"
    /// proc_pidpath on the token's pid, guarded against pid reuse by start time.
    case pidPath = "pid_path"
    case none
}

public struct AppIdentity: Equatable, Sendable {
    public var signingID: String?
    public var teamID: String?
    public var path: String?
    public var pid: Int32?
    public var status: SigningStatus
    public var source: IdentitySource

    static func unresolved(pid: Int32?) -> AppIdentity {
        AppIdentity(signingID: nil, teamID: nil, path: nil, pid: pid, status: .unresolved, source: .none)
    }
}

/// kSecCodeSignatureAdhoc from <Security/CSCommon.h>.
private let adhocFlag: UInt32 = 0x2

private func signingFacts(_ code: SecStaticCode) -> (id: String?, team: String?, status: SigningStatus)? {
    var info: CFDictionary?
    guard SecCodeCopySigningInformation(code, SecCSFlags(rawValue: kSecCSSigningInformation), &info) == errSecSuccess,
          let dict = info as? [String: Any] else { return nil }
    // Unsigned code yields a dictionary without an identifier.
    guard let id = dict[kSecCodeInfoIdentifier as String] as? String else { return (nil, nil, .unsigned) }
    let flags = (dict[kSecCodeInfoFlags as String] as? NSNumber)?.uint32Value ?? 0
    let team = dict[kSecCodeInfoTeamIdentifier as String] as? String
    return (id, team, flags & adhocFlag != 0 ? .adhoc : .signed)
}

/// Signing facts of the code at path; `.unverified` when it cannot be read.
public func classify(path: String) -> (id: String?, team: String?, status: SigningStatus) {
    var code: SecStaticCode?
    guard SecStaticCodeCreateWithPath(URL(fileURLWithPath: path) as CFURL, [], &code) == errSecSuccess,
          let code, let facts = signingFacts(code) else { return (nil, nil, .unverified) }
    return facts
}

/// Process start time via sysctl(KERN_PROC_PID), which, unlike
/// proc_pidinfo(PROC_PIDTBSDINFO), also works for other users' processes.
private func startTime(of pid: Int32) -> Date? {
    var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_PID, pid]
    var info = kinfo_proc()
    var size = MemoryLayout<kinfo_proc>.size
    guard sysctl(&mib, UInt32(mib.count), &info, &size, nil, 0) == 0, size == MemoryLayout<kinfo_proc>.size,
          info.kp_proc.p_pid == pid else { return nil }
    let start = info.kp_proc.p_un.__p_starttime
    return Date(timeIntervalSince1970: TimeInterval(start.tv_sec) + TimeInterval(start.tv_usec) / 1e6)
}

/// Identity of a live pid by its executable path. The process must have
/// started no later than observedAt, and its start time must be the same
/// before and after the path lookup; otherwise the pid may belong to a
/// different process and the result is `.unresolved` without a path.
public func resolve(pid: Int32, observedAt: Date) -> AppIdentity {
    guard pid > 0, let before = startTime(of: pid), before <= observedAt else { return .unresolved(pid: pid) }
    var buffer = [CChar](repeating: 0, count: Int(MAXPATHLEN) * 4)
    guard proc_pidpath(pid, &buffer, UInt32(buffer.count)) > 0 else { return .unresolved(pid: pid) }
    guard let after = startTime(of: pid), after == before else { return .unresolved(pid: pid) }
    let path = String(cString: buffer)
    let facts = classify(path: path)
    return AppIdentity(signingID: facts.id, teamID: facts.team, path: path, pid: pid, status: facts.status, source: .pidPath)
}

/// Identity of a flow's source from its audit token: the Security framework
/// lookup first, then the pid fallback when that lookup fails.
public func resolve(auditToken data: Data?, observedAt: Date) -> AppIdentity {
    guard let data, data.count == MemoryLayout<audit_token_t>.size else { return .unresolved(pid: nil) }
    var token = audit_token_t()
    withUnsafeMutableBytes(of: &token) { $0.copyBytes(from: data) }
    let pid = audit_token_to_pid(token)

    var guest: SecCode?
    var staticCode: SecStaticCode?
    var url: CFURL?
    if SecCodeCopyGuestWithAttributes(nil, [kSecGuestAttributeAudit: data as CFData] as CFDictionary, [], &guest) == errSecSuccess,
       let guest,
       SecCodeCopyStaticCode(guest, [], &staticCode) == errSecSuccess, let staticCode,
       let facts = signingFacts(staticCode),
       SecCodeCopyPath(staticCode, [], &url) == errSecSuccess, let url {
        return AppIdentity(signingID: facts.id, teamID: facts.team, path: (url as URL).path, pid: pid, status: facts.status, source: .auditToken)
    }
    return resolve(pid: pid, observedAt: observedAt)
}
