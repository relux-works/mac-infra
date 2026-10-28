import Darwin
import Foundation

struct ProtectListFileError: Error, CustomStringConvertible {
    let description: String
    init(_ reason: String) { description = reason }
}

extension ProtectList {
    // These trust rules mirror internal/security/netfilterctl/protect_file.go
    // and must stay identical. The explicit root is a trust anchor; path is
    // resolved within it. Production always passes uid 0 and "/".
    static func load(path: String, expectedOwnerUID: uid_t, rootDirectory: String) throws -> ProtectList {
        let path = URL(fileURLWithPath: path).standardizedFileURL.path
        let parts = path.dropFirst().split(separator: "/", omittingEmptySubsequences: false).map(String.init)
        guard !parts.isEmpty, parts.allSatisfy({ !$0.isEmpty && $0 != "." && $0 != ".." }) else {
            throw ProtectListFileError("protect-list invalid path component")
        }
        let flags = O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK
        var dir = open(rootDirectory, flags | O_DIRECTORY)
        guard dir >= 0 else { throw ProtectListFileError("protect-list root directory unavailable: \(String(cString: strerror(errno)))") }
        defer { close(dir) }
        try checkDirectory(dir, expectedOwnerUID: expectedOwnerUID)
        for part in parts.dropLast() {
            let next = openat(dir, part, flags | O_DIRECTORY)
            guard next >= 0 else { throw openError(dir: dir, name: part, code: errno, directory: true) }
            close(dir)
            dir = next
            try checkDirectory(dir, expectedOwnerUID: expectedOwnerUID)
        }
        let name = parts.last!
        let fd = openat(dir, name, flags)
        guard fd >= 0 else { throw openError(dir: dir, name: name, code: errno, directory: false) }
        defer { close(fd) }
        var st = stat()
        guard fstat(fd, &st) == 0 else { throw ProtectListFileError("protect-list fstat failed: \(String(cString: strerror(errno)))") }
        guard st.st_mode & S_IFMT == S_IFREG else { throw ProtectListFileError("protect-list is not a regular file") }
        guard st.st_nlink == 1 else { throw ProtectListFileError("protect-list link count is not 1") }
        guard st.st_uid == expectedOwnerUID else { throw ProtectListFileError("protect-list not owned by root") }
        guard st.st_mode & 0o022 == 0 else { throw ProtectListFileError("protect-list is group/world writable") }
        guard st.st_mode & 0o7000 == 0 else { throw ProtectListFileError("protect-list has set-uid, set-gid or sticky bit") }
        // Bound allocation even if a checked file grows; read only the checked fd.
        var data = Data()
        var buffer = [UInt8](repeating: 0, count: 8192)
        while data.count <= 65536 {
            let count = read(fd, &buffer, min(buffer.count, 65537 - data.count))
            if count < 0 {
                if errno == EINTR { continue }
                throw ProtectListFileError("protect-list read failed: \(String(cString: strerror(errno)))")
            }
            if count == 0 { break }
            data.append(contentsOf: buffer.prefix(count))
        }
        return try decode(data)
    }

    private static func checkDirectory(_ fd: Int32, expectedOwnerUID: uid_t) throws {
        var st = stat()
        guard fstat(fd, &st) == 0 else { throw ProtectListFileError("protect-list directory fstat failed: \(String(cString: strerror(errno)))") }
        guard st.st_mode & S_IFMT == S_IFDIR else { throw ProtectListFileError("protect-list path component is not a directory") }
        guard st.st_uid == expectedOwnerUID else { throw ProtectListFileError("protect-list directory not owned by root") }
        guard st.st_mode & 0o022 == 0 else { throw ProtectListFileError("protect-list directory is group/world writable") }
    }

    private static func openError(dir: Int32, name: String, code: Int32, directory: Bool) -> ProtectListFileError {
        // Diagnostic only after openat failed: this lookup never authorizes a read.
        var st = stat()
        if code == ELOOP || (fstatat(dir, name, &st, AT_SYMLINK_NOFOLLOW) == 0 && st.st_mode & S_IFMT == S_IFLNK) {
            return ProtectListFileError("protect-list path component is a symlink")
        }
        if code == ENOENT { return ProtectListFileError("protect-list missing (enforcement off)") }
        if directory && code == ENOTDIR { return ProtectListFileError("protect-list path component is not a directory") }
        return ProtectListFileError("protect-list unavailable (enforcement off): \(String(cString: strerror(code)))")
    }
}
