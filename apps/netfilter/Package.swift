// swift-tools-version:6.0
// Test harness for the extension's identity resolver (Shared/), runnable
// with `swift test` outside the system extension and its sandbox.
import PackageDescription

let package = Package(
    name: "NetFilterIdentity",
    platforms: [.macOS(.v15)],
    targets: [
        .target(name: "NetFilterIdentity", path: "Shared", linkerSettings: [.linkedLibrary("bsm")]),
        .testTarget(name: "NetFilterIdentityTests", dependencies: ["NetFilterIdentity"], path: "Tests/NetFilterIdentityTests"),
    ]
)
