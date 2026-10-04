// swift-tools-version: 6.4
//
// VQProtocol — Swift implementation of the Ventriloquist wire protocol
// (normative spec: protocol/README.md; authority: protocol/vectors/*.json).
//
// CryptoKit only, no third-party dependencies. `VQPhoneCore` is the
// transport-agnostic phone engine (Foundation + VQProtocol only) shared by the
// iOS app and PhoneSim. The `PhoneSim` executable
// target (SPEC §8, milestone M4) will be added to this package later as
// `.executableTarget(name: "PhoneSim", dependencies: ["VQPhoneCore", "VQProtocol"])`.

import PackageDescription

let package = Package(
    name: "VQProtocol",
    platforms: [
        .iOS(.v26),
        .macOS(.v26),
    ],
    products: [
        .library(name: "VQProtocol", targets: ["VQProtocol"]),
        .library(name: "VQPhoneCore", targets: ["VQPhoneCore"]),
    ],
    targets: [
        .target(
            name: "VQProtocol",
            path: "Sources/VQProtocol"
        ),
        .target(
            name: "VQPhoneCore",
            dependencies: ["VQProtocol"],
            path: "Sources/VQPhoneCore"
        ),
        .testTarget(
            name: "VQPhoneCoreTests",
            dependencies: ["VQPhoneCore", "VQProtocol"],
            path: "Tests/VQPhoneCoreTests"
        ),
        .testTarget(
            name: "VQProtocolTests",
            dependencies: ["VQProtocol"],
            path: "Tests/VQProtocolTests"
        ),
    ],
    swiftLanguageModes: [.v6]
)
