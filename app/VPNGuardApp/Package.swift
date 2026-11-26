// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "VPNGuardApp",
    platforms: [
        .macOS(.v14)
    ],
    products: [
        .executable(name: "VPNGuardApp", targets: ["VPNGuardApp"]),
        .executable(name: "vpnguard-netwatch", targets: ["VPNGuardNetWatch"])
    ],
    targets: [
        .executableTarget(
            name: "VPNGuardApp",
            path: "Sources/VPNGuardApp"
        ),
        .executableTarget(
            name: "VPNGuardNetWatch",
            path: "Sources/VPNGuardNetWatch"
        ),
        .testTarget(
            name: "VPNGuardAppTests",
            dependencies: ["VPNGuardApp"],
            path: "Tests/VPNGuardAppTests"
        )
    ]
)
