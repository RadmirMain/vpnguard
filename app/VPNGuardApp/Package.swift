// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "VPNGuardApp",
    platforms: [
        .macOS(.v14)
    ],
    products: [
        .executable(name: "VPNGuardApp", targets: ["VPNGuardApp"])
    ],
    targets: [
        .executableTarget(
            name: "VPNGuardApp",
            path: "Sources/VPNGuardApp"
        ),
        .testTarget(
            name: "VPNGuardAppTests",
            dependencies: ["VPNGuardApp"],
            path: "Tests/VPNGuardAppTests"
        )
    ]
)
