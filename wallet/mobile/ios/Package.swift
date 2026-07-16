// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "MindChainWalletSecurity",
    platforms: [.iOS(.v16), .macOS(.v13)],
    products: [
        .library(name: "MindChainWalletSecurity", targets: ["MindChainWalletSecurity"])
    ],
    targets: [
        .target(name: "MindChainWalletSecurity"),
        .testTarget(
            name: "MindChainWalletSecurityTests",
            dependencies: ["MindChainWalletSecurity"]
        )
    ]
)
