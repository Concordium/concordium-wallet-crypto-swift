// swift-tools-version:5.6

import PackageDescription

let package = Package(
    name: "ConcordiumWalletCrypto",
    platforms: [
        .iOS(.v13),
        .macOS(.v10_15),
    ],
    products: [
        .library(
            name: "ConcordiumWalletCrypto",
            targets: ["ConcordiumWalletCrypto"]
        ),
    ],
    targets: [
        .binaryTarget(
            name: "RustFramework",
            url: "https://github.com/Concordium/concordium-wallet-crypto-swift/releases/download/build%2F1.0.0-1/RustFramework.xcframework.zip",
            checksum: "edc2628d1721697b555891316dac3be1490072c1649d040fff8f3c160b2d0e09"
        ),
        .target(
            name: "ConcordiumWalletCrypto",
            dependencies: [
                .target(name: "RustFramework"),
            ]
        ),
    ]
)
