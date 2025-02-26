// swift-tools-version: 5.6

import PackageDescription

let package = Package(
    name: "ConcordiumWalletCrypto",
    products: [
        .library(
            name: "ConcordiumWalletCrypto",
            targets: ["libmobile_wallet"]),
    ],
    dependencies: [],
    targets: [
        .binaryTarget(name: "libmobile_wallet", url: "https://s3.eu-west-1.amazonaws.com/static-libraries.concordium.com/iOS/libmobile_wallet_0.25.0.xcframework.zip", checksum: "5a64b0cbb82b2749f010ed50e5047e4ccbfa9eef0bdf37f1e976d49185670226")
    ]
)
