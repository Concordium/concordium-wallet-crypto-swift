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
        .binaryTarget(name: "libmobile_wallet", url: "https://s3.eu-west-1.amazonaws.com/static-libraries.concordium.com/iOS/libmobile_wallet_0.25.0.xcframework.zip", checksum: "c16289ce5eab7e4990afea12f806fb892f0621e39ab19126fe402631553cb3aa")
    ]
)
