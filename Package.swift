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
        .binaryTarget(name: "libmobile_wallet", url: "https://s3.eu-west-1.amazonaws.com/static-libraries.concordium.com/iOS/libmobile_wallet_0.25.0.xcframework.zip", checksum: "70a3e42407a5d0952ccd26fe75a50a0e867e49f96017f73ece780028840dd05e")
    ]
)
