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
        .binaryTarget(name: "libmobile_wallet", url: "https://s3.eu-west-1.amazonaws.com/static-libraries.concordium.com/iOS/libmobile_wallet_0.25.0.xcframework.zip", checksum: "c8cfc429f2ed99c807327ddb70f498624634bb8c0ab01904844005095eb80993")
    ]
)
