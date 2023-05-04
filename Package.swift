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
        .binaryTarget(name: "libmobile_wallet", url: "https://s3.eu-west-1.amazonaws.com/static-libraries.concordium.com/iOS/libmobile_wallet_0.24.0-0.xcframework.zip", checksum: "8051b9681901187537adc76858715d569d51abd4c201c376f292749da0b6eb60")
    ]
)
