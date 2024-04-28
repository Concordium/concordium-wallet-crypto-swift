// swift-tools-version: 5.5

import Foundation
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
        overridableFrameworkTarget(
            name: "ConcordiumWalletCryptoUniffi",
            url: "https://github.com/Concordium/concordium-wallet-crypto-swift/releases/download/build%2F3.0.0-0/ConcordiumWalletCryptoUniffi.xcframework.zip",
            checksum: "6ef2b7c508c1f0a185d2191cbd3fe0052c9ea5f2c807bdc2a50787cee7f29c24"
        ),
        .target(
            name: "ConcordiumWalletCrypto",
            dependencies: [
                .target(name: "ConcordiumWalletCryptoUniffi"),
            ]
        ),
    ]
)

func overridableFrameworkTarget(name: String, url: String, checksum: String) -> Target {
    if let p = providedFrameworkPath(), !p.isEmpty {
        return .binaryTarget(name: name, path: p)
    }
    return .binaryTarget(name: name, url: url, checksum: checksum)
}

func providedFrameworkPath() -> String? {
    if let p = getEnv("CONCORDIUM_WALLET_CRYPTO_FRAMEWORK_PATH") {
        return p
    }
    if let _ = getEnv("CONCORDIUM_WALLET_CRYPTO_PATH") {
        return "./generated/ConcordiumWalletCryptoUniffi.xcframework"
    }
    return nil
}

func getEnv(_ key: String) -> String? {
    ProcessInfo.processInfo.environment[key]
}
