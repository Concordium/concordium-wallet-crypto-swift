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
            url: "https://github.com/Concordium/concordium-wallet-crypto-swift/releases/download/build%2F3.1.1-0/ConcordiumWalletCryptoUniffi.xcframework.zip",
            checksum: "7af27968d9efe99ecb933e7385d0d1557a94d310a7395a90526acac44119a29e"
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
