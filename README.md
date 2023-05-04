# ConcordiumWalletCrypto

[Swift package](https://developer.apple.com/documentation/xcode/swift-packages) providing Concordium's [Rust-based crypto library for mobile wallets](https://github.com/Concordium/concordium-base/tree/main/mobile_wallet), compiled for iOS as an [XCFramework](https://developer.apple.com/documentation/xcode/distributing-binary-frameworks-as-swift-packages).

The binaries are compiled internally and uploaded to S3. The only target of the package is a binary target that references the appropriate version of this file.

## Versioning

The available versions of the package are represented by the commit tags of this repository.

The version follows the one of the [Rust sources](https://github.com/Concordium/concordium-base/blob/main/mobile_wallet/Cargo.toml) with a "build version" appended with a `-` separator. This extra component counts from 0 for any given library version and is bumped whenever a new Swift package based on the same Rust sources is built.

## Relase new version

Steps for building and releasing a new version `<version>`:

1. Using the appropriate automated job, run [`./build-ios.sh`](https://github.com/Concordium/concordium-base/blob/main/mobile_wallet/scripts/build-ios.sh) from `concordium-base`, archive `ios/build/libmobile_wallet.xcframework` as a compressed zip file named `libmobile_wallet_<version>.xcframework.zip`, and upload this file to S3 bucket/path `static-libraries.concordium.com/iOS`.

2. Compute checksum of the archive using the command
   ```
   swift package compute-checksum libmobile_wallet_<version>.xcframework.zip
   ```

3. Commit a change to [`Package.swift](https://github.com/Concordium/concordium-wallet-crypto-swift/blob/main/Package.swift), updating the `libmobile_wallet` binary target with the new version in the `url` string and the new `checksum`.

4. Push an annotated tag named by the version for the new commit:
   ```
   git tag -a <version>
   ```
   Give the tag a message describing what changed in the new version.
