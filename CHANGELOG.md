# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Build-time environment variable `CONCORDIUM_WALLET_CRYPTO_FRAMEWORK_PATH`
  for resolving the framework to a path instead of using the released one.

### Changed

- Rename crate from "crypto" to "concordium-wallet-crypto-uniffi"
- Rename generated framework from "RustFramework" to "ConcordiumWalletCrypto".
- Bump UniFFI from v0.25.x to v0.26.x.

## [1.0.0] - 2024-02-06

Migrate crypto library from `ConcordiumSwiftSdk`.
This completely replaces the existing use of the repo where it was only used to host the compiled `mobile_wallet` sources from `concordium-base`.
The Rust sources of the new library (which still depend on other part of `concordium-base`) are now part of the repository.

## [0.24.0] - 2023-05-04

Legacy library used by Concordium's reference iOS wallet (https://github.com/Concordium/concordium-reference-wallet-ios/).
