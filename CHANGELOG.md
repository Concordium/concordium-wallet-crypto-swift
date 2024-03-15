# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Build-time environment variable `CONCORDIUM_WALLET_CRYPTO_FRAMEWORK_PATH`
  for resolving the framework to a path instead of using the released one.

- Functions and associated types for creating identity issuance and recovery requests as well as account credential (deployment).

  UDL signatures:
  
  - `string identity_issuance_request_json(IdentityIssuanceRequestParameters params)`
  - `string identity_recovery_request_json(IdentityRecoveryRequestParameters params)`
  - `AccountCredentialResult account_credential(AccountCredentialParameters params)`
  - `string account_credential_deployment_hash_hex(AccountCredential credential, u64 expiry_unix)`
  - `string account_credential_deployment_signed_payload_hex(SignedAccountCredential credential)`
  
  The parameter types mirror the corresponding "input" types from `wallet_library` but use only types supported by UniFFI.
  The values are translated into these library types via JSON encoding/decoding.
  This is in contrast to the Java SDK where the value is passed as a JSON encoded string
  which is then decoded directly into the library input type.
  Doing it this way ensures that the conversions that are only checked at runtime happen internally in this library is easily tested,
  rather than across the FFI boundary.
  So it makes the FFI boundary statically typed and of course also generates the Swift types that we do need on the SDK side anyway.
  
  The identity request functions return their result as JSON encoded strings
  because the protocol actually is to just send the object as JSON in a URL parameter.
  So there's no point in decoding them into structured types - they would just be converted right back to JSON on the SDK side.
  We do decode the payload in a unit test to verify the format.

### Changed

- Rename crate from "crypto" to "concordium-wallet-crypto-uniffi".
- Rename generated framework from "RustFramework" to "ConcordiumWalletCrypto".
- Bump UniFFI from v0.25.x to v0.26.x.
- Rename functions to match the usage and conventions on the SDK side.

## [1.0.0] - 2024-02-06

Migrate crypto library from `ConcordiumSwiftSdk`.
This completely replaces the existing use of the repo where it was only used to host the compiled `mobile_wallet` sources from `concordium-base`.
The Rust sources of the new library (which still depend on other part of `concordium-base`) are now part of the repository.

## [0.24.0] - 2023-05-04

Legacy library used by Concordium's reference iOS wallet (https://github.com/Concordium/concordium-reference-wallet-ios/).
