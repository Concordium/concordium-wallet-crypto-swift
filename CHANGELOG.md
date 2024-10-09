# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [5.0.0] - 2024-10-09

### Changed

- **BREAKING** - `SecToPubTransferData.transfer_amount` has been changed to `MicroCCDAmount` (previously `String`) which is an alias in generated code for `u64`
- **BREAKING** - Any place where the `String` identifier of a concordium network was used, the new `Network` type is now used.
- **BREAKING** - Identity attribute tags are now represented by the `AttributeTag` type instead of `u8` and replaces any occurance of this.
- **BREAKING** - `AccountCredentialResult` is now called `AccountCredentialWithRandomness` to better signal its use, i.e. store the randomness corresponding to a credential.

### Added

- `get_encryption_keys`, `decrypt_amount`, and `combine_encrypted_amounts` functions for handling encrypted amounts.
- `prove_identity_statement` for producing proofs related to Concordium identities.
- `Network` type to represent different concordium network variants.
- `AttributeTag` to represent the different identity attribute variants.
- A number of types including `VerifiablePresentation`, `Web3IdCredential`, `VerifiableCredentialStatement`,
  and `VerifiableCredentialCommitmentInputs` (which are the most important to mention) for working with verifiable credentials and presentations
- `create_verifiable_presentation` which facilitates producing verifiable presentations by supplying a combination of the types mentioned above.
- `DID` along with the helper functions `parse_did_method` and correspondingly `did_method_as_string` for working with concordium decentralized identifiers, used in the
  types related to verifiable credentials

## [4.1.0] - 2024-09-12

### Added

- Added functions for encoding/decoding smart contract types using a provided contract type/module schema.

## [4.0.0] - 2024-08-27

### Changed

- Any raw data representation changed from `string` to `Bytes` (and consequently `Data` in the generated swift code). Any place where data was previously represented
  as hex strings, the corresponding `_hex` postfix of the data structure field or function name has been removed.

## [3.1.1] - 2024-08-06

### Changed

- Aligned fields in `SecToPubTransferData` with serde version of the underlying struct from concordium-base, which is similar to other FFI types in the crate.

## [3.1.0] - 2024-08-06

### Added

- `sec_to_pub_transfer_data` and `deserialize_sec_to_pub_transfer_data` functions to support `TransferToPublic` transactions
- `serialize_credential_deployment_info` and `deserialize_update_credentials_payload` functions to support `UpdateCredentials` transactions
- `make_configure_baker_keys_payload` function to support `ConfigureBaker` transactions
- `generate_baker_keys` function to generate a random set of baker keys

## [3.0.0] - 2024-04-25

### Changed/fixed

- `ChoiceArParameter` field `threshold`: Change type from `u32` to `u8` as that's the proper type.
- Rename `identity_provider_index` to `identity_provider_id` in UDL definition for consistency with SDK.
- `ChainArData` field `end_id_cred_pub_share_hex`: Renamed to `enc_id_cred_pub_share_hex` to fix typo.

## [2.0.0] - 2024-03-20

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

- Rename crate from "crypto" to "concordium-wallet-crypto-uniffi" and verify on CI that project works on all platforms.
- Rename generated framework from "RustFramework" to "ConcordiumWalletCryptoUniffi".
- Ensure that library builds on macOS 11+ and verify on CI.
- Bump UniFFI from v0.25.x to v0.26.x.
- Rename functions to match the usage and conventions on the SDK side.

## [1.0.0] - 2024-02-06

Migrate crypto library from `ConcordiumSwiftSdk`.
This completely replaces the existing use of the repo where it was only used to host the compiled `mobile_wallet` sources from `concordium-base`.
The Rust sources of the new library (which still depend on other part of `concordium-base`) are now part of the repository.

## [0.24.0] - 2023-05-04

Legacy library used by Concordium's reference iOS wallet (https://github.com/Concordium/concordium-reference-wallet-ios/).
