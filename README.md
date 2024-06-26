# `ConcordiumWalletCrypto`

[Swift package](https://developer.apple.com/documentation/xcode/swift-packages) providing bindings for Swift
of Concordium specific cryptographic functions that are written in Rust.

The project is a core component of the [Concordium Swift SDK](https://github.com/Concordium/concordium-swift-sdk.git).
It has its own repository because of limitations in SwiftPM
that prevent us from publishing everything in a single complete package.
In brief, Swift packages must be downloaded straight from git,
not a registry to which we can publish a complete build.
This repository thus serves the dual purpose of hosting both the Swift package
and the Rust crate `concordium-wallet-crypto-uniffi` that it's built from.

It should be noted that nothing in `concordium-wallet-crypto-uniffi` is actually specific to Swift:
It compiles on both Mac, Linux, and Windows and can be used from any of the
[languages that UniFFI supports](https://mozilla.github.io/uniffi-rs/Overview.html#supported-languages).

To avoid storing large binaries in git, a workflow compiles the bindings into an
[XCFramework](https://developer.apple.com/documentation/xcode/distributing-binary-frameworks-as-swift-packages)
and uploads it to GitHub as a release in this repository.

The Swift package specification refers to such a release, not the local Rust sources.
This means that the Swift sources (i.e. generated bridge code) and package spec made up by this repo
and its Rust sources aren't in sync between releases:
The Swift files always refer to the latest published release, even during development of the next version.

## Prior usage

This repository/package was previously used to host the binaries built from a previous incarnation of the Rust library
which was built and hosted elsewhere.
See commit 6b6af29816b0f966598b170d62334e2faf00062b for details.

That package is still available from tag
[`0.24.0-0`](https://github.com/Concordium/concordium-wallet-crypto-swift/releases/tag/0.24.0-0) and
[in use](https://github.com/Concordium/concordium-reference-wallet-ios/blob/main/ConcordiumWallet.xcodeproj/project.xcworkspace/xcshareddata/swiftpm/Package.resolved)
by the iOS reference wallet, but it isn't expected to receive updates in the future.

## Versioning

The available versions of the package are represented by the commit tags of this repository.
The version is defined by the Rust/Cargo project.

## Build

Supported Rust version: 1.72

*Prerequisites*

The repository uses git submodules. Make sure that all submodules are checked out correctly using

```shell
git submodule update --init
```

This must be done after the initial clone as well as every time you switch branch.

Ensure that the correct Rust toolchain has been installed with all the expected targets:

```shell
make setup
```

*Build*

Run

```shell
make framework
```

This script will compile the sources into a framework `./generated/ConcordiumWalletCryptoUniffi.xcframework`
that supports the following platforms:

- macOS: x86_64 (`x86_64-apple-darwin`) and ARM (`aarch64-apple-darwin`) as a universal binary
- iOS: ARM (`aarch64-apple-ios`)
- iOS simulator: x86_64 (`x86_64-apple-ios`) and ARM (`aarch64-apple-ios-sim`) as a universal binary.

The makefile is structured such that the targets can be easily combined to build other combinations of architectures.
The resulting framework is ready be integrated directly into an XCode project or a SwiftPM project as a binary target
in the project's `Package.swift` file.
In our [`Package.swift`](./Package.swift), the framework is referring to a GitHub release as explained above.

## Development

### Swift package

This repository is a Rust project with an embedded SwiftPM package for using it from Swift.
The Swift bridge in `./Sources` is generated by UniFFI and must not be edited manually.

The package spec file `Package.swift` is only edited as part of publishing a release.
This is also the only time that the generated changes in `./Sources` are committed.

Consider ignoring changes to the file between releases to avoid untimely updates using

```shell
git update-index --assume-unchanged ./Sources/ConcordiumWalletCrypto/generated.swift # revert with --no-assume-unchanged
```

The environment variable `CONCORDIUM_WALLET_CRYPTO_FRAMEWORK_PATH`
may be used to select a locally compiled framework instead of the released one.
This allows one to use an unreleased version during development of the SDK.
Note that even when this is used from downstream projects,
the provided path is evaluated relative to the root of this project.

For convenience, if `CONCORDIUM_WALLET_CRYPTO_PATH` is set
(indicating that we're using a development version of this library)
then `CONCORDIUM_WALLET_CRYPTO_FRAMEWORK_PATH` will default to `./generated/ConcordiumWalletCryptoUniffi.xcframework`.
Provide the empty string to that variable to disable this behavior.

### Rust

The Rust source files are expected to be formatted according to `cargo fmt`.

The version in `Cargo.toml` is not updated during regular development.
Explanation of changes are added to `CHANGELOG.md` under the "unreleased" section.
The version and changelog are updated as part of the release process,
which is explained in detail below.

## Release new version

Due to the dual nature of this repository, the release process is a little cumbersome,
so please follow the instructions below carefully.

The entire process should be done as a single PR (with no unrelated changes);
see [#11](https://github.com/Concordium/concordium-wallet-crypto-swift/pull/11) for a template.
To preserve tags, the PR must be merged without squashing.

Steps for building and releasing a new version `<version>` of the package:

1. Create and checkout a release branch named `release/<version>`.
2. Bump the version to `<version>` in `Cargo.toml` and
   [insert the changelog header](https://github.com/Concordium/concordium-wallet-crypto-swift/pull/11/files#diff-06572a96a58dc510037d5efa622f9bec8519bc1beab13c9f251e97e657a9d4ed).
   Commit and push the change to the release branch.
3. Create and push a (regular) tag named `build/<version>-<build-version>` for the new commit,
   where `<build-version>` starts out at `0`.
   Tagging is necessary because the workflow to be run in the next step uploads a release,
   and GitHub requires releases to be tagged.
   Pushing this tag will automatically trigger a [workflow](./.github/workflows/publish-framework.yml)
   that publishes a new version of the binary framework.
   If the build fails, commit a fix to the branch and repeat this step with `<build-version>` incremented by 1.
4. Run `make swift-bindings` locally to regenerate the Swift bridge sources.
5. Update `Package.swift` with the updated `url` and `checksum` of the binary framework.
   The checksum is part of the release built by the workflow above as the file `CHECKSUM`.
6. Commit the changes to `Sources/ConcordiumWalletCrypto/generated.swift` and `Package.swift`
   (no other files should have changes).
7. Merge PR for release branch *without squashing*.
8. On the resulting *merge commit* into `main`, push an *annotated* tag named by the version:
   ```shell
   git tag -a <version>
   ```
   Give a brief description of the changes from the Swift perspective as the tag message.

   The pushing of this tag will trigger a special workflow to add a release for this tag.
   The reason that the tag has to be after the merge is to avoid the release PR from being included in the autogenerated release notes
   of the *next* (framework) release.
