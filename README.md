# ConcordiumWalletCrypto

[Swift package](https://developer.apple.com/documentation/xcode/swift-packages) providing bindings for Swift
of Concordium specific cryptographic functions that are written in Rust.

The project is a core component of [`ConcordiumSwiftSdk`](https://github.com/Concordium/concordium-swift-sdk.git).
It has its own repository because of limitations in SwiftPM
that prevent us from publishing everything in a single complete package.
In brief, Swift packages must be downloaded straight from git,
not a registry to which we can publish a complete build.
This repository thus serves the dual purpose of hosting the Rust sources
while simultaneously hosting the Swift package.

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
[`0.24.0-0`](https://github.com/Concordium/concordium-wallet-crypto-swift/releases/tag/0.24.0-0)
and in use by the
[iOS reference wallet](https://github.com/Concordium/concordium-reference-wallet-ios/).

## Versioning

The available versions of the package are represented by the commit tags of this repository.
The version is defined by the Rust/Cargo project.

## Build

Supported Rust version: 1.72

Once the expected targets to the Rust toolchain have been installed using

```shell
rustup target add x86_64-apple-darwin aarch64-apple-darwin aarch64-apple-ios x86_64-apple-ios
```

then the library may be built simply by running

```shell
./build.sh
```

This script will compile the sources into a framework `./generated/RustFramework.xcframework` that supports
- macOS: x86_64 (`x86_64-apple-darwin`) and ARM (`aarch64-apple-darwin`) as a universal binary
- iOS: ARM (`aarch64-apple-ios`)
- iOS simulator: x86_64 (`x86_64-apple-ios`) and ARM (`aarch64-apple-ios-sim`) as a universal binary.

The framework is ready be integrated directly into an XCode project or a SwiftPM project as a binary target in `Package.swift`.
In our [`Package.swift`](./Package.swift), the framework is fetched from a GitHub release as explained above.

## Development

This repository is a Rust project with a SwiftPM package embedded into it.
The Swift bridge in `./Sources` is generated by UniFFI and must not be edited manually.

The package spec file `Package.swift` is only edited as part of publishing a release.
This is also the only time that the generated changes in `./Sources` are committed.

The Rust source files are expected to be formatted according to `cargo fmt`.

The version in `Cargo.toml` is not updated during regular development.
Explanation of changes are added to `CHANGELOG.md` under the "unreleased" section.
The version and changelog are updated as part of the release process,
which is explained in detail below.

## Release new version

The steps for building and releasing a new version `<version>` of the library are as follows:

1. Bump the version to `<version>` in `Cargo.toml` and insert the changelog header in a separate "release" PR.
2. Push a tag named `build/<version>-<build-version>` for the commit,
   where `<build-version>` is bumped (starting from 0) for each attempt at building `<version>`.
   This is necessary because GitHub requires releases to be tagged and the following workflow uploads a release.
3. Run the [workflow](./.github/workflows/publish-framework.yml) for publishing a new version of the binary framework.
   Use the tag you just created as "branch" to run from and input `<version>` (i.e. without the counter for "Version").
4. Run [`./build.sh`](./build.sh) locally to regenerate the Swift bridge sources.
   [TODO: Running the "bindgen" step is sufficient.]
5. Update `Package.swift` with the updated `url` and `checksum` of the binary framework.
   The workflow prints the checksum as the last step of its execution.
6. Commit the changes and push an annotated tag named by the version for the new commit:
   ```shell
   git tag -a <version>
   ```
   Give the tag a message describing what changed in the new version.

The entire process should be done as a single PR which,
in order to preserve the tags, gets merged without squashing.
