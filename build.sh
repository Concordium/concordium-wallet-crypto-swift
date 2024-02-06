#!/usr/bin/env sh

set -eux

# CLEAN UP #

rm -rf ./generated

# GENERATE BINDINGS/BRIDGE CODE #

cargo run --bin=uniffi-bindgen generate src/lib.udl --language=swift --out-dir=./generated/bindings
mkdir -p ./Sources/ConcordiumWalletCrypto
# Move Swift bridge code to source folder.
# The remaining files (header and renamed modulemap) should go into the framework.
mv ./generated/bindings/crypto.swift ./Sources/ConcordiumWalletCrypto/crypto.swift
mv ./generated/bindings/cryptoFFI.modulemap ./generated/bindings/module.modulemap

# BUILD STATIC LIBRARIES #

# Compile for Darwin (macOS) as universal binary.
cargo build --target=x86_64-apple-darwin --release
cargo build --target=aarch64-apple-darwin --release
mkdir -p ./generated/target/universal-darwin
lipo \
  ./target/x86_64-apple-darwin/release/libcrypto.a \
  ./target/aarch64-apple-darwin/release/libcrypto.a \
  -create -output ./generated/target/universal-darwin/libcrypto.a

# Compile for iOS.
cargo build --target=aarch64-apple-ios --release

# Compile for iOS Simulator as universal binary.
cargo build --target=x86_64-apple-ios --release
cargo build --target=aarch64-apple-ios-sim --release
mkdir -p ./generated/target/universal-ios
lipo \
  ./target/x86_64-apple-ios/release/libcrypto.a \
  ./target/aarch64-apple-ios-sim/release/libcrypto.a \
  -create -output ./generated/target/universal-ios/libcrypto.a

# BUILD BINARY FRAMEWORK #

xcodebuild -create-xcframework \
  -library ./generated/target/universal-darwin/libcrypto.a -headers ./generated/bindings \
  -library ./target/aarch64-apple-ios/release/libcrypto.a -headers ./generated/bindings \
  -library ./generated/target/universal-ios/libcrypto.a -headers ./generated/bindings \
  -output ./generated/RustFramework.xcframework

