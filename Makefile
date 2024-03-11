rust_toolchain = 1.72
cargo = cargo +$(rust_toolchain)

# Targets from building the individual components to assembling a complete framework.
# Cargo already does incremental building so no targets depend on any files.

.PHONY: default
default:
	# No default target.
	exit 1

# CONFIGURE #

# Installing targets as dependencies of the actual builds was also an option...

.PHONY: setup
setup:
	rustup toolchain install $(rust_toolchain)
	rustup target add --toolchain=$(rust_toolchain) \
		x86_64-apple-darwin \
		aarch64-apple-darwin \
		aarch64-apple-ios \
		x86_64-apple-ios \
		aarch64-apple-ios-sim

# BUILD FRAMEWORK #

.PHONY: framework # produces './generated/ConcordiumWalletCrypto.xcframework'
framework: clean-generated swift-bindings lib-darwin lib-ios lib-ios-sim
	xcodebuild -create-xcframework \
	  -library ./generated/target/universal-darwin/libconcordium_wallet_crypto_uniffi.a -headers ./generated/bindings \
	  -library ./target/aarch64-apple-ios/release/libconcordium_wallet_crypto_uniffi.a -headers ./generated/bindings \
	  -library ./generated/target/universal-ios/libconcordium_wallet_crypto_uniffi.a -headers ./generated/bindings \
	  -output ./generated/ConcordiumWalletCrypto.xcframework

# GENERATE BINDINGS #

.PHONY: swift-bindings
swift-bindings: # produces './generated/bindings'
	$(cargo) run --bin=uniffi-bindgen generate src/lib.udl --language=swift --out-dir=./generated/bindings
	mkdir -p ./Sources/ConcordiumWalletCrypto
	# Move Swift bridge code to source folder.
	# The remaining files (header and renamed modulemap) should go into the framework
	# (the directory is passed to 'xcodebuild -create-xcframework' via '-headers').
	mv ./generated/bindings/crypto.swift ./Sources/ConcordiumWalletCrypto/crypto.swift
	mv ./generated/bindings/cryptoFFI.modulemap ./generated/bindings/module.modulemap

# BUILD STATIC LIBRARIES #

.PHONY: lib-darwin-x86_64
lib-darwin-x86_64: # produces './target/x86_64-apple-darwin/release/libconcordium_wallet_crypto_uniffi.a'
	$(cargo) build --target=x86_64-apple-darwin --release

.PHONY: lib-darwin-aarch64
lib-darwin-aarch64: # produces './target/aarch64-apple-darwin/release/libconcordium_wallet_crypto_uniffi.a'
	$(cargo) build --target=aarch64-apple-darwin --release

.PHONY: lib-darwin
lib-darwin: lib-darwin-x86_64 lib-darwin-aarch64 # produces './generated/target/universal-darwin/libconcordium_wallet_crypto_uniffi.a'
	mkdir -p ./generated/target/universal-darwin
	lipo \
	  ./target/x86_64-apple-darwin/release/libconcordium_wallet_crypto_uniffi.a \
	  ./target/aarch64-apple-darwin/release/libconcordium_wallet_crypto_uniffi.a \
	  -create -output ./generated/target/universal-darwin/libconcordium_wallet_crypto_uniffi.a

.PHONY: lib-ios # produces './target/aarch64-apple-ios/release/libconcordium_wallet_crypto_uniffi.a'
lib-ios:
	$(cargo) build --target=aarch64-apple-ios --release

.PHONY: lib-ios-sim-x86_64 # produces './target/x86_64-apple-ios/release/libconcordium_wallet_crypto_uniffi.a'
lib-ios-sim-x86_64:
	$(cargo) build --target=x86_64-apple-ios --release

.PHONY: lib-ios-sim-aarch64 # produces './target/aarch64-apple-ios-sim/release/libconcordium_wallet_crypto_uniffi.a'
lib-ios-sim-aarch64:
	$(cargo) build --target=aarch64-apple-ios-sim --release

.PHONY: lib-ios-sim # produces './generated/target/universal-ios/libconcordium_wallet_crypto_uniffi.a'
lib-ios-sim: lib-ios-sim-x86_64 lib-ios-sim-aarch64
	mkdir -p ./generated/target/universal-ios
	lipo \
	  ./target/x86_64-apple-ios/release/libconcordium_wallet_crypto_uniffi.a \
	  ./target/aarch64-apple-ios-sim/release/libconcordium_wallet_crypto_uniffi.a \
	  -create -output ./generated/target/universal-ios/libconcordium_wallet_crypto_uniffi.a

# CLEANUP #

.PHONY: clean-target
clean-target:
	rm -rf ./target

.PHONY: clean-generated
clean-generated:
	rm -rf ./generated

.PHONY: clean
clean: clean-target clean-generated

# CONVENIENCE #

.PHONY: fmt
fmt:
	$(cargo) fmt

.PHONY: lint
lint:
	$(cargo) clippy

.PHONY: test
test:
	$(cargo) test
