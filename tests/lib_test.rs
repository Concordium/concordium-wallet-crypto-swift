use concordium_wallet_crypto_uniffi::*;

const SEED: &str = "efa5e27326f8fa0902e647b52449bf335b7b605adc387015ec903f41d95080eb71361cbc7fb78721dcd4f3926a337340aa1406df83332c44c1cdcfe100603860";
const MAINNET: &str = "mainnet";
const TESTNET: &str = "testnet";
const COMMITMENT_KEY: &str = "b14cbfe44a02c6b1f78711176d5f437295367aa4f2a8c2551ee10d25a03adc69d61a332a058971919dad7312e1fc94c5a8d45e64b6f917c540eee16c970c3d4b7f3caf48a7746284878e2ace21c82ea44bf84609834625be1f309988ac523fac";

// TODO: Add negative tests (currently there are none).

/* Tests ported from https://github.com/Concordium/concordium-swift-sdk/blob/5e700261a0dc08dd483981ce75c008d6bc3c80e5/Tests/ConcordiumSwiftSdkTests/ConcordiumHdWalletTest.swift
 * such that we don't have to release in order to be able to run tests.
 * The tests that verify that public keys match their sign counterparts have not been ported as that would require this crate to add dependencies that we otherwise don't need.
 * And the property is covered by the fact that we test the exact generated keys anyway.
 */

#[test]
fn mainnet_signing_key() {
    assert_eq!(
        get_account_signing_key(SEED.to_string(), MAINNET.to_string(), 0, 55, 7).unwrap(),
        "e4d1693c86eb9438feb9cbc3d561fbd9299e3a8b3a676eb2483b135f8dbf6eb1"
    );
}

#[test]
fn mainnet_public_key() {
    assert_eq!(
        get_account_public_key(SEED.to_string(), MAINNET.to_string(), 1, 341, 9).unwrap(),
        "d54aab7218fc683cbd4d822f7c2b4e7406c41ae08913012fab0fa992fa008e98"
    );
}

#[test]
fn mainnet_id_cred_sec() {
    assert_eq!(
        get_id_cred_sec(SEED.to_string(), MAINNET.to_string(), 2, 115).unwrap(),
        "33b9d19b2496f59ed853eb93b9d374482d2e03dd0a12e7807929d6ee54781bb1"
    );
}

#[test]
fn mainnet_prf_key() {
    assert_eq!(
        get_prf_key(SEED.to_string(), MAINNET.to_string(), 3, 35).unwrap(),
        "4409e2e4acffeae641456b5f7406ecf3e1e8bd3472e2df67a9f1e8574f211bc5"
    );
}

#[test]
fn mainnet_cred_id() {
    assert_eq!(
        get_credential_id(SEED.to_string(), MAINNET.to_string(), 10, 50, 5, COMMITMENT_KEY.to_string()).unwrap(),
        "8a3a87f3f38a7a507d1e85dc02a92b8bcaa859f5cf56accb3c1bc7c40e1789b4933875a38dd4c0646ca3e940a02c42d8"
    );
}

#[test]
fn mainnet_blinding_randomness() {
    assert_eq!(
        get_signature_blinding_randomness(SEED.to_string(), MAINNET.to_string(), 4, 5713).unwrap(),
        "1e3633af2b1dbe5600becfea0324bae1f4fa29f90bdf419f6fba1ff520cb3167"
    );
}

#[test]
fn mainnet_attribute_commitment_randomness() {
    assert_eq!(
        get_attribute_commitment_randomness(SEED.to_string(), MAINNET.to_string(), 5, 0, 4, 0)
            .unwrap(),
        "6ef6ba6490fa37cd517d2b89a12b77edf756f89df5e6f5597440630cd4580b8f"
    );
}

#[test]
fn testnet_signing_key() {
    assert_eq!(
        get_account_signing_key(SEED.to_string(), TESTNET.to_string(), 0, 55, 7).unwrap(),
        "aff97882c6df085e91ae2695a32d39dccb8f4b8d68d2f0db9637c3a95f845e3c"
    );
}

#[test]
fn testnet_public_key() {
    assert_eq!(
        get_account_public_key(SEED.to_string(), TESTNET.to_string(), 1, 341, 9).unwrap(),
        "ef6fd561ca0291a57cdfee896245db9803a86da74c9a6c1bf0252b18f8033003"
    );
}

#[test]
fn testnet_id_cred_sec() {
    assert_eq!(
        get_id_cred_sec(SEED.to_string(), TESTNET.to_string(), 2, 115).unwrap(),
        "33c9c538e362c5ac836afc08210f4b5d881ba65a0a45b7e353586dad0a0f56df"
    );
}

#[test]
fn testnet_prf_key() {
    assert_eq!(
        get_prf_key(SEED.to_string(), TESTNET.to_string(), 3, 35).unwrap(),
        "41d794d0b06a7a31fb79bb76c44e6b87c63e78f9afe8a772fc64d20f3d9e8e82"
    );
}

#[test]
fn testnet_cred_id() {
    assert_eq!(
        get_credential_id(SEED.to_string(), TESTNET.to_string(), 10, 50, 5, COMMITMENT_KEY.to_string()).unwrap(),
        "9535e4f2f964c955c1dd0f312f2edcbf4c7d036fe3052372a9ad949ff061b9b7ed6b00f93bc0713e381a93a43715206c"
    );
}

#[test]
fn testnet_blinding_randomness() {
    assert_eq!(
        get_signature_blinding_randomness(SEED.to_string(), TESTNET.to_string(), 4, 5713).unwrap(),
        "079eb7fe4a2e89007f411ede031543bd7f687d50341a5596e015c9f2f4c1f39b"
    );
}

#[test]
fn testnet_attribute_commitment_randomness() {
    assert_eq!(
        get_attribute_commitment_randomness(SEED.to_string(), TESTNET.to_string(), 5, 0, 4, 0)
            .unwrap(),
        "409fa90314ec8fb4a2ae812fd77fe58bfac81765cad3990478ff7a73ba6d88ae"
    );
}

#[test]
fn testnet_cred_id_matches_cred_deployment() {
    assert_eq!(
        get_credential_id(SEED.to_string(), TESTNET.to_string(), 0, 0, 1, COMMITMENT_KEY.to_string()).unwrap(),
        "b317d3fea7de56f8c96f6e72820c5cd502cc0eef8454016ee548913255897c6b52156cc60df965d3efb3f160eff6ced4"
    );
}

#[test]
fn mainnet_verifiable_credential_signing_key() {
    assert_eq!(
        get_verifiable_credential_signing_key(SEED.to_string(), MAINNET.to_string(), 1, 2, 1)
            .unwrap(),
        "670d904509ce09372deb784e702d4951d4e24437ad3879188d71ae6db51f3301"
    );
}

#[test]
fn mainnet_verifiable_credential_public_key() {
    assert_eq!(
        get_verifiable_credential_public_key(SEED.to_string(), MAINNET.to_string(), 3, 1232, 341)
            .unwrap(),
        "16afdb3cb3568b5ad8f9a0fa3c741b065642de8c53e58f7920bf449e63ff2bf9"
    );
}

#[test]
fn testnet_verifiable_credential_signing_key() {
    assert_eq!(
        get_verifiable_credential_signing_key(SEED.to_string(), TESTNET.to_string(), 13, 0, 1)
            .unwrap(),
        "c75a161b97a1e204d9f31202308958e541e14f0b14903bd220df883bd06702bb"
    );
}

#[test]
fn testnet_verifiable_credential_public_key() {
    assert_eq!(
        get_verifiable_credential_public_key(SEED.to_string(), TESTNET.to_string(), 17, 0, 341)
            .unwrap(),
        "c52a30475bac88da9e65471cf9cf59f99dcce22ce31de580b3066597746b394a"
    );
}
