use concordium_base::{
    common::{to_bytes, Deserial},
    dodis_yampolskiy_prf as prf,
    elgamal::{self, BabyStepGiantStep},
    encrypted_transfers::{self, types::EncryptedAmount},
    id::{self, constants::ArCurve},
};
use uniffi::deps::anyhow::Context;

use crate::{Bytes, ConcordiumWalletCryptoError, ConvertError, GlobalContext, MicroCCDAmount};

pub struct EncryptionKeys {
    pub secret: Bytes,
    pub public: Bytes,
}

impl TryFrom<Bytes> for prf::SecretKey<ArCurve> {
    type Error = serde_json::Error;

    fn try_from(value: Bytes) -> Result<Self, Self::Error> {
        serde_json::to_string(&value).and_then(|s| serde_json::from_str(&s))
    }
}

impl TryFrom<Bytes> for elgamal::SecretKey<ArCurve> {
    type Error = serde_json::Error;

    fn try_from(value: Bytes) -> Result<Self, Self::Error> {
        serde_json::to_string(&value).and_then(|s| serde_json::from_str(&s))
    }
}

impl TryFrom<Bytes> for EncryptedAmount<ArCurve> {
    type Error = serde_json::Error;

    fn try_from(value: Bytes) -> Result<Self, Self::Error> {
        serde_json::to_string(&value).and_then(|s| serde_json::from_str(&s))
    }
}

pub fn get_encryption_keys(
    global_context: GlobalContext,
    prf_key: Bytes,
    credential_index: u8,
) -> Result<EncryptionKeys, ConcordiumWalletCryptoError> {
    let fn_name = "get_encryption_keys";
    let global_context = concordium_base::id::types::GlobalContext::try_from(global_context)
        .map_err(|e| e.to_call_failed(fn_name.to_string()))?;

    let prf_key = prf::SecretKey::<ArCurve>::try_from(prf_key)
        .map_err(|e: serde_json::Error| e.to_call_failed(fn_name.to_string()))?;
    let scalar = prf_key
        .prf_exponent(credential_index)
        .with_context(|| {
            format!("Failed to get exponent of key for credential index {credential_index}")
        })
        .map_err(|e| e.to_call_failed(fn_name.to_string()))?;

    let secret_key = elgamal::SecretKey {
        generator: *global_context.elgamal_generator(),
        scalar,
    };
    let public_key = elgamal::PublicKey::from(&secret_key);
    let keys = EncryptionKeys {
        secret: to_bytes(&secret_key).into(),
        public: to_bytes(&public_key).into(),
    };
    Ok(keys)
}

/// Embed the precomputed table for decryption.
/// It is unfortunate that this is pure bytes, but not enough of data is marked
/// as const, and in any case a HashMap relies on an allocator, so will never be
/// const.
static TABLE_BYTES: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/table_bytes.bin"));

pub fn decrypt_amount(
    encrypted_amount: Bytes,
    encryption_secret_key: Bytes,
) -> Result<MicroCCDAmount, ConcordiumWalletCryptoError> {
    let fn_name = "decrypt_amount";
    let secret_key = elgamal::SecretKey::<ArCurve>::try_from(encryption_secret_key)
        .map_err(|e| e.to_call_failed(fn_name.to_string()))?;
    let encrypted_amount = encrypted_amount
        .try_into()
        .map_err(|e: serde_json::Error| e.to_call_failed(fn_name.to_string()))?;
    let table = BabyStepGiantStep::deserial(&mut std::io::Cursor::new(TABLE_BYTES))
        .expect("Can deserialize the serialized table");
    let amount = encrypted_transfers::decrypt_amount::<id::constants::ArCurve>(
        &table,
        &secret_key,
        &encrypted_amount,
    );
    Ok(amount.into())
}
