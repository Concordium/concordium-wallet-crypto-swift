use std::collections::HashMap;

use crate::UniffiCustomTypeConverter;
use concordium_base::{contracts_common::AccountAddressParseError, id::constants::ArCurve};
use rand::thread_rng;
use serde::{Deserialize, Serialize};
use uniffi::deps::anyhow::Context;

/// Error type returned by the bridge functions.
/// A corresponding Swift type will be generated (via the UDL definition).
#[derive(Debug, thiserror::Error)]
pub enum ConcordiumWalletCryptoError {
    /// FFI call failed
    #[error("call {call} failed: {msg}")]
    CallFailed { call: String, msg: String },
}

pub trait ConvertError
where
    Self: std::fmt::Display,
{
    /// Convert to [`ConcordiumWalletCryptoError::CallFailed`]
    fn to_call_failed(&self, fn_description: String) -> ConcordiumWalletCryptoError {
        ConcordiumWalletCryptoError::CallFailed {
            call: fn_description,
            msg: format!("{:#}", self),
        }
    }
}

impl ConvertError for serde_json::Error {}
impl ConvertError for uniffi::deps::anyhow::Error {}
impl ConvertError for AccountAddressParseError {}

#[repr(transparent)]
#[derive(Debug, Serialize, Deserialize, derive_more::From)]
pub struct Bytes(#[serde(with = "hex")] Vec<u8>);

impl AsRef<[u8]> for Bytes {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl UniffiCustomTypeConverter for Bytes {
    type Builtin = Vec<u8>;

    fn into_custom(val: Self::Builtin) -> uniffi::Result<Self>
    where
        Self: Sized,
    {
        Ok(Bytes(val))
    }

    fn from_custom(obj: Self) -> Self::Builtin {
        obj.0
    }
}

/// UniFFI compatible bridge to [`concordium_base::id::types::GlobalContext<concordium_base::id::constants::ArCurve>`],
/// providing the implementation of the UDL declaration of the same name.
/// The translation is performed using Serde.
#[derive(Clone, Debug, Serialize)]
pub struct GlobalContext {
    #[serde(rename = "onChainCommitmentKey")]
    pub on_chain_commitment_key_hex: String,
    #[serde(rename = "bulletproofGenerators")]
    pub bulletproof_generators_hex: String,
    #[serde(rename = "genesisString")]
    pub genesis_string: String,
}

impl TryFrom<GlobalContext> for concordium_base::id::types::GlobalContext<ArCurve> {
    type Error = uniffi::deps::anyhow::Error;

    fn try_from(value: GlobalContext) -> Result<Self, Self::Error> {
        serde_json::to_string(&value)
            .context("cannot encode request object as JSON")
            .and_then(|json| {
                serde_json::from_str::<concordium_base::id::types::GlobalContext<ArCurve>>(&json)
                    .context("cannot decode request object into internal type")
            })
    }
}

/// UniFFI compatible bridge to [`concordium_base::id::types::ChainArData<concordium_base::id::constants::ArCurve>`],
/// providing the implementation of the UDL declaration of the same name.
/// The translation is performed using Serde.
#[derive(Debug, Deserialize, Serialize)]
pub struct ChainArData {
    #[serde(rename = "encIdCredPubShare")]
    pub enc_id_cred_pub_share_hex: String,
}

/// UniFFI compatible bridge to [`concordium_base::id::types::Policy<concordium_base::id::constants::ArCurve,concordium_base::id::constants::AttributeKind> `],
/// providing the implementation of the UDL declaration of the same name.
/// The translation is performed using Serde.
#[derive(Debug, Deserialize, Serialize)]
pub struct Policy {
    #[serde(rename = "createdAt")]
    pub created_at_year_month: String,
    #[serde(rename = "revealedAttributes")]
    pub revealed_attributes: HashMap<String, String>,
    #[serde(rename = "validTo")]
    pub valid_to_year_month: String,
}

/// UniFFI compatible bridge to [`concordium_base::id::types::CredentialPublicKeys`],
/// providing the implementation of the UDL declaration of the same name.
/// The translation is performed using Serde.
#[derive(Debug, Deserialize, Serialize)]
pub struct CredentialPublicKeys {
    #[serde(rename = "keys")]
    pub keys: HashMap<u8, VerifyKey>,
    #[serde(rename = "threshold")]
    pub threshold: u8,
}

/// UniFFI compatible bridge to [`concordium_base::id::types::VerifyKey`],
/// providing the implementation of the UDL declaration of the same name.
/// The translation is performed using Serde.
#[derive(Debug, Deserialize, Serialize)]
pub struct VerifyKey {
    #[serde(rename = "schemeId")]
    pub scheme_id: String,
    #[serde(rename = "verifyKey")]
    pub key_hex: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BakerKeyPairs {
    #[serde(rename = "signatureSignKey")]
    pub signature_sign: Bytes,
    #[serde(rename = "signatureVerifyKey")]
    pub signature_verify: Bytes,
    #[serde(rename = "electionPrivateKey")]
    pub election_sign: Bytes,
    #[serde(rename = "electionVerifyKey")]
    pub election_verify: Bytes,
    #[serde(rename = "aggregationSignKey")]
    pub aggregation_sign: Bytes,
    #[serde(rename = "aggregationVerifyKey")]
    pub aggregation_verify: Bytes,
}

impl TryFrom<BakerKeyPairs> for concordium_base::base::BakerKeyPairs {
    type Error = serde_json::Error;

    fn try_from(value: BakerKeyPairs) -> Result<Self, Self::Error> {
        serde_json::to_string(&value).and_then(|s| serde_json::from_str(&s))
    }
}

impl From<concordium_base::base::BakerKeyPairs> for BakerKeyPairs {
    fn from(value: concordium_base::base::BakerKeyPairs) -> Self {
        let ser = serde_json::to_string(&value).expect("Serialization does not fail");
        serde_json::from_str(&ser).expect("Deserializing known value does not fail")
    }
}

/// Generate a set of baker keys
pub fn generate_baker_keys() -> BakerKeyPairs {
    let mut csprng = thread_rng();
    let keys = concordium_base::base::BakerKeyPairs::generate(&mut csprng);
    keys.into()
}
