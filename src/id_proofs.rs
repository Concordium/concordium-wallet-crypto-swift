use std::str::FromStr;

use concordium_base::{
    common::VERSION_0,
    id::{
        constants::{ArCurve, AttributeKind, IpPairing},
        id_proof_types::{ProofVersion, StatementWithContext},
        types::{IdentityObjectV1, IpInfo},
    },
};
use key_derivation::{CredentialContext, Net};
use serde::{Deserialize, Serialize};
use uniffi::deps::anyhow::Context;
use wallet_library::wallet::get_wallet;

use crate::{
    Bytes, ConcordiumWalletCryptoError, ConvertError, GlobalContext, IdentityObject,
    IdentityProviderInfo, Versioned,
};

/// For the case where the verifier wants the user to show the value of an
/// attribute and prove that it is indeed the value inside the on-chain
/// commitment. Since the verifier does not know the attribute value before
/// seing the proof, the value is not present here.
#[derive(Serialize)]
pub struct RevealAttributeStatement<Tag: Serialize> {
    /// The attribute that the verifier wants the user to reveal.
    #[serde(rename = "attributeTag")]
    pub attribute_tag: Tag,
}

/// Serves as a uniFFI compatible bridge to [`concordium_base::id::id_proof_types::RevealAttributeStatement<ArCurve, AttributeTag>`]
pub type RevealAttributeStatementV1 = RevealAttributeStatement<String>;

/// For the case where the verifier wants the user to prove that an attribute is
/// in a range. The statement is that the attribute value lies in `[lower,
/// upper)` in the scalar field.
#[derive(Serialize)]
pub struct AttributeInRangeStatement<Tag: Serialize, Value: Serialize> {
    /// The attribute that the verifier wants the user to prove is in a range.
    #[serde(rename = "attributeTag")]
    pub attribute_tag: Tag,
    /// The lower bound on the range.
    #[serde(rename = "lower")]
    pub lower: Value,
    #[serde(rename = "upper")]
    /// The upper bound of the range.
    pub upper: Value,
}

/// Serves as a uniFFI compatible bridge to [`concordium_base::id::id_proof_types::AttributeInRangeStatement<ArCurve, AttributeTag, AttributeKind>`]
pub type AttributeInRangeStatementV1 = AttributeInRangeStatement<String, String>;

/// For the case where the verifier wants the user to prove that an attribute is
/// in a set of attributes.
///
/// Serves as a uniFFI compatible bridge to [`concordium_base::id::id_proof_types::AttributeInSetStatement<ArCurve, AttributeTag, AttributeKind>`]
#[derive(Serialize)]
pub struct AttributeInSetStatement<Tag: Serialize, Value: Serialize> {
    /// The attribute that the verifier wants the user prove lies in a set.
    #[serde(rename = "attributeTag")]
    pub attribute_tag: Tag,
    /// The set that the attribute should lie in.
    #[serde(rename = "set")]
    pub set: Vec<Value>,
}

/// Serves as a uniFFI compatible bridge to [`concordium_base::id::id_proof_types::AttributeInSetStatement<ArCurve, AttributeTag, AttributeKind>`]
pub type AttributeInSetStatementV1 = AttributeInSetStatement<String, String>;

/// For the case where the verifier wants the user to prove that an attribute is
/// not in a set of attributes.
///
/// Serves as a uniFFI compatible bridge to [`concordium_base::id::id_proof_types::AttributeNotInSetStatement<ArCurve, AttributeTag, AttributeKind>`]
#[derive(Serialize)]
pub struct AttributeNotInSetStatement<Tag: Serialize, Value: Serialize> {
    /// The attribute that the verifier wants the user to prove does not lie in
    /// a set.
    #[serde(rename = "attributeTag")]
    pub attribute_tag: Tag,
    /// The set that the attribute should not lie in.
    #[serde(rename = "set")]
    pub set: Vec<Value>,
}

/// Serves as a uniFFI compatible bridge to [`concordium_base::id::id_proof_types::AttributeNotInSetStatement<ArCurve, AttributeTag, AttributeKind>`]
pub type AttributeNotInSetStatementV1 = AttributeNotInSetStatement<String, String>;

#[derive(Serialize)]
#[serde(tag = "type")]
pub enum AtomicStatement<Tag: Serialize, Value: Serialize> {
    /// The atomic statement stating that an attribute should be revealed.
    RevealAttribute {
        #[serde(flatten)]
        statement: RevealAttributeStatement<Tag>,
    },
    /// The atomic statement stating that an attribute is in a range.
    AttributeInRange {
        #[serde(flatten)]
        statement: AttributeInRangeStatement<Tag, Value>,
    },
    /// The atomic statement stating that an attribute is in a set.
    AttributeInSet {
        #[serde(flatten)]
        statement: AttributeInSetStatement<Tag, Value>,
    },
    /// The atomic statement stating that an attribute is not in a set.
    AttributeNotInSet {
        #[serde(flatten)]
        statement: AttributeNotInSetStatement<Tag, Value>,
    },
}

/// Serves as a uniFFI compatible bridge to [`concordium_base::id::id_proof_types::AtomicStatement<ArCurve, AttributeTag, AttributeKind>`]
pub type AtomicStatementV1 = AtomicStatement<String, String>;

#[derive(Serialize)]
#[serde(transparent)]
pub struct Statement<Tag: Serialize, Value: Serialize> {
    pub statements: Vec<AtomicStatement<Tag, Value>>,
}

/// Serves as a uniFFI compatible bridge to [`concordium_base::id::id_proof_types::Statement<ArCurve, AttributeKind>`]
pub type StatementV1 = Statement<String, String>;

impl TryFrom<StatementV1>
    for concordium_base::id::id_proof_types::Statement<ArCurve, AttributeKind>
{
    type Error = serde_json::Error;

    fn try_from(value: StatementV1) -> Result<Self, Self::Error> {
        serde_json::to_string(&value).and_then(|s| serde_json::from_str(&s))
    }
}

#[derive(Deserialize)]
#[serde(tag = "type", bound(deserialize = "Value: Deserialize<'de>"))]
pub enum AtomicProof<Value> {
    /// The atomic statement stating that an attribute should be revealed.
    RevealAttribute { attribute: Value, proof: Bytes },
    /// The atomic proof stating that an attribute is in a range.
    AttributeInRange { proof: Bytes },
    /// The atomic proof stating that an attribute is in a set.
    AttributeInSet { proof: Bytes },
    /// The atomic proof stating that an attribute is not in a set.
    AttributeNotInSet { proof: Bytes },
}

/// Serves as a uniFFI compatible bridge to [`concordium_base::id::id_proof_types::AtomicProof<ArCurve, AttributeKind>`]
pub type AtomicProofV1 = AtomicProof<String>;

#[derive(Deserialize)]
#[serde(bound(deserialize = "Value: Deserialize<'de>"))]
pub struct Proof<Value> {
    pub proofs: Vec<AtomicProof<Value>>,
}

/// Serves as a uniFFI compatible bridge to [`concordium_base::id::id_proof_types::Proof<ArCurve, AttributeKind>`]
pub type ProofV1 = Proof<String>;

/// Serves as a uniFFI compatible bridge to [`concordium_base::common::Versioned<concordium_base::id::id_proof_types::Proof<ArCurve, AttributeKind>>`]
pub type VersionedProofV1 = Versioned<ProofV1>;

impl
    TryFrom<
        concordium_base::common::Versioned<
            concordium_base::id::id_proof_types::Proof<ArCurve, AttributeKind>,
        >,
    > for VersionedProofV1
{
    type Error = serde_json::Error;

    fn try_from(
        value: concordium_base::common::Versioned<
            concordium_base::id::id_proof_types::Proof<ArCurve, AttributeKind>,
        >,
    ) -> Result<Self, Self::Error> {
        serde_json::to_string(&value).and_then(|s| serde_json::from_str(&s))
    }
}

/// Prove a [`StatementV1`] given the provided context, producing a [`VersionedProofV1`]
#[allow(clippy::too_many_arguments)]
pub fn prove_statement_v1(
    seed: Bytes,
    net: String,
    global_context: GlobalContext,
    ip_info: IdentityProviderInfo,
    identity_index: u32,
    credential_index: u8,
    identity_object: IdentityObject,
    statement: StatementV1,
    challenge: Bytes,
) -> Result<VersionedProofV1, ConcordiumWalletCryptoError> {
    let fn_name = "prove_id_statement";

    let net = Net::from_str(&net)
        .context("Failed to parse network")
        .map_err(|e| e.to_call_failed(fn_name.to_string()))?;
    let wallet =
        get_wallet(hex::encode(seed), net).map_err(|e| e.to_call_failed(fn_name.to_string()))?;
    let ip_info = IpInfo::<IpPairing>::try_from(ip_info)
        .map_err(|e| e.to_call_failed(fn_name.to_string()))?;
    let identity_provider_index = ip_info.ip_identity;
    let global_context =
        concordium_base::id::types::GlobalContext::<ArCurve>::try_from(global_context)
            .map_err(|e| e.to_call_failed(fn_name.to_string()))?;
    let id_object =
        IdentityObjectV1::<IpPairing, ArCurve, AttributeKind>::try_from(identity_object)
            .map_err(|e| e.to_call_failed(fn_name.to_string()))?;

    let credential_context = CredentialContext {
        wallet,
        identity_provider_index,
        identity_index,
        credential_index,
    };
    let cred_id = credential_context
        .wallet
        .get_prf_key(identity_provider_index.0, identity_index)
        .context("Failed to get PRF key")
        .and_then(|key| {
            key.prf(&global_context.on_chain_commitment_key.g, credential_index)
                .context("Failed to compute PRF")
        })
        .map_err(|e| e.to_call_failed(fn_name.to_string()))?;

    let statement =
        concordium_base::id::id_proof_types::Statement::<ArCurve, AttributeKind>::try_from(
            statement,
        )
        .map_err(|e| e.to_call_failed(fn_name.to_string()))?;
    let statement = StatementWithContext {
        statement,
        credential: cred_id,
    };

    let proof = statement
        .prove(
            ProofVersion::Version1,
            &global_context,
            challenge.as_ref(),
            &id_object.alist,
            &credential_context,
        )
        .context("Could not produce proof.")
        .map_err(|e| e.to_call_failed(fn_name.to_string()))?;
    VersionedProofV1::try_from(concordium_base::common::Versioned::new(VERSION_0, proof))
        .map_err(|e| e.to_call_failed(fn_name.to_string()))
}
