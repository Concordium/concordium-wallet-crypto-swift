use concordium_base::{
    common::VERSION_0,
    id::{
        constants::{ArCurve, AttributeKind, IpPairing},
        id_proof_types::{ProofVersion, StatementWithContext},
        types::IdentityObjectV1,
    },
};
use key_derivation::CredentialContext;
use serde::{Deserialize, Serialize};
use uniffi::deps::anyhow::Context;
use wallet_library::wallet::get_wallet;

use crate::{
    AttributeTag, Bytes, ConcordiumWalletCryptoError, ConvertError, GlobalContext, IdentityObject,
    Network, Versioned,
};

/// For the case where the verifier wants the user to show the value of an
/// attribute and prove that it is indeed the value inside the on-chain
/// commitment. Since the verifier does not know the attribute value before
/// seing the proof, the value is not present here.
#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct RevealAttributeStatement<Tag: Clone> {
    /// The attribute that the verifier wants the user to reveal.
    pub attribute_tag: Tag,
}

/// Serves as a uniFFI compatible bridge to [`concordium_base::id::id_proof_types::RevealAttributeStatement<AttributeTag>`]
pub type RevealAttributeIdentityStatement = RevealAttributeStatement<AttributeTag>;

/// For the case where the verifier wants the user to prove that an attribute is
/// in a range. The statement is that the attribute value lies in `[lower,
/// upper)` in the scalar field.
#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct AttributeInRangeStatement<Tag: Clone, Value: Clone> {
    /// The attribute that the verifier wants the user to prove is in a range.
    pub attribute_tag: Tag,
    /// The lower bound on the range.
    pub lower: Value,
    /// The upper bound of the range.
    pub upper: Value,
}

/// Serves as a uniFFI compatible bridge to [`concordium_base::id::id_proof_types::AttributeInRangeStatement<ArCurve, AttributeTag, AttributeKind>`]
pub type AttributeInRangeIdentityStatement = AttributeInRangeStatement<AttributeTag, String>;

/// For the case where the verifier wants the user to prove that an attribute is
/// in a set of attributes.
#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct AttributeInSetStatement<Tag: Clone, Value: Clone> {
    /// The attribute that the verifier wants the user prove lies in a set.
    pub attribute_tag: Tag,
    /// The set that the attribute should lie in.
    pub set: Vec<Value>,
}

/// Serves as a uniFFI compatible bridge to [`concordium_base::id::id_proof_types::AttributeInSetStatement<ArCurve, AttributeTag, AttributeKind>`]
pub type AttributeInSetIdentityStatement = AttributeInSetStatement<AttributeTag, String>;

/// For the case where the verifier wants the user to prove that an attribute is
/// not in a set of attributes.
#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct AttributeNotInSetStatement<Tag: Clone, Value: Clone> {
    /// The attribute that the verifier wants the user to prove does not lie in
    /// a set.
    pub attribute_tag: Tag,
    /// The set that the attribute should not lie in.
    pub set: Vec<Value>,
}

/// Serves as a uniFFI compatible bridge to [`concordium_base::id::id_proof_types::AttributeNotInSetStatement<ArCurve, AttributeTag, AttributeKind>`]
pub type AttributeNotInSetIdentityStatement = AttributeNotInSetStatement<AttributeTag, String>;

#[derive(Serialize, Deserialize, Clone)]
#[serde(tag = "type")]
pub enum AtomicStatement<Tag: Clone, Value: Clone> {
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
pub type AtomicIdentityStatement = AtomicStatement<AttributeTag, String>;

#[derive(Serialize)]
#[serde(transparent)]
pub struct Statement<Tag: Clone, Value: Clone> {
    pub statements: Vec<AtomicStatement<Tag, Value>>,
}

/// Serves as a uniFFI compatible bridge to [`concordium_base::id::id_proof_types::Statement<ArCurve, AttributeKind>`]
pub type IdentityStatement = Statement<AttributeTag, String>;

impl TryFrom<IdentityStatement>
    for concordium_base::id::id_proof_types::Statement<ArCurve, AttributeKind>
{
    type Error = serde_json::Error;

    fn try_from(value: IdentityStatement) -> Result<Self, Self::Error> {
        serde_json::to_string(&value).and_then(|s| serde_json::from_str(&s))
    }
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum AtomicProof<Value> {
    /// Revealing an attribute and a proof that it equals the attribute value
    /// inside the attribute commitment.
    RevealAttribute { attribute: Value, proof: Bytes },
    /// The atomic proof stating that an attribute is in a range.
    AttributeInRange { proof: Bytes },
    /// The atomic proof stating that an attribute is in a set.
    AttributeInSet { proof: Bytes },
    /// The atomic proof stating that an attribute is not in a set.
    AttributeNotInSet { proof: Bytes },
}

/// Serves as a uniFFI compatible bridge to [`concordium_base::id::id_proof_types::AtomicProof<ArCurve, AttributeKind>`]
pub type AtomicIdentityProof = AtomicProof<String>;

#[derive(Deserialize)]
pub struct Proof<Value> {
    pub proofs: Vec<AtomicProof<Value>>,
}

/// Serves as a uniFFI compatible bridge to [`concordium_base::id::id_proof_types::Proof<ArCurve, AttributeKind>`]
pub type IdentityProof = Proof<String>;

/// Serves as a uniFFI compatible bridge to [`concordium_base::common::Versioned<Proof<ArCurve, AttributeKind>>`]
pub type VersionedIdentityProof = Versioned<IdentityProof>;

impl
    TryFrom<
        concordium_base::common::Versioned<
            concordium_base::id::id_proof_types::Proof<ArCurve, AttributeKind>,
        >,
    > for VersionedIdentityProof
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

/// Prove a [`IdentityStatement`] given the provided context, producing a [`VersionedIdentityProof`]
#[allow(clippy::too_many_arguments)]
pub fn prove_identity_statement(
    seed: Bytes,
    net: Network,
    global_context: GlobalContext,
    ip_index: u32,
    identity_index: u32,
    credential_index: u8,
    identity_object: IdentityObject,
    statement: IdentityStatement,
    challenge: Bytes,
) -> Result<VersionedIdentityProof, ConcordiumWalletCryptoError> {
    let fn_name = "prove_id_statement";

    let wallet = get_wallet(hex::encode(seed), net.into())
        .map_err(|e| e.to_call_failed(fn_name.to_string()))?;
    let global_context =
        concordium_base::id::types::GlobalContext::<ArCurve>::try_from(global_context)
            .map_err(|e| e.to_call_failed(fn_name.to_string()))?;
    let id_object =
        IdentityObjectV1::<IpPairing, ArCurve, AttributeKind>::try_from(identity_object)
            .map_err(|e| e.to_call_failed(fn_name.to_string()))?;

    let credential_context = CredentialContext {
        wallet,
        identity_provider_index: ip_index.into(),
        identity_index,
        credential_index,
    };
    let cred_id = credential_context
        .wallet
        .get_prf_key(ip_index, identity_index)
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
            ProofVersion::Version2,
            &global_context,
            challenge.as_ref(),
            &id_object.alist,
            &credential_context,
        )
        .context("Could not produce proof.")
        .map_err(|e| e.to_call_failed(fn_name.to_string()))?;
    VersionedIdentityProof::try_from(concordium_base::common::Versioned::new(VERSION_0, proof))
        .map_err(|e| e.to_call_failed(fn_name.to_string()))
}
