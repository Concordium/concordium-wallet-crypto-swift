use std::{collections::HashMap, time::SystemTime};

use crate::{
    AttributeInRangeStatement, AttributeInSetStatement, AttributeNotInSetStatement, AttributeTag,
    AttributeValueStatement, Bytes, ConcordiumWalletCryptoError, ConvertError, Network,
    Web3IdAttribute,
};
use concordium_base::{
    id::constants::{ArCurve, IpPairing},
    web3id::{
        v1::{anchor::VerificationRequestData, PresentationV1 as PresV1},
        Web3IdAttribute as W3IdAttr,
    },
};
use serde::Deserialize;
use wallet_library::proofs::{PresentationV1Input, VerificationRequestV1Input};

#[derive(Deserialize)]
pub struct AttributeValueProof {
    pub proof: Bytes,
}

#[derive(Deserialize)]
#[serde(tag = "type")]
pub enum AtomicProofV1 {
    AttributeValue {
        #[serde(flatten)]
        proof: AttributeValueProof,
    }, // todo: serde flatten
    AttributeValueAlreadyRevealed,
    AttributeInRange {
        #[serde(flatten)]
        proof: Bytes,
    },
    AttributeInSet {
        #[serde(flatten)]
        proof: Bytes,
    },
    AttributeNotInSet {
        #[serde(flatten)]
        proof: Bytes,
    },
}

#[derive(Deserialize)]
pub enum IdentityAttribute {
    Committed { commited: Bytes },
    Revealed { revealed: String },
    Known,
}

#[derive(Deserialize)]
pub struct IdentityAttributesCredentialsProofs {
    pub signature: Bytes,
    pub cmm_id_cred_sec_sharing_coeff: Vec<Bytes>,
    pub challenge: Bytes,
    pub proof_id_cred_pub: HashMap<u32, Bytes>,
    pub proof_ip_signature: Bytes,
}

pub type ConcordiumIdentityCredentialZKProofs = ConcordiumZKProof<IdentityCredentialProofs>;

pub type ConcordiumAccountCredentialZKProofs = ConcordiumZKProof<AccountCredentialProofs>;

#[derive(Deserialize)]
pub struct IdentityCredentialProofs {
    pub identity_attributes: HashMap<AttributeTag, IdentityAttribute>,
    pub identity_attributes_proofs: IdentityAttributesCredentialsProofs,
    pub statement_proofs: Vec<AtomicProofV1>,
}

#[derive(Deserialize)]
pub struct AccountCredentialProofs {
    pub statement_proofs: Vec<AtomicProofV1>,
}

#[derive(Deserialize)]
pub enum ConcordiumZKProofVersion {
    ConcordiumZKProofV4,
}

#[derive(Deserialize)]
pub struct ConcordiumZKProof<T> {
    pub created_at: SystemTime,
    pub proof_value: T,
    pub proof_version: ConcordiumZKProofVersion,
}

/// Serves as a uniFFI compatible bridge to [`concordium_base::id::id_proof_types::AttributeValueStatement<ArCurve, AttributeTag, Web3IdAttribute>`]
pub type AttributeValueIdentityStatementV1 = AttributeValueStatement<AttributeTag, Web3IdAttribute>;
/// Serves as a uniFFI compatible bridge to [`concordium_base::id::id_proof_types::AttributeInRangeStatement<ArCurve, AttributeTag, Web3IdAttribute>`]
pub type AttributeInRangeIdentityStatementV1 =
    AttributeInRangeStatement<AttributeTag, Web3IdAttribute>;
/// Serves as a uniFFI compatible bridge to [`concordium_base::id::id_proof_types::AttributeInSetStatement<ArCurve, AttributeTag, Web3IdAttribute>`]
pub type AttributeInSetIdentityStatementV1 = AttributeInSetStatement<AttributeTag, Web3IdAttribute>;
/// Serves as a uniFFI compatible bridge to [`concordium_base::id::id_proof_types::AttributeNotInSetStatement<ArCurve, AttributeTag, Web3IdAttribute>`]
pub type AttributeNotInSetIdentityStatementV1 =
    AttributeNotInSetStatement<AttributeTag, Web3IdAttribute>;

/// UniFFI compatible bridge to [concordium_base::web3id::v1::AtomicStatementV1].
#[derive(Deserialize)]
pub enum AtomicStatementV1 {
    AttributeValue {
        #[serde(flatten)]
        statement: AttributeValueIdentityStatementV1,
    },
    AttributeInRange {
        #[serde(flatten)]
        statement: AttributeInRangeIdentityStatementV1,
    },
    AttributeInSet {
        #[serde(flatten)]
        statement: AttributeInSetIdentityStatementV1,
    },
    AttributeNotInSet {
        #[serde(flatten)]
        statement: AttributeNotInSetIdentityStatementV1,
    },
}

/// UniFFI compatible bridge to [concordium_base::web3id::v1::IdentityCredentialSubject].
#[derive(Deserialize)]
pub struct IdentityCredentialSubject {
    pub network: Network,
    pub cred_id: Bytes,
    pub statements: Vec<AtomicStatementV1>,
}

/// UniFFI compatible bridge to [concordium_base::web3id::v1::AccountCredentialSubject].
#[derive(Deserialize)]
pub struct AccountCredentialSubject {
    pub network: Network,
    pub cred_id: Bytes,
    pub statements: Vec<AtomicStatementV1>,
}

/// UniFFI compatible bridge to [concordium_base::web3id::v1::AccountBasedCredentialV1].
#[derive(Deserialize)]
pub struct AccountBasedCredentialV1 {
    pub issuer: u32,
    pub subject: AccountCredentialSubject,
    pub proof: ConcordiumAccountCredentialZKProofs,
}

/// UniFFI compatible bridge to [concordium_base::web3id::v1::IdentityBasedCredentialV1].
#[derive(Deserialize)]
pub struct IdentityBasedCredentialV1 {
    pub issuer: u32,
    pub validity: SystemTime,
    pub subject: IdentityCredentialSubject,
    pub proof: ConcordiumIdentityCredentialZKProofs,
}

/// UniFFI compatible bridge to [concordium_base::web3id::v1::CredentialV1<IpPairing, ArCurve, Web3IdAttribute>].
#[allow(clippy::large_enum_variant)]
#[derive(Deserialize)]
pub enum CredentialV1 {
    Account { account: AccountBasedCredentialV1 },
    Identity { identity: IdentityBasedCredentialV1 },
}

/// UniFFI compatible bridge to [concordium_base::web3id::v1::ContextProperty].
#[derive(Deserialize)]
pub struct ContextProperty {
    pub label: String,
    pub context: String,
}

/// UniFFI compatible bridge to [concordium_base::web3id::v1::ContextInformation].
#[derive(Deserialize)]
pub struct ContextInformation {
    pub given: Vec<ContextProperty>,
    pub requested: Vec<ContextProperty>,
}

/// UniFFI compatible bridge to [concordium_base::web3id::v1::PresentationV1].
#[derive(Deserialize)]
pub struct PresentationV1 {
    pub presentation_context: ContextInformation,
    pub verifiable_credentials: Vec<CredentialV1>,
}

impl TryFrom<PresV1<IpPairing, ArCurve, W3IdAttr>> for PresentationV1 {
    type Error = serde_json::Error;

    fn try_from(value: PresV1<IpPairing, ArCurve, W3IdAttr>) -> Result<Self, Self::Error> {
        serde_json::to_value(value).and_then(serde_json::from_value)
    }
}

/// Implements UDL definition of the same name.
pub fn create_presentation(input: String) -> Result<PresentationV1, ConcordiumWalletCryptoError> {
    let fn_desc = "create_presentation(input={input})";
    let proof_input: PresentationV1Input =
        serde_json::from_str(&input).map_err(|e| e.to_call_failed(fn_desc.to_string()))?;

    let presentation = proof_input
        .prove()
        .map_err(|e| e.to_call_failed(fn_desc.to_string()))?;

    PresentationV1::try_from(presentation).map_err(|e| e.to_call_failed(fn_desc.to_string()))
}

/// Implements UDL definition of the same name.
pub fn compute_anchor_hash(input: String) -> Result<Bytes, ConcordiumWalletCryptoError> {
    let fn_desc = "compute_anchor_hash(input={input})";
    let input: VerificationRequestV1Input =
        serde_json::from_str(&input).map_err(|e| e.to_call_failed(fn_desc.to_string()))?;

    let verification_request_data = VerificationRequestData {
        context: input.context,
        subject_claims: input.subject_claims,
    };

    let hash = verification_request_data.hash();

    Ok(hash.into())
}
