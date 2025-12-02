use std::time::SystemTime;

use crate::{
    AttributeInSetIdentityStatement, AttributeNotInSetIdentityStatement, AttributeTag, AttributeValueIdentityStatement, Bytes, ConcordiumWalletCryptoError, ConvertError, Network, id_proofs::AttributeInRangeIdentityStatement
};
use concordium_base::web3id::v1::anchor::VerificationRequestData;
use wallet_library::proofs::{PresentationV1Input, VerificationRequestV1Input};

pub struct AttributeValueProof {
    pub proof: Bytes,
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(tag = "type")]
pub enum AtomicProofV1 {
    AttributeValue { proof: AttributeValueProof }, // todo: serde flatten
    AttributeValueAlreadyRevealed,
    AttributeInRange { proof: Bytes },
    AttributeInSet { proof: Bytes },
    AttributeNotInSet { proof: Bytes },
}

pub enum IdentityAttribute {
    Committed(Bytes),
    Revealed(String),
    Known,
}

pub struct IdentityAttributesCredentialsProofs {}

pub struct IdentityCredentialProofs {
    pub identity_attributes: HashMap<AttributeTag, IdentityAttribute>,
    pub identity_attributes_proofs: IdentityAttributesCredentialsProofs,
    pub statement_proofs: Vec<AtomicProofV1>,
}

#[derive(Clone)]
pub struct AccountCredentialProofs {
    pub statement_proofs: Vec<AtomicProofV1>,
}

pub enum ConcordiumZKProofVersion {
    ConcordiumZKProofV4,
}

pub struct ConcordiumZKProof<T: Clone> {
    pub created_at: SystemTime,
    pub proof_value: T,
    pub proof_version: ConcordiumZKProofVersion,
}

/// UniFFI compatible bridge to [concordium_base::web3id::v1::AtomicStatementV1].
pub enum AtomicStatementV1 {
    AttributeValue {
        statement: AttributeValueIdentityStatement,
    },
    AttributeInRange {
        statement: AttributeInRangeIdentityStatement,
    },
    AttributeInSet {
        statement: AttributeInSetIdentityStatement,
    },
    AttributeNotInSet {
        statement: AttributeNotInSetIdentityStatement,
    },
}

/// UniFFI compatible bridge to [concordium_base::web3id::v1::IdentityCredentialSubject].
pub struct IdentityCredentialSubject {
    pub network: Network,
    pub cred_id: Bytes,
    pub statements: Vec<AtomicStatementV1>,
}

/// UniFFI compatible bridge to [concordium_base::web3id::v1::AccountCredentialSubject].
pub struct AccountCredentialSubject {
    pub network: Network,
    pub cred_id: Bytes,
    pub statements: Vec<AtomicStatementV1>,
}

/// UniFFI compatible bridge to [concordium_base::web3id::v1::AccountBasedCredentialV1].
pub struct AccountBasedCredentialV1 {
    pub issuer: u32,
    pub subject: AccountCredentialSubject,
    pub proof: ConcordiumZKProof<AccountCredentialProofs>,
}

/// UniFFI compatible bridge to [concordium_base::web3id::v1::IdentityBasedCredentialV1].
pub struct IdentityBasedCredentialV1 {
    pub issuer: u32,
    pub validity: SystemTime,
    pub subject: IdentityCredentialSubject,
    // pub proof: ConcordiumZKProof<T>,
}

/// UniFFI compatible bridge to [concordium_base::web3id::v1::CredentialV1].
pub enum CredentialV1 {
    Account { account: AccountBasedCredentialV1 },
    Identity { identity: IdentityBasedCredentialV1 },
}

/// UniFFI compatible bridge to [concordium_base::web3id::v1::ContextProperty].
pub struct ContextProperty {
    pub label: String,
    pub context: String,
}

/// UniFFI compatible bridge to [concordium_base::web3id::v1::ContextInformation].
pub struct ContextInformation {
    pub given: Vec<ContextProperty>,
    pub requested: Vec<ContextProperty>,
}

/// UniFFI compatible bridge to [concordium_base::web3id::v1::PresentationV1].
pub struct PresentationV1 {
    pub presentation_context: ContextInformation,
    pub verifiable_credentials: Vec<CredentialV1>,
}

/// Implements UDL definition of the same name.
pub fn create_presentation(input: String) -> Result<(), ConcordiumWalletCryptoError> {
    let fn_desc = "create_presentation(input={input})";
    let proof_input: PresentationV1Input =
        serde_json::from_str(&input).map_err(|e| e.to_call_failed(fn_desc.to_string()))?;

    proof_input
        .prove()
        .map_err(|e| e.to_call_failed(fn_desc.to_string()))?;
    Ok(())
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
