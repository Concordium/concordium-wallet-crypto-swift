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

/// Serves as a uniFFI compatible bridge to [`concordium_base::id::id_proof_types::AttributeValueProof<ArCurve>`]
#[derive(Debug, Deserialize, PartialEq)]
pub struct AttributeValueProof {
    pub proof: Bytes,
}

/// UniFFI compatible bridge to [concordium_base::web3id::v1::AtomicProofV1<ArCurve>].
#[derive(Debug, Deserialize, PartialEq)]
#[serde(tag = "type")]
pub enum AtomicProofV1 {
    AttributeValue {
        #[serde(flatten)]
        proof: AttributeValueProof,
    },
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

/// Serves as a uniFFI compatible bridge to [`concordium_base::id::types::IdentityAttribute<ArCurve, AttributeTag>`]
#[derive(Debug, Deserialize, PartialEq)]
pub enum IdentityAttribute {
    Committed {
        #[serde(flatten)]
        commited: Bytes,
    },
    Revealed {
        #[serde(flatten)]
        revealed: String,
    },
    Known,
}

/// Serves as a uniFFI compatible bridge to [`concordium_base::id::types::IdentityAttributesCredentialsProofs<IpPairing, ArCurve>`]
#[derive(Debug, Deserialize, PartialEq)]
pub struct IdentityAttributesCredentialsProofs {
    pub signature: Bytes,
    pub cmm_id_cred_sec_sharing_coeff: Vec<Bytes>,
    pub challenge: Bytes,
    pub proof_id_cred_pub: HashMap<u32, Bytes>,
    pub proof_ip_signature: Bytes,
}

/// UniFFI compatible bridge to [concordium_base::web3id::v1::ConcordiumZKProof<IdentityCredentialProofs<ArCurve, AttributeTag, Web3IdAttribute>>].
pub type ConcordiumIdentityCredentialZKProofs = ConcordiumZKProof<IdentityCredentialProofs>;

/// UniFFI compatible bridge to [concordium_base::web3id::v1::ConcordiumZKProof<AccountCredentialProofs<ArCurve>>].
pub type ConcordiumAccountCredentialZKProofs = ConcordiumZKProof<AccountCredentialProofs>;

/// UniFFI compatible bridge to [concordium_base::web3id::v1::IdentityCredentialProofs<ArCurve, AttributeTag, Web3IdAttribute>].
#[derive(Debug, Deserialize, PartialEq)]
pub struct IdentityCredentialProofs {
    pub identity_attributes: HashMap<AttributeTag, IdentityAttribute>,
    pub identity_attributes_proofs: IdentityAttributesCredentialsProofs,
    pub statement_proofs: Vec<AtomicProofV1>,
}

/// UniFFI compatible bridge to [concordium_base::web3id::v1::AccountCredentialProofs<ArCurve>].
#[derive(Debug, Deserialize, PartialEq)]
pub struct AccountCredentialProofs {
    pub statement_proofs: Vec<AtomicProofV1>,
}

/// UniFFI compatible bridge to [concordium_base::web3id::v1::ConcordiumZKProofVersion].
#[derive(Debug, Deserialize, PartialEq)]
pub enum ConcordiumZKProofVersion {
    ConcordiumZKProofV4,
}

#[derive(Debug, Deserialize, PartialEq)]
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

/// UniFFI compatible bridge to [concordium_base::web3id::v1::AtomicStatementV1<ArCurve, AttributeTag, Web3IdAttribute>].
#[derive(Debug, Deserialize, PartialEq)]
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

/// UniFFI compatible bridge to [concordium_base::web3id::v1::IdentityCredentialSubject<ArCurve, Web3IdAttribute>].
#[derive(Debug, Deserialize, PartialEq)]
pub struct IdentityCredentialSubject {
    pub network: Network,
    pub cred_id: Bytes,
    pub statements: Vec<AtomicStatementV1>,
}

/// UniFFI compatible bridge to [concordium_base::web3id::v1::AccountCredentialSubject<ArCurve, Web3IdAttribute>].
#[derive(Debug, Deserialize, PartialEq)]
pub struct AccountCredentialSubject {
    pub network: Network,
    pub cred_id: Bytes,
    pub statements: Vec<AtomicStatementV1>,
}

/// UniFFI compatible bridge to [concordium_base::web3id::v1::AccountBasedCredentialV1<ArCurve, Web3IdAttribute>].
#[derive(Debug, Deserialize, PartialEq)]
pub struct AccountBasedCredentialV1 {
    pub issuer: u32,
    pub subject: AccountCredentialSubject,
    pub proof: ConcordiumAccountCredentialZKProofs,
}

/// UniFFI compatible bridge to [concordium_base::web3id::v1::IdentityBasedCredentialV1<IpPairing, ArCurve, Web3IdAttribute>].
#[derive(Debug, Deserialize, PartialEq)]
pub struct IdentityBasedCredentialV1 {
    pub issuer: u32,
    pub validity: SystemTime,
    pub subject: IdentityCredentialSubject,
    pub proof: ConcordiumIdentityCredentialZKProofs,
}

/// UniFFI compatible bridge to [concordium_base::web3id::v1::CredentialV1<IpPairing, ArCurve, Web3IdAttribute>].
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Deserialize, PartialEq)]
pub enum CredentialV1 {
    Account {
        #[serde(flatten)]
        account: AccountBasedCredentialV1,
    },
    Identity {
        #[serde(flatten)]
        identity: IdentityBasedCredentialV1,
    },
}

/// UniFFI compatible bridge to [concordium_base::web3id::v1::ContextProperty].
#[derive(Debug, Deserialize, PartialEq)]
pub struct ContextProperty {
    pub label: String,
    pub context: String,
}

/// UniFFI compatible bridge to [concordium_base::web3id::v1::ContextInformation].
#[derive(Debug, Deserialize, PartialEq)]
pub struct ContextInformation {
    pub given: Vec<ContextProperty>,
    pub requested: Vec<ContextProperty>,
}

/// UniFFI compatible bridge to [concordium_base::web3id::v1::PresentationV1<IpPairing, ArCurve, Web3IdAttribute>].
#[derive(Debug, Deserialize, PartialEq)]
pub struct PresentationV1 {
    #[serde(rename = "presentationContext")]
    pub presentation_context: ContextInformation,
    #[serde(rename = "verifiableCredential")]
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

#[cfg(test)]
mod tests {
    use super::*;
    use concordium_base::web3id::v1;

    fn create_base_presntation_v1() -> PresV1<IpPairing, ArCurve, W3IdAttr> {
        let presentation_context = v1::ContextInformation {
            given: vec![v1::ContextProperty {
                label: "label".into(),
                context: "context".into(),
            }],
            requested: vec![],
        };

        let linking_proof = v1::LinkingProofV1 {
            created_at: chrono::DateTime::from_timestamp_secs(0).unwrap(),
            proof_value: [0u8; 0],
            proof_type: v1::ConcordiumLinkingProofVersion::ConcordiumWeakLinkingProofV1,
        };

        let verifiable_credentials = vec![];

        PresV1 {
            presentation_context,
            verifiable_credentials,
            linking_proof,
        }
    }

    fn create_crate_presentation_v1() -> PresentationV1 {
        let presentation_context = ContextInformation {
            given: vec![ContextProperty {
                label: "label".into(),
                context: "context".into(),
            }],
            requested: vec![],
        };
        let verifiable_credentials = vec![];
        PresentationV1 {
            presentation_context,
            verifiable_credentials,
        }
    }

    #[test]
    fn convert_presentation_v1() {
        let base_pres_v1 = create_base_presntation_v1();
        let crate_pres_v1 = create_crate_presentation_v1();

        let converted = PresentationV1::try_from(base_pres_v1)
            .expect("Could not convert from base's PresentationV1");
        assert_eq!(crate_pres_v1, converted);
    }
}
