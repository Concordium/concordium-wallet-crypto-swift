use std::{
    collections::{BTreeSet, HashMap},
    time::{SystemTime, UNIX_EPOCH},
};

use chrono::{DateTime, Utc};
use concordium_base::{
    contracts_common::Timestamp,
    id::constants::{ArCurve, AttributeKind},
    web3id::{self, Presentation},
};
use uniffi::deps::anyhow::Context;

use crate::{
    types::ContractAddress, AtomicProof, AtomicStatement, AtomicStatementV1,
    AttributeInRangeStatement, AttributeInSetStatement, AttributeNotInSetStatement, Bytes,
    ConcordiumWalletCryptoError, ConvertError, GlobalContext,
};

/// A value of an attribute. This is the low-level representation. The
/// different variants are present to enable different representations in JSON,
/// and different embeddings as field elements when constructing and verifying
/// proofs.
///
/// Serves as a uniFFI compatible bridge to [`web3id::Web3IdAttribute`]
#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(from = "web3id::Web3IdAttribute", into = "web3id::Web3IdAttribute")]
pub enum Web3IdAttribute {
    String { value: String },
    Numeric { value: u64 },
    Timestamp { value: SystemTime },
}

impl From<Web3IdAttribute> for web3id::Web3IdAttribute {
    fn from(value: Web3IdAttribute) -> Self {
        match value {
            Web3IdAttribute::String { value } => {
                web3id::Web3IdAttribute::String(AttributeKind(value.to_string()))
            }
            Web3IdAttribute::Numeric { value } => web3id::Web3IdAttribute::Numeric(value),
            Web3IdAttribute::Timestamp { value } => {
                let v = DateTime::<Utc>::from(value);
                web3id::Web3IdAttribute::Timestamp(Timestamp {
                    millis: v.timestamp_millis() as u64,
                })
            }
        }
    }
}

impl From<web3id::Web3IdAttribute> for Web3IdAttribute {
    fn from(value: web3id::Web3IdAttribute) -> Self {
        match value {
            web3id::Web3IdAttribute::String(value) => Web3IdAttribute::String { value: value.0 },
            web3id::Web3IdAttribute::Numeric(value) => Web3IdAttribute::Numeric { value },
            web3id::Web3IdAttribute::Timestamp(value) => Web3IdAttribute::Timestamp {
                value: UNIX_EPOCH + std::time::Duration::from_millis(value.millis),
            },
        }
    }
}
/// Serves as a uniFFI compatible bridge to [`concordium_base::id::id_proof_types::AttributeInRangeStatement<ArCurve, String, Web3IdAttribute>`]
pub type AttributeInRangeStatementV2 = AttributeInRangeStatement<Web3IdAttribute>;
/// Serves as a uniFFI compatible bridge to [`concordium_base::id::id_proof_types::AttributeInSetStatement<ArCurve, String, Web3IdAttribute>`]
pub type AttributeInSetStatementV2 = AttributeInSetStatement<Web3IdAttribute>;
/// Serves as a uniFFI compatible bridge to [`concordium_base::id::id_proof_types::AttributeNotInSetStatement<ArCurve, String, Web3IdAttribute>`]
pub type AttributeNotInSetStatementV2 = AttributeNotInSetStatement<Web3IdAttribute>;
/// Serves as a uniFFI compatible bridge to [`concordium_base::id::id_proof_types::AtomicStatement<ArCurve, String, Web3IdAttribute>`]
pub type AtomicStatementV2 = AtomicStatement<Web3IdAttribute>;

/// A statement about a single credential, either an identity credential or a
/// Web3 credential.
///
/// Serves as a uniFFI compatible bridge to [`web3id::CredentialStatement<ArCurve, Web3IdAttribute>`]
pub enum VerifiableCredentialStatement {
    /// Statement about a credential derived from an identity issued by an
    /// identity provider.
    Account {
        /// [`web3id::did::Network`]
        network: String,
        /// [`concordium_base::base::CredentialRegistrationID`]
        cred_id: Bytes,
        statement: Vec<AtomicStatementV1>,
    },
    /// Statement about a credential issued by a Web3 identity provider, a smart
    /// contract.
    Web3Id {
        /// The credential type. This is chosen by the provider to provide
        /// some information about what the credential is about.
        cred_type: Vec<String>,
        /// [`web3id::did::Network`]
        network: String,
        /// Reference to a specific smart contract instance that issued the
        /// credential.
        contract: ContractAddress,
        /// Credential identifier inside the contract [`web3id::CredentialHolderId`].
        holder_id: Bytes,
        statement: Vec<AtomicStatementV2>,
    },
}

impl TryFrom<VerifiableCredentialStatement>
    for web3id::CredentialStatement<ArCurve, web3id::Web3IdAttribute>
{
    type Error = serde_json::Error;

    fn try_from(value: VerifiableCredentialStatement) -> Result<Self, Self::Error> {
        let cred_statement = match value {
            VerifiableCredentialStatement::Account {
                network,
                cred_id,
                statement,
            } => Self::Account {
                network: serde_json::to_value(network).and_then(serde_json::from_value)?,
                cred_id: serde_json::to_value(cred_id).and_then(serde_json::from_value)?,
                statement: serde_json::to_value(statement).and_then(serde_json::from_value)?,
            },
            VerifiableCredentialStatement::Web3Id {
                network,
                contract,
                holder_id,
                statement,
                cred_type,
            } => Self::Web3Id {
                ty: BTreeSet::from_iter(cred_type),
                network: serde_json::to_value(network).and_then(serde_json::from_value)?,
                contract: contract.into(),
                credential: serde_json::to_value(holder_id).and_then(serde_json::from_value)?,
                statement: serde_json::to_value(statement).and_then(serde_json::from_value)?,
            },
        };
        Ok(cred_statement)
    }
}

/// A request for a proof. This is the statement and challenge. The secret data
/// comes separately.
///
/// Serves as a uniFFI compatible bridge to [`web3id::Request<ArCurve, Web3IdAttribute>`]
pub struct VerifiablePresentationRequest {
    pub challenge: Bytes,
    pub statements: Vec<VerifiableCredentialStatement>,
}

impl TryFrom<VerifiablePresentationRequest> for web3id::Request<ArCurve, web3id::Web3IdAttribute> {
    type Error = serde_json::Error;

    fn try_from(value: VerifiablePresentationRequest) -> Result<Self, Self::Error> {
        let converted = Self {
            challenge: serde_json::to_value(value.challenge).and_then(serde_json::from_value)?,
            credential_statements: value
                .statements
                .into_iter()
                .map(web3id::CredentialStatement::try_from)
                .collect::<Result<Vec<_>, _>>()?,
        };
        Ok(converted)
    }
}

/// The additional inputs, additional to the [`VerifiablePresentationRequest`] that are needed to
/// produce a [`VerifablePresentation`].
///
/// Serves as a uniFFI compatible bridge to [`web3id::OwnedCommitmentInputs<ArCurve, Web3IdAttribute, SecretKey>`]
#[derive(serde::Serialize)]
pub enum VerifiableCredentialCommitmentInputs {
    /// Inputs are for an identity credential issued by an identity provider.
    Account {
        issuer: u32,
        /// The values that are committed to and are required in the proofs.
        values: HashMap<String, String>,
        /// The randomness to go along with commitments in `values`.
        randomness: HashMap<String, Bytes>,
    },
    /// Inputs are for a credential issued by Web3ID issuer.
    Web3Issuer {
        signature: Bytes,
        /// The signer that will sign the presentation.
        /// [`concordium_base::ed25519::SecretKey`]
        signer: Bytes,
        /// All the values the user has and are required in the proofs.
        values: HashMap<String, Web3IdAttribute>,
        /// The randomness to go along with commitments in `values`. This has to
        /// have the same keys as the `values` field, but it is more
        /// convenient if it is a separate map itself.
        randomness: HashMap<String, Bytes>,
    },
}

impl TryFrom<VerifiableCredentialCommitmentInputs>
    for web3id::OwnedCommitmentInputs<
        ArCurve,
        web3id::Web3IdAttribute,
        concordium_base::ed25519::SecretKey,
    >
{
    type Error = serde_json::Error;

    fn try_from(value: VerifiableCredentialCommitmentInputs) -> Result<Self, Self::Error> {
        serde_json::to_value(value).and_then(serde_json::from_value)
    }
}

/// Serves as a uniFFI compatible bridge to [`id::id_proof_types::AtomicProof<ArCurve, Web3IdAttribute>`]
pub type AtomicProofV2 = AtomicProof<Web3IdAttribute>;

/// A pair of a statement and a proof.
#[derive(serde::Deserialize)]
#[serde(from = "(AtomicStatement<Value>, AtomicProof<Value>)")]
pub struct CredentialStatementWithProof<Value> {
    pub statement: AtomicStatement<Value>,
    pub proof: AtomicProof<Value>,
}

/// Serves as a uniFFI compatible bridge to [`web3id::StatementWithProof<ArCurve, String, String>`]
pub type AccountStatementWithProof = CredentialStatementWithProof<String>;

/// Serves as a uniFFI compatible bridge to [`web3id::StatementWithProof<ArCurve, String, Web3IdAttribute>`]
pub type Web3IdStatementWithProof = CredentialStatementWithProof<Web3IdAttribute>;

impl<Value> From<(AtomicStatement<Value>, AtomicProof<Value>)>
    for CredentialStatementWithProof<Value>
{
    fn from(value: (AtomicStatement<Value>, AtomicProof<Value>)) -> Self {
        Self {
            statement: value.0,
            proof: value.1,
        }
    }
}

/// Commitments signed by the issuer.
///
/// Serves as a uniFFI compatible bridge to [`web3id::SignedCommitments<ArCurve>`]
#[derive(serde::Deserialize)]
pub struct SignedCommitments {
    pub signature: Bytes,
    pub commitments: HashMap<String, Bytes>,
}

/// A proof corresponding to one [`CredentialStatement`]. This contains almost
/// all the information needed to verify it, except the issuer's public key in
/// case of the `Web3Id` proof, and the public commitments in case of the
/// `Account` proof.
///
/// Serves as a uniFFI compatible bridge to [`web3id::CredentialProof<ArCurve, Web3IdAttribute>`]
pub enum VerifiableCredentialProof {
    Account {
        /// Creation timestamp of the proof.
        /// RFC 3339 formatted datetime
        created: SystemTime,
        /// [`web3id::did::Network`]
        network: String,
        /// Reference to the credential to which this statement applies.
        cred_id: Bytes,
        /// Issuer of this credential, the identity provider index on the
        /// relevant network.
        issuer: u32,
        proofs: Vec<CredentialStatementWithProof<String>>,
    },
    Web3Id {
        /// Creation timestamp of the proof.
        /// RFC 3339 formatted datetime
        created: SystemTime,
        /// Owner of the credential, a public key.
        /// [`web3id::CredentialHolderId`].
        holder_id: Bytes,
        /// [`web3id::did::Network`]
        network: String,
        /// Reference to a specific smart contract instance.
        contract: ContractAddress,
        /// The credential type. This is chosen by the provider to provide
        /// some information about what the credential is about.
        cred_type: Vec<String>,
        /// Commitments that the user has. These are all the commitments that
        /// are part of the credential, indexed by the attribute tag.
        /// [`web3id::SignedCommitments<ArCurve>`]
        commitments: SignedCommitments,
        /// Individual proofs for statements.
        proofs: Vec<CredentialStatementWithProof<Web3IdAttribute>>,
    },
}

impl TryFrom<web3id::CredentialProof<ArCurve, web3id::Web3IdAttribute>>
    for VerifiableCredentialProof
{
    type Error = serde_json::Error;

    fn try_from(
        value: web3id::CredentialProof<ArCurve, web3id::Web3IdAttribute>,
    ) -> Result<Self, Self::Error> {
        let converted = match value {
            web3id::CredentialProof::Account {
                created,
                network,
                cred_id,
                issuer,
                proofs,
            } => Self::Account {
                created: created.into(),
                network: serde_json::to_value(network).and_then(serde_json::from_value)?,
                cred_id: serde_json::to_value(cred_id).and_then(serde_json::from_value)?,
                issuer: issuer.0,
                proofs: serde_json::to_value(proofs).and_then(serde_json::from_value)?,
            },
            web3id::CredentialProof::Web3Id {
                created,
                holder,
                network,
                contract,
                ty,
                commitments,
                proofs,
            } => Self::Web3Id {
                created: created.into(),
                holder_id: serde_json::to_value(holder).and_then(serde_json::from_value)?,
                network: serde_json::to_value(network).and_then(serde_json::from_value)?,
                contract: contract.into(),
                cred_type: ty.into_iter().collect(),
                commitments: serde_json::to_value(commitments).and_then(serde_json::from_value)?,
                proofs: serde_json::to_value(proofs).and_then(serde_json::from_value)?,
            },
        };
        Ok(converted)
    }
}

fn deserialize_system_time<'de, D>(deserializer: D) -> Result<SystemTime, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let dt: DateTime<Utc> = serde::Deserialize::deserialize(deserializer)?;
    Ok(dt.into())
}

/// A proof that establishes that the owner of the credential has indeed created
/// the presentation. At present this is a list of signatures.
///
/// Serves as a uniFFI compatible bridge to [`web3id::LinkingProof`]
#[derive(serde::Deserialize)]
pub struct LinkingProof {
    #[serde(deserialize_with = "deserialize_system_time")]
    pub created: SystemTime,
    pub proof_value: Vec<Bytes>,
}

/// A presentation is the response to a [`Request`]. It contains proofs for
/// statements, ownership proof for all Web3 credentials, and a context. The
/// only missing part to verify the proof are the public commitments.
///
/// Serves as a uniFFI compatible bridge to [`web3id::Presentation<ArCurve, Web3IdAttribute>`]
pub struct VerifiablePresentation {
    pub presentation_context: Bytes,
    pub verifiable_credential: Vec<VerifiableCredentialProof>,
    /// Signatures from keys of Web3 credentials (not from ID credentials).
    /// The order is the same as that in the `credential_proofs` field.
    pub linking_proof: LinkingProof,
}

impl TryFrom<Presentation<ArCurve, web3id::Web3IdAttribute>> for VerifiablePresentation {
    type Error = serde_json::Error;

    fn try_from(
        value: Presentation<ArCurve, web3id::Web3IdAttribute>,
    ) -> Result<Self, Self::Error> {
        let verifiable_credential: Result<Vec<_>, _> = value
            .verifiable_credential
            .into_iter()
            .map(VerifiableCredentialProof::try_from)
            .collect();
        let converted = Self {
            presentation_context: serde_json::to_value(value.presentation_context)
                .and_then(serde_json::from_value)?,
            linking_proof: serde_json::to_value(value.linking_proof)
                .and_then(serde_json::from_value)?,
            verifiable_credential: verifiable_credential?,
        };
        Ok(converted)
    }
}

/// Create a verifiable presentation from a [`VerifiablePresentationRequest`], the associated
/// commitment inputs and the cryptographic parameters of the chain.
pub fn create_verifiable_presentation(
    request: VerifiablePresentationRequest,
    global: GlobalContext,
    commitment_inputs: Vec<VerifiableCredentialCommitmentInputs>,
) -> Result<VerifiablePresentation, ConcordiumWalletCryptoError> {
    let fn_name = "create_verifiable_presentation";
    let request =
        web3id::Request::try_from(request).map_err(|e| e.to_call_failed(fn_name.to_string()))?;
    let global = concordium_base::id::types::GlobalContext::<ArCurve>::try_from(global)
        .map_err(|e| e.to_call_failed(fn_name.to_string()))?;
    let commitment_inputs: Vec<_> = commitment_inputs
        .into_iter()
        .map(web3id::OwnedCommitmentInputs::try_from)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| e.to_call_failed(fn_name.to_string()))?;

    let presentation = request
        .prove(&global, commitment_inputs.iter().map(Into::into))
        .context("Failed to create verifiable presentation")
        .map_err(|e| e.to_call_failed(fn_name.to_string()))?;
    VerifiablePresentation::try_from(presentation)
        .map_err(|e| e.to_call_failed(fn_name.to_string()))
}
