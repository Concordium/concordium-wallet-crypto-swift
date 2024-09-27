use std::{
    collections::{BTreeSet, HashMap},
    time::{SystemTime, UNIX_EPOCH},
};

use chrono::{DateTime, Utc};
use concordium_base::{
    common::to_bytes,
    contracts_common::Timestamp,
    id::{
        constants::{ArCurve, AttributeKind},
        types::IpIdentity,
    },
    web3id::{self, Presentation},
};
use uniffi::deps::anyhow::{self, Context};

use crate::{
    serde_convert, types::ContractAddress, AtomicProof, AtomicStatement, AtomicStatementV1,
    AttributeInRangeStatement, AttributeInSetStatement, AttributeNotInSetStatement, AttributeTag,
    Bytes, ConcordiumWalletCryptoError, ConvertError, GlobalContext, Network,
    RevealAttributeStatement,
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
/// Serves as a uniFFI compatible bridge to [`concordium_base::id::id_proof_types::RevealAttributeStatement<ArCurve, String>`]
pub type RevealAttributeStatementV2 = RevealAttributeStatement<String>;
/// Serves as a uniFFI compatible bridge to [`concordium_base::id::id_proof_types::AttributeInRangeStatement<ArCurve, String, Web3IdAttribute>`]
pub type AttributeInRangeStatementV2 = AttributeInRangeStatement<String, Web3IdAttribute>;
/// Serves as a uniFFI compatible bridge to [`concordium_base::id::id_proof_types::AttributeInSetStatement<ArCurve, String, Web3IdAttribute>`]
pub type AttributeInSetStatementV2 = AttributeInSetStatement<String, Web3IdAttribute>;
/// Serves as a uniFFI compatible bridge to [`concordium_base::id::id_proof_types::AttributeNotInSetStatement<ArCurve, String, Web3IdAttribute>`]
pub type AttributeNotInSetStatementV2 = AttributeNotInSetStatement<String, Web3IdAttribute>;
/// Serves as a uniFFI compatible bridge to [`concordium_base::id::id_proof_types::AtomicStatement<ArCurve, String, Web3IdAttribute>`]
pub type AtomicStatementV2 = AtomicStatement<String, Web3IdAttribute>;

/// A statement about a single credential, either an identity credential or a
/// Web3 credential.
///
/// Serves as a uniFFI compatible bridge to [`web3id::CredentialStatement<ArCurve, Web3IdAttribute>`]
pub enum VerifiableCredentialStatement {
    /// Statement about a credential derived from an identity issued by an
    /// identity provider.
    Account {
        network: Network,
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
        network: Network,
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
                network: network.into(),
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
                network: network.into(),
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
        values: HashMap<AttributeTag, String>,
        /// The randomness to go along with commitments in `values`.
        randomness: HashMap<AttributeTag, Bytes>,
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
#[serde(from = "(AtomicStatement<Tag, Value>, AtomicProof<Value>)")]
pub struct CredentialStatementWithProof<Tag, Value> {
    pub statement: AtomicStatement<Tag, Value>,
    pub proof: AtomicProof<Value>,
}

/// Serves as a uniFFI compatible bridge to [`web3id::StatementWithProof<ArCurve, String, String>`]
pub type AccountStatementWithProof = CredentialStatementWithProof<AttributeTag, String>;

/// Serves as a uniFFI compatible bridge to [`web3id::StatementWithProof<ArCurve, String, Web3IdAttribute>`]
pub type Web3IdStatementWithProof = CredentialStatementWithProof<String, Web3IdAttribute>;

impl<Tag, Value> From<(AtomicStatement<Tag, Value>, AtomicProof<Value>)>
    for CredentialStatementWithProof<Tag, Value>
{
    fn from(value: (AtomicStatement<Tag, Value>, AtomicProof<Value>)) -> Self {
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

/// The supported DID identifiers on Concordium.
#[derive(Debug)]
pub enum IdentifierType {
    /// Reference to an account via an address.
    Account { address_base58: String },
    /// Reference to a specific credential via its ID.
    Credential { cred_id: Bytes },
    /// Reference to a specific smart contract instance.
    ContractData {
        address: ContractAddress,
        entrypoint: String,
        parameter: Bytes,
    },
    /// Reference to a specific Ed25519 public key.
    PublicKey { key: Bytes },
    /// Reference to a specific identity provider.
    Idp { idp_identity: u32 },
}

impl TryFrom<IdentifierType> for web3id::did::IdentifierType {
    type Error = serde_json::Error;

    fn try_from(value: IdentifierType) -> Result<Self, Self::Error> {
        let converted = match value {
            IdentifierType::Account { address_base58 } => Self::Account {
                address: serde_json::from_str(&address_base58)?,
            },
            IdentifierType::Credential { cred_id } => Self::Credential {
                cred_id: serde_convert(cred_id)?,
            },
            IdentifierType::ContractData {
                address,
                entrypoint,
                parameter,
            } => Self::ContractData {
                address: address.into(),
                entrypoint: serde_convert(entrypoint)?,
                parameter: serde_convert(&parameter)?,
            },
            IdentifierType::PublicKey { key } => Self::PublicKey {
                key: serde_convert(&key)?,
            },
            IdentifierType::Idp { idp_identity } => Self::Idp {
                idp_identity: IpIdentity(idp_identity),
            },
        };
        Ok(converted)
    }
}

impl From<web3id::did::IdentifierType> for IdentifierType {
    fn from(value: web3id::did::IdentifierType) -> Self {
        match value {
            web3id::did::IdentifierType::Account { address } => Self::Account {
                address_base58: address.to_string(),
            },
            web3id::did::IdentifierType::Credential { cred_id } => Self::Credential {
                cred_id: to_bytes(&cred_id).into(),
            },
            web3id::did::IdentifierType::ContractData {
                address,
                entrypoint,
                parameter,
            } => Self::ContractData {
                address: address.into(),
                entrypoint: entrypoint.to_string(),
                parameter: to_bytes(&parameter).into(),
            },
            web3id::did::IdentifierType::PublicKey { key } => Self::PublicKey {
                key: to_bytes(&key).into(),
            },
            web3id::did::IdentifierType::Idp { idp_identity } => Self::Idp {
                idp_identity: idp_identity.0,
            },
        }
    }
}

/// A DID method.
#[derive(Debug)]
pub struct DID {
    /// The network part of the method.
    pub network: Network,
    /// The remaining identifier.
    pub id_type: IdentifierType,
}

impl From<web3id::did::Method> for DID {
    fn from(value: web3id::did::Method) -> Self {
        Self {
            network: value.network.into(),
            id_type: value.ty.into(),
        }
    }
}

impl TryFrom<DID> for web3id::did::Method {
    type Error = anyhow::Error;

    fn try_from(value: DID) -> Result<Self, Self::Error> {
        let converted = Self {
            network: value.network.into(),
            ty: value.id_type.try_into()?,
        };
        Ok(converted)
    }
}

/// Parse the `Method` from the given string
pub fn parse_did_method(value: String) -> Result<DID, ConcordiumWalletCryptoError> {
    let fn_desc = format!("parse_did_method(value={})", value);
    let method = web3id::did::Method::try_from(value)
        .context("Failed to parse DID")
        .map_err(|e| e.to_call_failed(fn_desc.to_string()))?;
    Ok(method.into())
}

/// Format the given `Method` as a DID string
pub fn did_method_as_string(did: DID) -> Result<String, ConcordiumWalletCryptoError> {
    let fn_desc = format!("parse_did_method(value={:?})", did);
    let method =
        web3id::did::Method::try_from(did).map_err(|e| e.to_call_failed(fn_desc.to_string()))?;
    Ok(method.to_string())
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
        network: Network,
        /// Reference to the credential to which this statement applies.
        cred_id: Bytes,
        /// Issuer of this credential, the identity provider index on the
        /// relevant network.
        issuer: u32,
        proofs: Vec<CredentialStatementWithProof<AttributeTag, String>>,
    },
    Web3Id {
        /// Creation timestamp of the proof.
        /// RFC 3339 formatted datetime
        created: SystemTime,
        /// Owner of the credential, a public key.
        /// [`web3id::CredentialHolderId`].
        holder_id: Bytes,
        /// [`web3id::did::Network`]
        network: Network,
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
        proofs: Vec<CredentialStatementWithProof<String, Web3IdAttribute>>,
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
                network: network.into(),
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
                network: network.into(),
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
