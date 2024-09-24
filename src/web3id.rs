use std::collections::HashMap;

use concordium_base::{
    base::ContractAddress,
    contracts_common::Timestamp,
    id::constants::{ArCurve, AttributeKind},
    web3id,
};

use crate::{AtomicProof, AtomicStatement, AtomicStatementV1, Bytes};

pub enum Web3IdAttribute {
    String(String),
    Numeric(u64),
    Timestamp { millis: u64 },
}

impl From<&Web3IdAttribute> for web3id::Web3IdAttribute {
    fn from(value: &Web3IdAttribute) -> Self {
        match value {
            Web3IdAttribute::String(value) => {
                web3id::Web3IdAttribute::String(AttributeKind(value.to_string()))
            }
            Web3IdAttribute::Numeric(value) => web3id::Web3IdAttribute::Numeric(*value),
            Web3IdAttribute::Timestamp { millis } => {
                web3id::Web3IdAttribute::Timestamp(Timestamp { millis: *millis })
            }
        }
    }
}

impl serde::Serialize for Web3IdAttribute {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let v = concordium_base::web3id::Web3IdAttribute::from(self);
        v.serialize(serializer)
    }
}

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

// NOTE: copied from the implementation from `concordium_base::web3id`
impl serde::Serialize for VerifiableCredentialStatement {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            VerifiableCredentialStatement::Account {
                network,
                cred_id,
                statement,
            } => {
                let json = serde_json::json!({
                    "id": format!("did:ccd:{network}:cred:{cred_id}"),
                    "statement": statement,
                });
                json.serialize(serializer)
            }
            VerifiableCredentialStatement::Web3Id {
                network,
                contract,
                holder_id,
                statement,
                cred_type,
            } => {
                let json = serde_json::json!({
                    "type": cred_type,
                    "id": format!("did:ccd:{network}:sci:{}:{}/credentialEntry/{}", contract.index, contract.subindex, holder_id),
                    "statement": statement,
                });
                json.serialize(serializer)
            }
        }
    }
}

/// A request for a proof. This is the statement and challenge. The secret data
/// comes separately.
///
/// Serves as a uniFFI compatible bridge to [`web3id::Request<ArCurve, Web3IdAttribute>`]
#[derive(serde::Serialize)]
pub struct VerifiablePresentationRequest {
    pub challenge: Bytes,
    pub statements: Vec<VerifiableCredentialStatement>,
}

impl TryFrom<VerifiablePresentationRequest> for web3id::Request<ArCurve, web3id::Web3IdAttribute> {
    type Error = serde_json::Error;

    fn try_from(value: VerifiablePresentationRequest) -> Result<Self, Self::Error> {
        serde_json::to_value(value).and_then(serde_json::from_value)
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

/// A pair of a statement and a proof.
///
/// Serves as a uniFFI compatible bridge to [`web3id::StatementWithProof<ArCurve, String, Value>`]
pub struct StatementWithProof<Value: serde::Serialize> {
    statement: AtomicStatement<String, Value>,
    proof: AtomicProof<Value>,
}

/// Commitments signed by the issuer.
///
/// Serves as a uniFFI compatible bridge to [`web3id::SignedCommitments<ArCurve>`]
#[derive(serde::Serialize)]
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
        /// Creation timestamp of the proof. UNIX timestamp
        /// RFC 3339 formatted datetime
        created: String,
        /// [`web3id::did::Network`]
        network: String,
        /// Reference to the credential to which this statement applies.
        cred_id: Bytes,
        /// Issuer of this credential, the identity provider index on the
        /// relevant network.
        issuer: u32,
        proofs: Vec<StatementWithProof<String>>,
    },
    Web3Id {
        /// Creation timestamp of the proof.
        /// RFC 3339 formatted datetime
        created: String,
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
        proofs: Vec<StatementWithProof<Web3IdAttribute>>,
    },
}

// NOTE: copied from the implementation from `concordium_base::web3id`
impl serde::Serialize for VerifiableCredentialProof {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            VerifiableCredentialProof::Account {
                created,
                network,
                cred_id,
                issuer,
                proofs,
            } => {
                let json = serde_json::json!({
                    "type": ["VerifiableCredential", "ConcordiumVerifiableCredential"],
                    "issuer": format!("did:ccd:{network}:idp:{issuer}"),
                    "credentialSubject": {
                        "id": format!("did:ccd:{network}:cred:{cred_id}"),
                        "statement": proofs.iter().map(|x| &x.statement).collect::<Vec<_>>(),
                        "proof": {
                            "type": "ConcordiumZKProofV3",
                            "created": created,
                            "proofValue": proofs.iter().map(|x| &x.proof).collect::<Vec<_>>(),
                        }
                    }
                });
                json.serialize(serializer)
            }
            VerifiableCredentialProof::Web3Id {
                created,
                network,
                contract,
                cred_type,
                commitments,
                proofs,
                holder_id,
            } => {
                let json = serde_json::json!({
                    "type": cred_type,
                    "issuer": format!("did:ccd:{network}:sci:{}:{}/issuer", contract.index, contract.subindex),
                    "credentialSubject": {
                        "id": format!("did:ccd:{network}:pkc:{}", holder_id),
                        "statement": proofs.iter().map(|x| &x.statement).collect::<Vec<_>>(),
                        "proof": {
                            "type": "ConcordiumZKProofV3",
                            "created": created,
                            "commitments": commitments,
                            "proofValue": proofs.iter().map(|x| &x.proof).collect::<Vec<_>>(),
                        }
                    }
                });
                json.serialize(serializer)
            }
        }
    }
}
///
/// A proof that establishes that the owner of the credential has indeed created
/// the presentation. At present this is a list of signatures.
///
/// Serves as a uniFFI compatible bridge to [`web3id::LinkingProof`]
pub struct LinkingProof {
    /// RFC 3339 formatted datetime
    pub created: String,
    pub proof_value: Vec<Bytes>,
}

impl serde::Serialize for LinkingProof {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let json = serde_json::json!({
            "type": "ConcordiumWeakLinkingProofV1",
            "created": self.created,
            "proofValue": self.proof_value,
        });
        json.serialize(serializer)
    }
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

// NOTE: copied from the implementation from `concordium_base::web3id`
impl serde::Serialize for VerifiablePresentation {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let json = serde_json::json!({
            "type": "VerifiablePresentation",
            "presentationContext": self.presentation_context,
            "verifiableCredential": &self.verifiable_credential,
            "proof": &self.linking_proof
        });
        json.serialize(serializer)
    }
}
