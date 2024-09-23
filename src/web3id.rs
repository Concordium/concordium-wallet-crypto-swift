use concordium_base::{
    base::ContractAddress, contracts_common::Timestamp, id::constants::AttributeKind,
};

use crate::{AtomicStatement, AtomicStatementV1, Bytes};

// We deviate from using serde for translation between uniFFI compatible types and types from
// concordium_base, as the serialization of these align with the spec for verifiable credentials
// and the different entities defined in that. Converting back and forth from these is too complex
// to be feasible.

pub enum Web3IdAttribute {
    String(String),
    Numeric(u64),
    Timestamp { millis: u64 },
}

impl From<&Web3IdAttribute> for concordium_base::web3id::Web3IdAttribute {
    fn from(value: &Web3IdAttribute) -> Self {
        match value {
            Web3IdAttribute::String(value) => {
                concordium_base::web3id::Web3IdAttribute::String(AttributeKind(value.to_string()))
            }
            Web3IdAttribute::Numeric(value) => {
                concordium_base::web3id::Web3IdAttribute::Numeric(*value)
            }
            Web3IdAttribute::Timestamp { millis } => {
                concordium_base::web3id::Web3IdAttribute::Timestamp(Timestamp { millis: *millis })
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

pub type AtomicStatementV2 = AtomicStatement<String, Web3IdAttribute>;

pub enum CredentialStatement {
    /// Statement about a credential derived from an identity issued by an
    /// identity provider.
    Account {
        /// [`concordium_base::web3id::did::Network`]
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
        ty: Vec<String>,
        /// [`concordium_base::web3id::did::Network`]
        network: String,
        /// Reference to a specific smart contract instance that issued the
        /// credential.
        contract: ContractAddress,
        /// Credential identifier inside the contract [`concordium_base::web3id::CredentialHolderId`].
        credential: Bytes,
        statement: Vec<AtomicStatementV2>,
    },
}
