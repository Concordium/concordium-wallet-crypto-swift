use std::{collections::HashMap, time::SystemTime};

use crate::{
    serde_convert, AnonymityRevokerInfo, AttributeInRangeStatement, AttributeInSetStatement,
    AttributeNotInSetStatement, AttributeTag, AttributeValueStatement, Bytes,
    ConcordiumWalletCryptoError, ConvertError, GlobalContext, IdentityObject, IdentityProviderInfo,
    Network, RevealAttributeIdentityStatement, Web3IdAttribute,
};
use concordium_base::{
    common::{base16_encode_string, Serialize},
    id::{
        constants::{ArCurve, IpPairing},
        types,
    },
    web3id::{v1, Web3IdAttribute as W3IdAttr},
};
use serde::{de::Error as DeError, Deserialize};

/// UniFFI compatible bridge to [concordium_base::web3id::v1::ConcordiumZKProof].
pub type ConcordiumCredentialZKProofs = ConcordiumZKProof<Bytes>;

impl<T: Serialize> TryFrom<v1::ConcordiumZKProof<T>> for ConcordiumCredentialZKProofs {
    type Error = uniffi::deps::anyhow::Error;

    fn try_from(value: v1::ConcordiumZKProof<T>) -> Result<Self, Self::Error> {
        Ok(Self {
            created_at: value.created_at.into(),
            proof_value: base16_encode_string(&value.proof_value)
                .as_str()
                .try_into()?,
            proof_version: ConcordiumZKProofVersion::ConcordiumZKProofV4,
        })
    }
}

/// UniFFI compatible bridge to [concordium_base::web3id::v1::ConcordiumZKProofVersion].
#[derive(Debug, Deserialize, PartialEq)]
pub enum ConcordiumZKProofVersion {
    ConcordiumZKProofV4,
}

#[derive(Debug, Deserialize, PartialEq)]
pub struct ConcordiumZKProof<T> {
    #[serde(rename = "created")]
    pub created_at: SystemTime,
    #[serde(rename = "proofValue")]
    pub proof_value: T,
    #[serde(rename = "type")]
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
#[derive(Debug, serde::Serialize, Deserialize, PartialEq)]
#[serde(tag = "type")]
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

impl TryFrom<v1::AtomicStatementV1<ArCurve, concordium_base::id::types::AttributeTag, W3IdAttr>>
    for AtomicStatementV1
{
    type Error = serde_json::Error;

    fn try_from(
        value: v1::AtomicStatementV1<ArCurve, concordium_base::id::types::AttributeTag, W3IdAttr>,
    ) -> Result<Self, Self::Error> {
        serde_convert(value)
    }
}

/// UniFFI compatible bridge to [concordium_base::web3id::v1::IdentityCredentialSubject<ArCurve, Web3IdAttribute>].
#[derive(Debug, PartialEq)]
pub struct IdentityCredentialSubject {
    pub network: Network,
    pub cred_id: Bytes,
    pub statements: Vec<AtomicStatementV1>,
}

impl TryFrom<v1::IdentityCredentialSubject<ArCurve, W3IdAttr>> for IdentityCredentialSubject {
    type Error = uniffi::deps::anyhow::Error;

    fn try_from(
        value: v1::IdentityCredentialSubject<ArCurve, W3IdAttr>,
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            network: value.network.into(),
            cred_id: Bytes(value.cred_id.0),
            statements: value
                .statements
                .into_iter()
                .map(|val| val.try_into())
                .collect::<Result<_, _>>()?,
        })
    }
}

/// UniFFI compatible bridge to [concordium_base::web3id::v1::AccountCredentialSubject<ArCurve, Web3IdAttribute>].
#[derive(Debug, PartialEq)]
pub struct AccountCredentialSubject {
    pub network: Network,
    pub cred_id: Bytes,
    pub statements: Vec<AtomicStatementV1>,
}

impl TryFrom<v1::AccountCredentialSubject<ArCurve, W3IdAttr>> for AccountCredentialSubject {
    type Error = uniffi::deps::anyhow::Error;

    fn try_from(
        value: v1::AccountCredentialSubject<ArCurve, W3IdAttr>,
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            network: value.network.into(),
            cred_id: Bytes(value.cred_id.to_string().into_bytes()),
            statements: value
                .statements
                .into_iter()
                .map(|val| val.try_into())
                .collect::<Result<_, _>>()?,
        })
    }
}

/// UniFFI compatible bridge to [concordium_base::web3id::v1::AccountBasedCredentialV1<ArCurve, Web3IdAttribute>].
#[derive(Debug, PartialEq)]
pub struct AccountBasedCredentialV1 {
    pub issuer: u32,
    pub subject: AccountCredentialSubject,
    pub proofs: ConcordiumCredentialZKProofs,
}

impl TryFrom<v1::AccountBasedCredentialV1<ArCurve, W3IdAttr>> for AccountBasedCredentialV1 {
    type Error = uniffi::deps::anyhow::Error;

    fn try_from(
        value: v1::AccountBasedCredentialV1<ArCurve, W3IdAttr>,
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            issuer: value.issuer.0,
            subject: value.subject.try_into()?,
            proofs: value.proof.try_into()?,
        })
    }
}

/// UniFFI compatible bridge to [concordium_base::web3id::v1::IdentityBasedCredentialV1<IpPairing, ArCurve, Web3IdAttribute>].
#[derive(Debug, PartialEq)]
pub struct IdentityBasedCredentialV1 {
    pub issuer: u32,
    pub valid_from: SystemTime,
    pub valid_until: SystemTime,
    pub subject: IdentityCredentialSubject,
    pub proofs: ConcordiumCredentialZKProofs,
}

impl TryFrom<v1::IdentityBasedCredentialV1<IpPairing, ArCurve, W3IdAttr>>
    for IdentityBasedCredentialV1
{
    type Error = uniffi::deps::anyhow::Error;

    fn try_from(
        value: v1::IdentityBasedCredentialV1<IpPairing, ArCurve, W3IdAttr>,
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            issuer: value.issuer.0,
            valid_until: value
                .validity
                .valid_to
                .upper_inclusive()
                .unwrap_or_default()
                .into(),
            valid_from: value.validity.created_at.lower().unwrap_or_default().into(),
            subject: value.subject.try_into()?,
            proofs: value.proof.try_into()?,
        })
    }
}

/// UniFFI compatible bridge to [concordium_base::web3id::v1::CredentialV1<IpPairing, ArCurve, Web3IdAttribute>].
#[allow(clippy::large_enum_variant)]
#[derive(Debug, PartialEq)]
pub enum CredentialV1 {
    Account { account: AccountBasedCredentialV1 },
    Identity { identity: IdentityBasedCredentialV1 },
}

impl TryFrom<v1::CredentialV1<IpPairing, ArCurve, W3IdAttr>> for CredentialV1 {
    type Error = uniffi::deps::anyhow::Error;

    fn try_from(
        value: v1::CredentialV1<IpPairing, ArCurve, W3IdAttr>,
    ) -> Result<Self, Self::Error> {
        match value {
            v1::CredentialV1::Account(acc_cred) => Ok(Self::Account {
                account: acc_cred.try_into()?,
            }),
            v1::CredentialV1::Identity(id_cred) => Ok(Self::Identity {
                identity: id_cred.try_into()?,
            }),
        }
    }
}

/// UniFFI compatible bridge to [concordium_base::web3id::v1::ContextProperty].
#[derive(Debug, PartialEq)]
pub struct ContextProperty {
    pub label: String,
    pub context: String,
}

impl From<v1::ContextProperty> for ContextProperty {
    fn from(value: v1::ContextProperty) -> Self {
        Self {
            label: value.label,
            context: value.context,
        }
    }
}

impl From<ContextProperty> for v1::ContextProperty {
    fn from(value: ContextProperty) -> Self {
        Self {
            label: value.label,
            context: value.context,
        }
    }
}

/// UniFFI compatible bridge to [concordium_base::web3id::v1::ContextInformation].
#[derive(Debug, PartialEq)]
pub struct ContextInformation {
    pub given: Vec<ContextProperty>,
    pub requested: Vec<ContextProperty>,
}

impl From<v1::ContextInformation> for ContextInformation {
    fn from(value: v1::ContextInformation) -> Self {
        Self {
            given: value.given.into_iter().map(|val| val.into()).collect(),
            requested: value.requested.into_iter().map(|val| val.into()).collect(),
        }
    }
}

impl From<ContextInformation> for v1::ContextInformation {
    fn from(value: ContextInformation) -> Self {
        Self {
            given: value.given.into_iter().map(|val| val.into()).collect(),
            requested: value.requested.into_iter().map(|val| val.into()).collect(),
        }
    }
}

#[derive(Debug, PartialEq)]
pub enum ConcordiumLinkingProofVersion {
    ConcordiumWeakLinkingProofV1,
}

/// UniFFI compatible bridge to [concordium_base::web3id::v1::LinkingProofV1].
#[derive(Debug, PartialEq)]
pub struct LinkingProofV1 {
    pub created_at: SystemTime,
    pub proof_value: Vec<u8>,
    pub proof_type: ConcordiumLinkingProofVersion,
}

impl From<v1::LinkingProofV1> for LinkingProofV1 {
    fn from(value: v1::LinkingProofV1) -> Self {
        Self {
            created_at: value.created_at.into(),
            proof_value: value.proof_value.into(),
            proof_type: ConcordiumLinkingProofVersion::ConcordiumWeakLinkingProofV1,
        }
    }
}

/// UniFFI compatible bridge to [concordium_base::web3id::v1::PresentationV1<IpPairing, ArCurve, Web3IdAttribute>].
#[derive(Debug, PartialEq)]
pub struct PresentationV1 {
    pub presentation_context: ContextInformation,
    pub verifiable_credentials: Vec<CredentialV1>,
    pub linking_proof: LinkingProofV1,
}

impl TryFrom<v1::PresentationV1<IpPairing, ArCurve, W3IdAttr>> for PresentationV1 {
    type Error = uniffi::deps::anyhow::Error;

    fn try_from(
        value: v1::PresentationV1<IpPairing, ArCurve, W3IdAttr>,
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            presentation_context: value.presentation_context.into(),
            linking_proof: value.linking_proof.into(),
            verifiable_credentials: value
                .verifiable_credentials
                .into_iter()
                .map(|val| val.try_into())
                .collect::<Result<_, _>>()?,
        })
    }
}

/// UniFFI compatible bridge to [concordium_base::web3id::v1::IdentityBasedSubjectClaims<ArCurve, Web3IdAttribute>].
pub struct IdentityBasedSubjectClaims {
    /// Network to which the identity credentials are issued
    pub network: Network,
    /// Identity provider which issued the credentials
    pub issuer: u32,
    /// Attribute statements
    pub statements: Vec<AtomicStatementV1>,
}

impl TryFrom<IdentityBasedSubjectClaims> for v1::IdentityBasedSubjectClaims<ArCurve, W3IdAttr> {
    type Error = serde_json::Error;

    fn try_from(value: IdentityBasedSubjectClaims) -> Result<Self, Self::Error> {
        Ok(Self {
            network: value.network.into(),
            issuer: types::IpIdentity(value.issuer),
            statements: value
                .statements
                .into_iter()
                .map(serde_convert)
                .collect::<Result<_, _>>()?,
        })
    }
}

/// UniFFI compatible bridge to [concordium_base::web3id::v1::AccountBasedSubjectClaims<ArCurve, Web3IdAttribute>].
pub struct AccountBasedSubjectClaims {
    /// Network on which the account exists
    pub network: Network,
    /// Identity provider which issued the credentials
    pub issuer: u32,
    /// Account registration id
    pub cred_id: Bytes,
    /// Attribute statements
    pub statements: Vec<AtomicStatementV1>,
}

impl TryFrom<AccountBasedSubjectClaims> for v1::AccountBasedSubjectClaims<ArCurve, W3IdAttr> {
    type Error = serde_json::Error;

    fn try_from(value: AccountBasedSubjectClaims) -> Result<Self, Self::Error> {
        Ok(Self {
            network: value.network.into(),
            issuer: types::IpIdentity(value.issuer),
            cred_id: serde_convert(value.cred_id)?,
            statements: value
                .statements
                .into_iter()
                .map(serde_convert)
                .collect::<Result<_, _>>()?,
        })
    }
}

/// UniFFI compatible bridge to [concordium_base::web3id::v1::SubjectClaims<ArCurve, Web3IdAttribute>].
pub enum SubjectClaims {
    Account {
        account: AccountBasedSubjectClaims,
    },
    Identity {
        identity: IdentityBasedSubjectClaims,
    },
}

impl TryFrom<SubjectClaims> for v1::SubjectClaims<ArCurve, W3IdAttr> {
    type Error = uniffi::deps::anyhow::Error;

    fn try_from(value: SubjectClaims) -> Result<Self, Self::Error> {
        Ok(match value {
            SubjectClaims::Account { account } => Self::Account(account.try_into()?),
            SubjectClaims::Identity { identity } => Self::Identity(identity.try_into()?),
        })
    }
}

/// UniFFI compatible bridge to [concordium_base::web3id::v1::RequestV1<C: Curve, AttributeType>].
pub struct RequestV1 {
    /// Context challenge for the proof
    pub context: ContextInformation,
    /// Claims to prove
    pub subject_claims: Vec<SubjectClaims>,
}

impl TryFrom<RequestV1> for v1::RequestV1<ArCurve, W3IdAttr> {
    type Error = uniffi::deps::anyhow::Error;

    fn try_from(value: RequestV1) -> Result<Self, Self::Error> {
        Ok(Self {
            context: value.context.into(),
            subject_claims: value
                .subject_claims
                .into_iter()
                .map(|val| val.try_into())
                .collect::<Result<_, _>>()?,
        })
    }
}

/// UniFFI compatible bridge to [concordium_base::id::types::CredentialHolderInfo<ArCurve>]
#[derive(serde::Serialize)]
pub struct CredentialHolderInfo {
    #[serde(rename = "idCredSecret")]
    pub id_cred: Bytes,
}

/// UniFFI compatible bridge to [concordium_base::id::types::AccCredentialInfo<ArCurve>]
#[derive(serde::Serialize)]
pub struct AccCredentialInfo {
    #[serde(rename = "credentialHolderInformation")]
    pub cred_holder_info: CredentialHolderInfo,
    #[serde(rename = "prfKey")]
    pub prf_key: Bytes,
}

/// UniFFI compatible bridge to [concordium_base::id::types::IdObjectUseData<IpPairing, ArCurve>]
#[derive(serde::Serialize)]
pub struct IdObjectUseData {
    #[serde(rename = "aci")]
    pub aci: AccCredentialInfo,
    #[serde(rename = "randomness")]
    pub randomness: Bytes,
}

impl TryFrom<IdObjectUseData> for types::IdObjectUseData<IpPairing, ArCurve> {
    type Error = serde_json::Error;

    fn try_from(value: IdObjectUseData) -> Result<Self, Self::Error> {
        serde_convert(value)
    }
}

/// UniFFI compatible bridge to [concordium_base::id::types::ArInfos<ArCurve>]
#[derive(serde::Serialize)]
pub struct ArInfos {
    pub anonymity_revokers: HashMap<u32, AnonymityRevokerInfo>,
}

impl TryFrom<ArInfos> for types::ArInfos<ArCurve> {
    type Error = serde_json::Error;

    fn try_from(value: ArInfos) -> Result<Self, Self::Error> {
        // Manually convert the UniFFI-friendly ArInfos into the internal representation
        // to avoid going through a JSON map with string keys (which relies on
        // `ArIdentity::from_str` and can fail with "Could not read u32.").
        //
        // Here we:
        // - convert each u32 key into `ArIdentity` via TryFrom<u32>
        // - convert each `AnonymityRevokerInfo` into the internal `ArInfo<ArCurve>`
        //   using `serde_convert`, which operates on the value only.
        use std::collections::BTreeMap;

        let mut map: BTreeMap<types::ArIdentity, types::ArInfo<ArCurve>> = BTreeMap::new();

        for (id, info) in value.anonymity_revokers {
            // Convert the numeric identity into ArIdentity (non-zero u32).
            let ar_id = types::ArIdentity::try_from(id)
                .map_err(|e| serde_json::Error::custom(e))?;

            // Convert the public AR info structure.
            let ar_info: types::ArInfo<ArCurve> = serde_convert(info)?;

            map.insert(ar_id, ar_info);
        }

        Ok(types::ArInfos {
            anonymity_revokers: map,
        })
    }
}

impl TryFrom<IdentityObject>
    for concordium_base::id::types::IdentityObjectV1<IpPairing, ArCurve, W3IdAttr>
{
    type Error = serde_json::Error;

    fn try_from(value: IdentityObject) -> Result<Self, Self::Error> {
        serde_convert(value)
    }
}

/// UniFFI compatible bridge to [concordium_base::web3id::v1::OwnedIdentityCredentialProofPrivateInputs<IpPairing, ArCurve, Web3IdAttribute>].
pub struct OwnedIdentityCredentialProofPrivateInputs {
    /// Identity provider information
    pub ip_info: IdentityProviderInfo,
    /// Public information on the __supported__ anonymity revokers.
    /// Must include at least the anonymity revokers supported by the identity provider.
    /// This is used to create and validate credential.
    pub ars_infos: ArInfos,
    /// Identity object. Together with `id_object_use_data`, it constitutes the identity credentials.
    pub id_object: IdentityObject,
    /// Parts of the identity credentials created locally and not by the identity provider
    pub id_object_use_data: IdObjectUseData,
}

impl TryFrom<OwnedIdentityCredentialProofPrivateInputs>
    for v1::OwnedIdentityCredentialProofPrivateInputs<IpPairing, ArCurve, W3IdAttr>
{
    type Error = uniffi::deps::anyhow::Error;

    fn try_from(value: OwnedIdentityCredentialProofPrivateInputs) -> Result<Self, Self::Error> {
        Ok(Self {
            ip_info: value.ip_info.try_into()?,
            ars_infos: value.ars_infos.try_into()?,
            id_object: value.id_object.try_into()?,
            id_object_use_data: value.id_object_use_data.try_into()?,
        })
    }
}

/// UniFFI compatible bridge to [concordium_base::web3id::v1::OwnedAccountCredentialProofPrivateInputs<IpPairing, ArCurve, Web3IdAttribute>].
#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OwnedAccountCredentialProofPrivateInputs {
    /// Issuer of the identity credentials used to deploy the account credentials
    pub issuer: u32,
    #[serde(rename = "values")]
    /// The attribute values that are committed to in the account credentials
    pub attribute_values: HashMap<AttributeTag, Web3IdAttribute>,
    /// The randomness of the attribute commitments in the account credentials
    #[serde(rename = "randomness")]
    pub attribute_randomness: HashMap<AttributeTag, Bytes>,
}

impl TryFrom<OwnedAccountCredentialProofPrivateInputs>
    for v1::OwnedAccountCredentialProofPrivateInputs<ArCurve, W3IdAttr>
{
    type Error = serde_json::Error;

    fn try_from(value: OwnedAccountCredentialProofPrivateInputs) -> Result<Self, Self::Error> {
        serde_convert(value)
    }
}

/// UniFFI compatible bridge to [concordium_base::web3id::v1::OwnedCredentialProofPrivateInputs<IpPairing, ArCurve, Web3IdAttribute>].
#[allow(clippy::large_enum_variant)]
pub enum OwnedCredentialProofPrivateInputs {
    /// Private inputs for account based credential
    Account {
        account: OwnedAccountCredentialProofPrivateInputs,
    },
    /// Private inputs for identity based credential
    Identity {
        identity: OwnedIdentityCredentialProofPrivateInputs,
    },
}

impl TryFrom<OwnedCredentialProofPrivateInputs>
    for v1::OwnedCredentialProofPrivateInputs<IpPairing, ArCurve, W3IdAttr>
{
    type Error = uniffi::deps::anyhow::Error;

    fn try_from(value: OwnedCredentialProofPrivateInputs) -> Result<Self, Self::Error> {
        Ok(match value {
            OwnedCredentialProofPrivateInputs::Account { account } => {
                Self::Account(account.try_into()?)
            }
            OwnedCredentialProofPrivateInputs::Identity { identity } => {
                Self::Identity(Box::new(identity.try_into()?))
            }
        })
    }
}

/// UniFFI compatible bridge to [concordium_base::web3id::v1::anchor::ContextLabel].
pub enum ContextLabel {
    /// A nonce which should be at least of lenth bytes32.
    Nonce,
    /// Payment hash (Concordium transaction hash).
    PaymentHash,
    /// Concordium block hash.
    BlockHash,
    /// Identifier for some connection (e.g. wallet-connect topic).
    ConnectionId,
    /// Identifier for some resource (e.g. Website URL or fingerprint of TLS certificate).
    ResourceId,
    /// String value for general purposes.
    ContextString,
}

impl From<ContextLabel> for v1::anchor::ContextLabel {
    fn from(value: ContextLabel) -> Self {
        match value {
            ContextLabel::Nonce => Self::Nonce,
            ContextLabel::PaymentHash => Self::PaymentHash,
            ContextLabel::BlockHash => Self::BlockHash,
            ContextLabel::ConnectionId => Self::ConnectionId,
            ContextLabel::ResourceId => Self::ResourceId,
            ContextLabel::ContextString => Self::ContextString,
        }
    }
}

/// UniFFI compatible bridge to [concordium_base::web3id::v1::anchor::LabeledContextProperty].
#[derive(serde::Serialize)]
pub enum LabeledContextProperty {
    /// Cryptographic nonce context which should be of length 32 bytes. Should be randomly
    /// generated.
    Nonce { nonce: Bytes },
    /// Payment hash context (Concordium transaction hash).
    PaymentHash { payment_hash: Bytes },
    /// Concordium block hash context.
    BlockHash { block_hash: Bytes },
    /// Identifier for some connection (e.g. wallet-connect topic).
    ConnectionId { connection_id: String },
    /// Identifier for some resource (e.g. Website URL or fingerprint of TLS certificate).
    ResourceId { resouce_id: String },
    /// String value for general purposes.
    ContextString { context_string: String },
}

impl TryFrom<LabeledContextProperty> for v1::anchor::LabeledContextProperty {
    type Error = serde_json::Error;

    fn try_from(value: LabeledContextProperty) -> Result<Self, Self::Error> {
        // Convert UniFFI bridge enum to base library format
        // The base library expects {"label": "...", "context": "..."} format
        let (label, context_str) = match value {
            LabeledContextProperty::Nonce { nonce } => {
                // Bytes implements Display which formats as hex
                (v1::anchor::ContextLabel::Nonce, format!("{}", nonce))
            }
            LabeledContextProperty::PaymentHash { payment_hash } => {
                (v1::anchor::ContextLabel::PaymentHash, format!("{}", payment_hash))
            }
            LabeledContextProperty::BlockHash { block_hash } => {
                (v1::anchor::ContextLabel::BlockHash, format!("{}", block_hash))
            }
            LabeledContextProperty::ConnectionId { connection_id } => {
                (v1::anchor::ContextLabel::ConnectionId, connection_id)
            }
            LabeledContextProperty::ResourceId { resouce_id } => {
                (v1::anchor::ContextLabel::ResourceId, resouce_id)
            }
            LabeledContextProperty::ContextString { context_string } => {
                (v1::anchor::ContextLabel::ContextString, context_string)
            }
        };
        
        // Use the base library's method to create from label and value string
        v1::anchor::LabeledContextProperty::try_from_label_and_value_str(label, &context_str)
            .map_err(|e| serde_json::Error::from(DeError::custom(format!("Failed to parse context property: {}", e))))
    }
}

/// UniFFI compatible bridge to [concordium_base::web3id::v1::anchor::UnfilledContextInformation].
pub struct UnfilledContextInformation {
    /// Context information that is already provided.
    pub given: Vec<LabeledContextProperty>,
    /// Context information that must be provided by the credential holder.
    pub requested: Vec<ContextLabel>,
}

impl TryFrom<UnfilledContextInformation> for v1::anchor::UnfilledContextInformation {
    type Error = serde_json::Error;

    fn try_from(value: UnfilledContextInformation) -> Result<Self, Self::Error> {
        Ok(Self {
            given: value
                .given
                .into_iter()
                .map(|val| val.try_into())
                .collect::<Result<_, _>>()?,
            requested: value.requested.into_iter().map(|val| val.into()).collect(),
        })
    }
}

/// UniFFI compatible bridge to [concordium_base::web3id::v1::anchor::RequestedStatement].
pub enum RequestedStatement {
    /// The atomic statement stating that an attribute should be revealed.
    RevealAttribute {
        statement: RevealAttributeIdentityStatement,
    },
    /// The atomic statement stating that an attribute is in a range.
    AttributeInRange {
        statement: AttributeInRangeIdentityStatementV1,
    },
    /// The atomic statement stating that an attribute is in a set.
    AttributeInSet {
        statement: AttributeInSetIdentityStatementV1,
    },
    /// The atomic statement stating that an attribute is not in a set.
    AttributeNotInSet {
        statement: AttributeNotInSetIdentityStatementV1,
    },
}

impl TryFrom<RequestedStatement> for v1::anchor::RequestedStatement<types::AttributeTag> {
    type Error = serde_json::Error;

    fn try_from(value: RequestedStatement) -> Result<Self, Self::Error> {
        Ok(match value {
            RequestedStatement::RevealAttribute { statement } => {
                Self::RevealAttribute(serde_convert(statement)?)
            }
            RequestedStatement::AttributeInRange { statement } => {
                Self::AttributeInRange(serde_convert(statement)?)
            }
            RequestedStatement::AttributeInSet { statement } => {
                Self::AttributeInSet(serde_convert(statement)?)
            }
            RequestedStatement::AttributeNotInSet { statement } => {
                Self::AttributeNotInSet(serde_convert(statement)?)
            }
        })
    }
}

/// UniFFI compatible bridge to [concordium_base::web3id::v1::anchor::IdentityProviderDid].
pub struct IdentityProviderDid {
    /// The network part of the method.
    pub network: Network,
    /// The on-chain identifier of the Concordium Identity Provider.
    pub identity_provider: u32,
}

impl From<IdentityProviderDid> for v1::anchor::IdentityProviderDid {
    fn from(value: IdentityProviderDid) -> Self {
        Self {
            network: value.network.into(),
            identity_provider: types::IpIdentity(value.identity_provider),
        }
    }
}

/// UniFFI compatible bridge to [concordium_base::web3id::v1::anchor::IdentityCredentialType].
pub enum IdentityCredentialType {
    IdentityCredential,
    AccountCredential,
}

impl From<IdentityCredentialType> for v1::anchor::IdentityCredentialType {
    fn from(value: IdentityCredentialType) -> Self {
        match value {
            IdentityCredentialType::IdentityCredential => Self::IdentityCredential,
            IdentityCredentialType::AccountCredential => Self::AccountCredential,
        }
    }
}

/// UniFFI compatible bridge to [concordium_base::web3id::v1::anchor::RequestedIdentitySubjectClaims].
pub struct RequestedIdentitySubjectClaims {
    pub statements: Vec<RequestedStatement>,
    pub issuers: Vec<IdentityProviderDid>,
    pub source: Vec<IdentityCredentialType>,
}

impl TryFrom<RequestedIdentitySubjectClaims> for v1::anchor::RequestedIdentitySubjectClaims {
    type Error = serde_json::Error;

    fn try_from(value: RequestedIdentitySubjectClaims) -> Result<Self, Self::Error> {
        Ok(Self {
            statements: value
                .statements
                .into_iter()
                .map(|val| val.try_into())
                .collect::<Result<_, _>>()?,
            issuers: value.issuers.into_iter().map(|val| val.into()).collect(),
            source: value.source.into_iter().map(|val| val.into()).collect(),
        })
    }
}

/// UniFFI compatible bridge to [concordium_base::web3id::v1::anchor::RequestedSubjectClaims].
pub enum RequestedSubjectClaims {
    Identity {
        identity: RequestedIdentitySubjectClaims,
    },
}

impl TryFrom<RequestedSubjectClaims> for v1::anchor::RequestedSubjectClaims {
    type Error = serde_json::Error;
    fn try_from(value: RequestedSubjectClaims) -> Result<Self, Self::Error> {
        match value {
            RequestedSubjectClaims::Identity { identity } => Ok(
                v1::anchor::RequestedSubjectClaims::Identity(identity.try_into()?),
            ),
        }
    }
}

/// UniFFI compatible bridge to [concordium_base::web3id::v1::anchor::VerificationRequestData].
pub struct VerificationRequestData {
    /// Context information for a verifiable presentation request.
    pub context: UnfilledContextInformation,
    /// The claims for a list of subjects containing requested statements about the subjects.
    pub subject_claims: Vec<RequestedSubjectClaims>,
}

impl TryFrom<VerificationRequestData> for v1::anchor::VerificationRequestData {
    type Error = serde_json::Error;
    fn try_from(value: VerificationRequestData) -> Result<Self, Self::Error> {
        Ok(Self {
            context: value.context.try_into()?,
            subject_claims: value
                .subject_claims
                .into_iter()
                .map(|val| val.try_into())
                .collect::<Result<_, _>>()?,
        })
    }
}

/// Implements UDL definition of the same name.
pub fn create_verifiable_presentation_v1(
    request: RequestV1,
    global: GlobalContext,
    inputs: Vec<OwnedCredentialProofPrivateInputs>,
) -> Result<PresentationV1, ConcordiumWalletCryptoError> {
    let fn_desc = "create_verifiable_presentation_v1";

    // Convert high-level RequestV1 into the internal web3Id v1 type.
    // If this fails we want a precise error message to see which stage broke.
    let request: v1::RequestV1<ArCurve, W3IdAttr> = request.try_into().map_err(
        |e: uniffi::deps::anyhow::Error| {
            e.to_call_failed(format!("{fn_desc}: request conversion failed: {e}"))
        },
    )?;

    // Convert the UniFFI-friendly private inputs into the internal representation.
    let inputs = inputs
        .into_iter()
        .map(v1::OwnedCredentialProofPrivateInputs::try_from)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e: uniffi::deps::anyhow::Error| {
            e.to_call_failed(format!("{fn_desc}: inputs conversion failed: {e}"))
        })?;
    let borrowed = inputs.iter().map(|val| val.borrow());

    // Convert global context as well.
    let global = global.try_into().map_err(|e: serde_json::Error| {
        e.to_call_failed(format!("{fn_desc}: global context conversion failed: {e}"))
    })?;

    // Run the actual prover.
    let presentation = request.prove(&global, borrowed).map_err(|e| {
        e.to_call_failed(format!("{fn_desc}: prove failed: {e}"))
    })?;

    // Convert internal presentation back into the UniFFI bridge type.
    PresentationV1::try_from(presentation).map_err(|e| {
        e.to_call_failed(format!(
            "{fn_desc}: presentation conversion failed: {e}"
        ))
    })
}

/// Implements UDL definition of the same name.
pub fn compute_anchor_hash(
    verification_request_data: VerificationRequestData,
) -> Result<Bytes, ConcordiumWalletCryptoError> {
    let fn_desc = "compute_anchor_hash(data={VerificationRequestData})";

    let hash = v1::anchor::VerificationRequestData::try_from(verification_request_data)
        .map_err(|e| e.to_call_failed(fn_desc.to_string()))?
        .hash();
    Ok(hash.into())
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;
    use chrono::{DateTime, Utc};

    type DateTimeUtc = DateTime<Utc>;
    const PRESENTATION_V1_JSON: &str = r#"{
                "type": [
                    "VerifiablePresentation",
                    "ConcordiumVerifiablePresentationV1"
                ],
                "presentationContext": {
                    "type": "ConcordiumContextInformationV1",
                    "given": [
                    {
                        "label": "prop1",
                        "context": "val1"
                    }
                    ],
                    "requested": [
                    {
                        "label": "prop2",
                        "context": "val2"
                    }
                    ]
                },
                "verifiableCredential": [
                    {
                    "type": [
                        "VerifiableCredential",
                        "ConcordiumVerifiableCredentialV1",
                        "ConcordiumIdBasedCredential"
                    ],
                    "credentialSubject": {
                        "id": "did:ccd:testnet:encidcred:04000500000001a45064854acb7969f49e221ca4e57aaf5d3a7af2a012e667d9f123a96e7fab6f3c0458e59149062a37615fbaff4d412f959d6060a0b98ae6c2d1f08ab3e173f02ceb959c69c30eb55017c74af4179470adb3b3b7b5e382bc8fd3dc173d7bc6b400000002acb968eac3f7f940d80e2cc4dee7ef9256cb1d19fd61a8c2b6d8bf61cdbfb105975b4132cd73f9679567ad8501e698c280e2dc5cac96c5e428adcc4cd9de19b7704df058a5c938c894bf03a94298fc5f741930c575f8f0dd1af64052dcaf4f00000000038b3287ab16051907adab6558c887faae7d41384462d58b569b45ff4549c23325e763ebf98bb7b68090c9c23d11ae057787793917a120aaf73f3caeec5adfc74d43f7ab4d920d89940a8e1cf5e73df89ff49cf95ac38dbc127587259fcdd8baec00000004b5754b446925b3861025a250ab232c5a53da735d5cfb13250db74b37b28ef522242228ab0a3735825be48a37e18bbf7c962776f4a4698f6e30c4ed4d4aca5583296fd05ca86234abe88d347b506073c32d8b87b88f03e9e888aa8a6d76050b2200000005b0e9cd5f084c79d1d7beb52f58182962aebe2fad91740537faa2d409d31dec9af504b7ac8dc15eae6738698d2dc10410930a5f6bc26b8b3b65c82748119af60f17f1e114c62afa62f7783b20a455cd4747d6cda058f381e40185bb9e6618f4e4",
                        "statement": [
                        {
                            "type": "AttributeInRange",
                            "attributeTag": "dob",
                            "lower": 80,
                            "upper": 1237
                        },
                        {
                            "type": "AttributeInSet",
                            "attributeTag": "sex",
                            "set": [
                            "aa",
                            "ff",
                            "zz"
                            ]
                        },
                        {
                            "type": "AttributeNotInSet",
                            "attributeTag": "lastName",
                            "set": [
                            "aa",
                            "ff",
                            "zz"
                            ]
                        },
                        {
                            "type": "AttributeInRange",
                            "attributeTag": "countryOfResidence",
                            "lower": {
                            "type": "date-time",
                            "timestamp": "2023-08-27T23:12:15Z"
                            },
                            "upper": {
                            "type": "date-time",
                            "timestamp": "2023-08-29T23:12:15Z"
                            }
                        },
                        {
                            "type": "AttributeValue",
                            "attributeTag": "nationality",
                            "attributeValue": "testvalue"
                        }
                        ]
                    },
                    "validFrom": "2020-05-01T00:00:00Z",
                    "validUntil": "2022-05-31T23:59:59Z",
                    "issuer": "did:ccd:testnet:idp:0",
                    "proof": {
                        "created": "2023-08-28T23:12:15Z",
                        "proofValue": "0000000000000006010098ad4f48bcd0cf5440853e520858603f16058ee0fc1afdc3efe98abe98771e23c000d19119c28d704a5916929f66f2a30200abb05a0ff79b3b06f912f0ec642268d3a1ad1cdf4f050ab7d55c795aa1ab771f4be29f29134e0d7709566f9b2468805f03009158599821c271588f24e92db7ca30197ec5b0c901efaadd34cca707e56b9aab1a7f14e329816e2acf4d07a7edf1bd6b0400af07a1ba7a22bcb1602114921a48fa966a821354cd0dd63a87ce018caccc50b56f2c9f55a062cdc423657aa5cec8a4c9050100097465737476616c75650602aef4be258f8baca0ee44affd36bc9ca6299cc811ac6cb77d10792ff546153d6a84c0c0e030b131ed29111911794174859966f6ba8cafaf228cb921351c2cbc84358c0fa946ca862f8e30d920e46397bf96b56f50b66ae9c93953dc24de2904640000000000000004a547c8619f3ff2670efbefb21281e459b7cc9766c4f377f78e9f97e2c50569a8dcb155f2a502e936d2cb6ef1a73e92af9916e6353b7127d55bb525cb18074b5ec130463e03a4eda583b05c2d63db40a08ab8bf05f930ec234cc2f788d5f5bfbeab3e4881918ce964ffd55483219edd435ac865286bfd313cd834aabfa8061d2ae173cbe4b59ab2bda78faa4c2c937afba80d7fba0822579ac0ef6915f4820f968a74f00ff5ab74e90b0a7bcb2b92093a5e94a54aea1d48ffd1e5bb3fb48069bc022d40f10bd9f0db027ee76e5d78722b22605a1f420c0d8923f384fd2e9df4d500000005000000014996e6a8d95d738baf684228c059ffda43b6a801240c467ff648b24c1e32a8fa25e6348ea46cfe7a6134f6754367715ab1fa97f963720164fd4af47882ea5f5c68917936ca63783c8e7252b3add6d60427580f639caec877eaf62af847e260b0000000022edfd6a9b5f6cb325c2ddafc2f37328768062360b94ff89b795eefc2bdd8b8c7566f982f3189e2158c9932e6c2236beae9c4a1767de64235066fc668c43590a466a5e08b9552ff74c7850795edfb41de40a8183b3ae27e25e14a851192492649000000035477e4693d1f65ba2c6d911de408be4b4164ae853b9d944859a7125c7f80c8b6737b58adf891170ac056de0907671899121fede2fd7cbcd6c266fef9d011baf65e6529fb326268ad4394ac4bdcd594901d2d649c9633ed273d47472550a6ed1d00000004636f324e0c8d9958f960f621ba0bdb0a12c2fdac465fab6f3d6b0219edf20bda34bcc475e9e940e5f2c166aab81bb46a24fe84a7c150f60f19b25a9aa26b02960fb8204657da982ecc80099255157f127037fc1d01bae5e751dfd1b568d5d3b2000000055252326e4bd286ff449e1e4191ad5bfd3834498357850252b2efdf71e5a195801b0b139f690a241db78ffae798e90adf5468ed485dd47c396dafdbf95846ab3f1dfc26f4044279839a74ef3d99d3e683ddfd948707a841052beed7fa59d3cfe10a85e4f590f94aeec5694aa34ce7809e6409635c3dcc06c48e2b6eb7c88e805b0000000c0044de5e492f26cdc8d9dd7353c8f4561776db5cf1e9e56765f8a27325bea23c7c6e93ee0e96b86044e30a334d6a3574f1eb257fbc13e38045de829d08e668e1760233b357f18e2fb13b681affb3100a76389289b0a672fb4c018b496086e907a8d9010101024a3c3d379c549361b01f1da35dc354171e8b08e37cde8b26708a7d0a74a1c475001607576a587bc3724829d37a211c4e7ac685f5d2ff8d183878c47761fa207a2772c92a29d9723c60fcf02a5f3ee44f16c8d719ef0ff7306017e8abcca0ac43da002c1306c3df6c321d1827b482e5bdd43d9ae0ebda13ee87f8ffce45b9280974d30da67ed93028333a98441ec283b84ef993ba16ee3f63abeb6913cb84c6087e520031d913edbe710a6ef608a7496ddb24b62af6dc53b0c400515094a102dc34ba7e5101b14654477c70600fc619c536a55689a34483d87a607c616b8e4a7f588b1c0020de9f2cbea7cb077e1dc06c4f2f3286792ff9ab865d04a264699b063387d3565a810470a1a3f0b94ed0a313bf2558035cb562112fe9d4ce3db05035da60dfb401023ecf78fe04bea07742a2b68c1dfc848ced58d50cc72e3aa9417456c137f07042000000000000000502803596b4ba5ea05b1fea2b78e292f935d621453cffcd207e10f3072b2813ca3e963cebf05b19cd82da4bd5aad1dcc7fda1492d7ffc8f532bc4b37e9bf4753b7ae6b8f08e05a851052fc6ac7617ce68293678747d11f9a508bab6f7a60edde9c4975a76ced40574074001091721440b1d62252454c2b26494f5014ef4b5f0adaab23eea032dabcf7fc274915ed26a38ea985468e8f27f81f378870fdf0c9fa880b75d301d54dead22ebe69d98305b8bcb1825f77084a3fe794ef69ae07ca2f40c327c3b8055a8dc2823524df825d4748e84c743856120bf5bc77826884412154e26cf2b601c2b869084806c5e670919b8cb8d6ea8f7a8fd14096f7dc9765bcd0d5a04e5770764de9318b0f4f5fd1343b30f0954656423cbb994da605956acc5e30000000792698ceb941b32e6ff12451a75d1eb465ca0710879a4d67ecf75ff5e614605b7284f07109a658007dd94b499322649a68af4e7b7ad848fbc3e2dfe248fe846d0836279a0a8045909516fa2de9ce9d456e68278372af302a891a3c138596bb369abb626f0e5ccd6ceb9d6f7f0bd979a37afdeff02c294ad7db9ad1335f0d532027bf7fc78c7fe3d1025bbd9b754e8ce068ef1e251727d48cb25040091f05b327ac2ec733c1cb349f6aa20c00f644a3f9c84df72112b4f4b247126df77eb27933db078a098bc904d01ce5de1be0fdb9d8796b3d427c7a89d7ace44209339c5577416dff5094858771314c6dcb8562f7d17a30c84630530510bff914ff0398b4616171386c23145d4cff3e4a0f698715bd68dbe2233b851ee49c17c0b7dc9b6f5f4ae461de98c4d582c8be6f490e75a0c2b1a61dfca366e86ca6ed131b93d43c93292f6182cf3d86e98d0baf613630e7a34a54dcba10f680b641579909c138223182443f71f110d7eb97d0bc99c795d95f28611ddf484208c3aa9763b517024d32faaea07a4343e4fa9b72ffb951fddd5e811def887a8d92e89c574d7820ed46df10da13e63ec1223d2bf1ee4b8f6cd353eae032fd8b3f6f886d5feb3032ac2c6cef1f03513e04646ffdbd0be6597f674bfcbce9f16127b43aa49f4e6853c56e2cd96c75aab089f07d04515e52a097c1b08c75ddb30315af1d65aebd00585c3818e7587baa5b11b80a0fd5fd2e0b7b473c9ad112a3168aadaf83ba4d94ad7e6b47c639684d634fe5ae59fc1f9e6741e924bdc8ed49c2a72bf1e7869fff80d17a7a0adacbf2123fbed51683d0897fd76310f3896381f47c675764b6475a027f92a0b89d863218dce9b3ac48524b3d1def4f0877aeab34415a27e33d305e9ae39dc8c918125498ab16932378e9f739bd2e0c4866265ff9f98c7b562000c762254336c3ac576cdfd96936c3f32ded9523594401d0ad2f2232a01b9c8443395180f1ec80a119e63e0bf631cb93a9db4ee6a2a29e06f520835f7af238e1c8cd873bef1e4039035240c33b7dec4981aa53e914f67ac932328b31f3fc4d0aac1c19a4da4dab1b525a63008d0e40b86076a1b7e9f0f219955c76798ae8d5131eee35e9900c5cdc8b58badd7022044521d7ad239a91bb2ae1a02fc61472f7d3629d14070641a1e86c2ef60ae3a42de23a15550c75b135a7be766fc38a2554377afc4892fef23e54ad59b72bfa590493d3a0e6d0c3692f9b12c28a4c2fcbfc8331381867935bdbdbe83220fe2330b5024ffdaeb37eb9a4f8dc8505ff846ce16a24ad0f36b8145591838c8cd056b4fa56d76e3f0d3c04cd58a13fc953ac12f292817ad4c1b46d62e372b5a5f8c7f3a4dcb29beb03b75d7b9d0a4a463e37f00da224c7fde6d34c3d53f34ac41a47b698e9b381d0debc448c465c594d9cf9c42e8cbce7e0e03091000000000028f08b690d86821cdcd517648214e22b5b0b73e2c7f82a3ccae933d61bc0e28fc69b047aba5cc6b8e9e6f4578e02924db920fdd2cbc3f1171c98169f4fd5676b77f210f9ae5e949afab54b2e52137538906ea05c5fc5e0ca989eb081a3ba9285ea611a9d69bbefb08d3142a7523a3ca91961b4f6deaa87286a4fe776607572b5db7e6ea488c5b9007731663b4537b584983937bfa8ec12bc8f6b1ec8185cb2863f7dc15f82f50978301f7441901d2921799af71fbf5f3a83162ddaed844b5647970b4bf4cb7d8bae88457f65c2e5f09b71b6585303e4783642c20949423fba406002407e6a58cd57836650e76df878926d0b6315f4c4329385566667701fe7f820487cbd29bfc97194ed8868ed4e458c7b2bf8ab6f04efee532502cf588c4f26b9b2830baa635c56857be5fd6803fd35d508881bd7cf3b5872ff84640384e2576bd93d4d86fdafcba2df3f29036491573031ede2ddb09dd092ad890a68f07876aeeb5ed24f1e21e96aa8f81d1b57f7963fdb0d617a6c302365781dcbe1628103ba3e9fb7c05ec5064aa5f518a2dd54deb3bb6547660749326b8e7c23931f938d1f94b2b199330c7cf4e21caaf3586b5ce3f56d5a1a06a78729f9e8b7838eef1f95828f2e1f46ccd7642fae51f13d2b0d6c55b328e0d6bae6355d412db989f82a3fa47b167da18c385588da0d8b2715d09c06cb2e03a1bccf8e112893d054c79b8d850d3c90fc8866865a2f85a8b3f64d9dfad1381b1bc0653335ac741925dccaac600000002895dca7ed412bae0cb70d758773dcfbb2254c95be80f230ceb3a73883bd6b6220cff45b7e9d058da58071acb8a32767b99a869379b6095f4e2b7ddecbd8a4d17a094f9681a4345c35c87dd86cba4074e56dae9e1ddadb7edfa248058f12f8f0c965d922130d696027a12fdfd06b1c39c7fba1875b39f751be361ccf330dfcdfa68623eb78747bc06f9ac45b812d5d313abfbfabdb4411220d1e78b5384749bb890b3f220139e0200315d516b3fb2e156b2a5c1c2a081a3e67eb6e8fc97be9bb4439a9eaadaab8e29db023baa98322d0d0e7f06efd708b5c7f8846e799e8607a20242d81c399a6571f8ea9c203a534ebfc6bf416540b8ad6a2c82e66dd9d2c0c502b387e119ec10c4a8963ee52710d75c21710881bae7fb5a8595fd43a9156419f8080891e50139bd4af14f1ba25ebe0152b5e83d115be493372e147742d8bfe3a8269e8ecd27ec055a11055d5405192cda8c8db528f06b120fc2e3f47089897411aaae9e0b0179b2e09afee8e5d56ea05b85694d71186f6d6dba1465c19cfc41f55751c1c7e3e071f0a97733f2ad4a8d7eb5038bb97411c01f77d451d483611c939f1910f388110198c69a2efdce02ad2334a1c39958bd66abb940ef1f42143a65010e383128f291e962c579ec7cb9f24f373554e84ce1a21f459d5ea4ab1a41ec733322f9b95611de75450bf415e60dc15f8d33fdb61f14d9c73c92cd6ace0943403768e8947e8122b2cbbc663a5373940daf22b914730c980c66e87e444db56f000000078c1751517b7f76514a5ea7af097099c03cc64d9416494d5a9f448c2615903650ab7c8c2358619073d84f04034ba7f768b62b4825d8a12f4c0378b2b271eb05f8b3cff514ebdae3b6de637539305437c2bc0bc6c2649961a1d22295035d07f460863a3d0467f01e79c4199bf3dd73a57a58315be6b4e465e43fe66e82dc933ee622598672fbd0c5bae12d8e187c7a6dc8a2c4b3dc57040a759e23594760d76c8d6655c0860e4a1187e89d7451b1507bc5e0ff3eeb28577af943a44afb61d96eca898cb8417551edffc189fe2d24e83f554206c397b80153044e45be32aef5b46deff4625d1d316338bf3521ee32ef50388a067b5c0972ca68797b98b337c09589c307d5adfac00a524ccca6d8d5450a0eea765673fbea3956aa0edf0dc0a2c7318dd61540865a408715c148e406489f7e56d953af3df90585b2dd12e99a4a6878009001b62f9fa0a023041fd77f41be2da2ed746a07bb3fa3864ab5e76be4f98d480fd97280735eb9f44c6bb0b1b02e2ee8c9d1c71c68de3325e6d14f44ef98b68b50ddef96b312c9a17296ecf837591659252f25670d9744c7334abca978eab4d7c40276b876ca682c2c06ba2809082d842c021fadb934bff19025c4dc1d80f6a9fac3cf59a7209c1d73113b87b8d34a8d618a5534db6fbc4492cfb6439a2c088cbbd44febb15f56e1d119bbf1e2bd108325711d56938eeffce12ecc900059822448666fd380701afb94887ff3a73d5ab6e3a9614ec319bb579d02de414db8a02d54f80928255dafc2b7833159aab87daffd5e143e7e939ec2c05496573f7de1aa46492cc29053e0ab0d7a2b524b3cade5e2ee0fbb0aa8f0b340cf139321230da9d50df0e36794ff03927ebdfaeb5b4c88612f9a7cb6660d8a088433ec92cd24ad06e4bb75885b0b7103d524f4f6b080be40484b9138278d95feb40af1c52cbb29f7623675d081c0930866586fee0476a9f21bffe406e3265413f792e0d464e9476becd32bb6af4856aaf4dfdbd6f1a2fea4cbe6df332e324f091fa74e7d9cdf01",
                        "type": "ConcordiumZKProofV4"
                    }
                    }
                ],
                "proof": {
                    "created": "2023-08-28T23:12:15Z",
                    "proofValue": "",
                    "type": "ConcordiumWeakLinkingProofV1"
                }
            }"#;

    fn create_base_presntation_v1() -> v1::PresentationV1<IpPairing, ArCurve, W3IdAttr> {
        serde_json::from_str(PRESENTATION_V1_JSON).unwrap()
    }

    fn create_bridge_presentation_v1() -> PresentationV1 {
        PresentationV1 {
            presentation_context: ContextInformation {
                given: vec![ContextProperty {
                    label: "prop1".into(),
                    context: "val1".into(),
                }],
                requested: vec![ContextProperty {
                    label: "prop2".into(),
                    context: "val2".into(),
                }],
            },
            verifiable_credentials: vec![CredentialV1::Identity {
                identity: IdentityBasedCredentialV1 {
                    issuer: 0,
                    valid_from: DateTimeUtc::from_str("2020-05-01T00:00:00Z").unwrap().into(),
                    valid_until: DateTimeUtc::from_str("2022-05-31T23:59:59Z").unwrap().into(),
                    subject: IdentityCredentialSubject {
                        network: Network::Testnet,
                        cred_id: Bytes::try_from("04000500000001a45064854acb7969f49e221ca4e57aaf5d3a7af2a012e667d9f123a96e7fab6f3c0458e59149062a37615fbaff4d412f959d6060a0b98ae6c2d1f08ab3e173f02ceb959c69c30eb55017c74af4179470adb3b3b7b5e382bc8fd3dc173d7bc6b400000002acb968eac3f7f940d80e2cc4dee7ef9256cb1d19fd61a8c2b6d8bf61cdbfb105975b4132cd73f9679567ad8501e698c280e2dc5cac96c5e428adcc4cd9de19b7704df058a5c938c894bf03a94298fc5f741930c575f8f0dd1af64052dcaf4f00000000038b3287ab16051907adab6558c887faae7d41384462d58b569b45ff4549c23325e763ebf98bb7b68090c9c23d11ae057787793917a120aaf73f3caeec5adfc74d43f7ab4d920d89940a8e1cf5e73df89ff49cf95ac38dbc127587259fcdd8baec00000004b5754b446925b3861025a250ab232c5a53da735d5cfb13250db74b37b28ef522242228ab0a3735825be48a37e18bbf7c962776f4a4698f6e30c4ed4d4aca5583296fd05ca86234abe88d347b506073c32d8b87b88f03e9e888aa8a6d76050b2200000005b0e9cd5f084c79d1d7beb52f58182962aebe2fad91740537faa2d409d31dec9af504b7ac8dc15eae6738698d2dc10410930a5f6bc26b8b3b65c82748119af60f17f1e114c62afa62f7783b20a455cd4747d6cda058f381e40185bb9e6618f4e4").unwrap(),
                        statements: vec![
                            serde_json::from_str(r#"{
                                "type": "AttributeInRange",
                                "attributeTag": "dob",
                                "lower": 80,
                                "upper": 1237
                            }"#).unwrap(),
                            serde_json::from_str(r#"{
                                "type": "AttributeInSet",
                                "attributeTag": "sex",
                                "set": [
                                "aa",
                                "ff",
                                "zz"
                                ]
                            }"#).unwrap(),
                            serde_json::from_str(r#"{
                                "type": "AttributeNotInSet",
                                "attributeTag": "lastName",
                                "set": [
                                "aa",
                                "ff",
                                "zz"
                                ]
                            }"#).unwrap(),
                            serde_json::from_str(r#"{
                                "type": "AttributeInRange",
                                "attributeTag": "countryOfResidence",
                                "lower": {
                                "type": "date-time",
                                "timestamp": "2023-08-27T23:12:15Z"
                                },
                                "upper": {
                                "type": "date-time",
                                "timestamp": "2023-08-29T23:12:15Z"
                                }
                            }"#).unwrap(),
                            serde_json::from_str(r#"{
                                "type": "AttributeValue",
                                "attributeTag": "nationality",
                                "attributeValue": "testvalue"
                            }"#).unwrap(),
                        ]
                    },
                    proofs: ConcordiumCredentialZKProofs {
                        created_at: DateTimeUtc::from_str("2023-08-28T23:12:15Z").unwrap().into(),
                        proof_value: Bytes::try_from("0000000000000006010098ad4f48bcd0cf5440853e520858603f16058ee0fc1afdc3efe98abe98771e23c000d19119c28d704a5916929f66f2a30200abb05a0ff79b3b06f912f0ec642268d3a1ad1cdf4f050ab7d55c795aa1ab771f4be29f29134e0d7709566f9b2468805f03009158599821c271588f24e92db7ca30197ec5b0c901efaadd34cca707e56b9aab1a7f14e329816e2acf4d07a7edf1bd6b0400af07a1ba7a22bcb1602114921a48fa966a821354cd0dd63a87ce018caccc50b56f2c9f55a062cdc423657aa5cec8a4c9050100097465737476616c75650602aef4be258f8baca0ee44affd36bc9ca6299cc811ac6cb77d10792ff546153d6a84c0c0e030b131ed29111911794174859966f6ba8cafaf228cb921351c2cbc84358c0fa946ca862f8e30d920e46397bf96b56f50b66ae9c93953dc24de2904640000000000000004a547c8619f3ff2670efbefb21281e459b7cc9766c4f377f78e9f97e2c50569a8dcb155f2a502e936d2cb6ef1a73e92af9916e6353b7127d55bb525cb18074b5ec130463e03a4eda583b05c2d63db40a08ab8bf05f930ec234cc2f788d5f5bfbeab3e4881918ce964ffd55483219edd435ac865286bfd313cd834aabfa8061d2ae173cbe4b59ab2bda78faa4c2c937afba80d7fba0822579ac0ef6915f4820f968a74f00ff5ab74e90b0a7bcb2b92093a5e94a54aea1d48ffd1e5bb3fb48069bc022d40f10bd9f0db027ee76e5d78722b22605a1f420c0d8923f384fd2e9df4d500000005000000014996e6a8d95d738baf684228c059ffda43b6a801240c467ff648b24c1e32a8fa25e6348ea46cfe7a6134f6754367715ab1fa97f963720164fd4af47882ea5f5c68917936ca63783c8e7252b3add6d60427580f639caec877eaf62af847e260b0000000022edfd6a9b5f6cb325c2ddafc2f37328768062360b94ff89b795eefc2bdd8b8c7566f982f3189e2158c9932e6c2236beae9c4a1767de64235066fc668c43590a466a5e08b9552ff74c7850795edfb41de40a8183b3ae27e25e14a851192492649000000035477e4693d1f65ba2c6d911de408be4b4164ae853b9d944859a7125c7f80c8b6737b58adf891170ac056de0907671899121fede2fd7cbcd6c266fef9d011baf65e6529fb326268ad4394ac4bdcd594901d2d649c9633ed273d47472550a6ed1d00000004636f324e0c8d9958f960f621ba0bdb0a12c2fdac465fab6f3d6b0219edf20bda34bcc475e9e940e5f2c166aab81bb46a24fe84a7c150f60f19b25a9aa26b02960fb8204657da982ecc80099255157f127037fc1d01bae5e751dfd1b568d5d3b2000000055252326e4bd286ff449e1e4191ad5bfd3834498357850252b2efdf71e5a195801b0b139f690a241db78ffae798e90adf5468ed485dd47c396dafdbf95846ab3f1dfc26f4044279839a74ef3d99d3e683ddfd948707a841052beed7fa59d3cfe10a85e4f590f94aeec5694aa34ce7809e6409635c3dcc06c48e2b6eb7c88e805b0000000c0044de5e492f26cdc8d9dd7353c8f4561776db5cf1e9e56765f8a27325bea23c7c6e93ee0e96b86044e30a334d6a3574f1eb257fbc13e38045de829d08e668e1760233b357f18e2fb13b681affb3100a76389289b0a672fb4c018b496086e907a8d9010101024a3c3d379c549361b01f1da35dc354171e8b08e37cde8b26708a7d0a74a1c475001607576a587bc3724829d37a211c4e7ac685f5d2ff8d183878c47761fa207a2772c92a29d9723c60fcf02a5f3ee44f16c8d719ef0ff7306017e8abcca0ac43da002c1306c3df6c321d1827b482e5bdd43d9ae0ebda13ee87f8ffce45b9280974d30da67ed93028333a98441ec283b84ef993ba16ee3f63abeb6913cb84c6087e520031d913edbe710a6ef608a7496ddb24b62af6dc53b0c400515094a102dc34ba7e5101b14654477c70600fc619c536a55689a34483d87a607c616b8e4a7f588b1c0020de9f2cbea7cb077e1dc06c4f2f3286792ff9ab865d04a264699b063387d3565a810470a1a3f0b94ed0a313bf2558035cb562112fe9d4ce3db05035da60dfb401023ecf78fe04bea07742a2b68c1dfc848ced58d50cc72e3aa9417456c137f07042000000000000000502803596b4ba5ea05b1fea2b78e292f935d621453cffcd207e10f3072b2813ca3e963cebf05b19cd82da4bd5aad1dcc7fda1492d7ffc8f532bc4b37e9bf4753b7ae6b8f08e05a851052fc6ac7617ce68293678747d11f9a508bab6f7a60edde9c4975a76ced40574074001091721440b1d62252454c2b26494f5014ef4b5f0adaab23eea032dabcf7fc274915ed26a38ea985468e8f27f81f378870fdf0c9fa880b75d301d54dead22ebe69d98305b8bcb1825f77084a3fe794ef69ae07ca2f40c327c3b8055a8dc2823524df825d4748e84c743856120bf5bc77826884412154e26cf2b601c2b869084806c5e670919b8cb8d6ea8f7a8fd14096f7dc9765bcd0d5a04e5770764de9318b0f4f5fd1343b30f0954656423cbb994da605956acc5e30000000792698ceb941b32e6ff12451a75d1eb465ca0710879a4d67ecf75ff5e614605b7284f07109a658007dd94b499322649a68af4e7b7ad848fbc3e2dfe248fe846d0836279a0a8045909516fa2de9ce9d456e68278372af302a891a3c138596bb369abb626f0e5ccd6ceb9d6f7f0bd979a37afdeff02c294ad7db9ad1335f0d532027bf7fc78c7fe3d1025bbd9b754e8ce068ef1e251727d48cb25040091f05b327ac2ec733c1cb349f6aa20c00f644a3f9c84df72112b4f4b247126df77eb27933db078a098bc904d01ce5de1be0fdb9d8796b3d427c7a89d7ace44209339c5577416dff5094858771314c6dcb8562f7d17a30c84630530510bff914ff0398b4616171386c23145d4cff3e4a0f698715bd68dbe2233b851ee49c17c0b7dc9b6f5f4ae461de98c4d582c8be6f490e75a0c2b1a61dfca366e86ca6ed131b93d43c93292f6182cf3d86e98d0baf613630e7a34a54dcba10f680b641579909c138223182443f71f110d7eb97d0bc99c795d95f28611ddf484208c3aa9763b517024d32faaea07a4343e4fa9b72ffb951fddd5e811def887a8d92e89c574d7820ed46df10da13e63ec1223d2bf1ee4b8f6cd353eae032fd8b3f6f886d5feb3032ac2c6cef1f03513e04646ffdbd0be6597f674bfcbce9f16127b43aa49f4e6853c56e2cd96c75aab089f07d04515e52a097c1b08c75ddb30315af1d65aebd00585c3818e7587baa5b11b80a0fd5fd2e0b7b473c9ad112a3168aadaf83ba4d94ad7e6b47c639684d634fe5ae59fc1f9e6741e924bdc8ed49c2a72bf1e7869fff80d17a7a0adacbf2123fbed51683d0897fd76310f3896381f47c675764b6475a027f92a0b89d863218dce9b3ac48524b3d1def4f0877aeab34415a27e33d305e9ae39dc8c918125498ab16932378e9f739bd2e0c4866265ff9f98c7b562000c762254336c3ac576cdfd96936c3f32ded9523594401d0ad2f2232a01b9c8443395180f1ec80a119e63e0bf631cb93a9db4ee6a2a29e06f520835f7af238e1c8cd873bef1e4039035240c33b7dec4981aa53e914f67ac932328b31f3fc4d0aac1c19a4da4dab1b525a63008d0e40b86076a1b7e9f0f219955c76798ae8d5131eee35e9900c5cdc8b58badd7022044521d7ad239a91bb2ae1a02fc61472f7d3629d14070641a1e86c2ef60ae3a42de23a15550c75b135a7be766fc38a2554377afc4892fef23e54ad59b72bfa590493d3a0e6d0c3692f9b12c28a4c2fcbfc8331381867935bdbdbe83220fe2330b5024ffdaeb37eb9a4f8dc8505ff846ce16a24ad0f36b8145591838c8cd056b4fa56d76e3f0d3c04cd58a13fc953ac12f292817ad4c1b46d62e372b5a5f8c7f3a4dcb29beb03b75d7b9d0a4a463e37f00da224c7fde6d34c3d53f34ac41a47b698e9b381d0debc448c465c594d9cf9c42e8cbce7e0e03091000000000028f08b690d86821cdcd517648214e22b5b0b73e2c7f82a3ccae933d61bc0e28fc69b047aba5cc6b8e9e6f4578e02924db920fdd2cbc3f1171c98169f4fd5676b77f210f9ae5e949afab54b2e52137538906ea05c5fc5e0ca989eb081a3ba9285ea611a9d69bbefb08d3142a7523a3ca91961b4f6deaa87286a4fe776607572b5db7e6ea488c5b9007731663b4537b584983937bfa8ec12bc8f6b1ec8185cb2863f7dc15f82f50978301f7441901d2921799af71fbf5f3a83162ddaed844b5647970b4bf4cb7d8bae88457f65c2e5f09b71b6585303e4783642c20949423fba406002407e6a58cd57836650e76df878926d0b6315f4c4329385566667701fe7f820487cbd29bfc97194ed8868ed4e458c7b2bf8ab6f04efee532502cf588c4f26b9b2830baa635c56857be5fd6803fd35d508881bd7cf3b5872ff84640384e2576bd93d4d86fdafcba2df3f29036491573031ede2ddb09dd092ad890a68f07876aeeb5ed24f1e21e96aa8f81d1b57f7963fdb0d617a6c302365781dcbe1628103ba3e9fb7c05ec5064aa5f518a2dd54deb3bb6547660749326b8e7c23931f938d1f94b2b199330c7cf4e21caaf3586b5ce3f56d5a1a06a78729f9e8b7838eef1f95828f2e1f46ccd7642fae51f13d2b0d6c55b328e0d6bae6355d412db989f82a3fa47b167da18c385588da0d8b2715d09c06cb2e03a1bccf8e112893d054c79b8d850d3c90fc8866865a2f85a8b3f64d9dfad1381b1bc0653335ac741925dccaac600000002895dca7ed412bae0cb70d758773dcfbb2254c95be80f230ceb3a73883bd6b6220cff45b7e9d058da58071acb8a32767b99a869379b6095f4e2b7ddecbd8a4d17a094f9681a4345c35c87dd86cba4074e56dae9e1ddadb7edfa248058f12f8f0c965d922130d696027a12fdfd06b1c39c7fba1875b39f751be361ccf330dfcdfa68623eb78747bc06f9ac45b812d5d313abfbfabdb4411220d1e78b5384749bb890b3f220139e0200315d516b3fb2e156b2a5c1c2a081a3e67eb6e8fc97be9bb4439a9eaadaab8e29db023baa98322d0d0e7f06efd708b5c7f8846e799e8607a20242d81c399a6571f8ea9c203a534ebfc6bf416540b8ad6a2c82e66dd9d2c0c502b387e119ec10c4a8963ee52710d75c21710881bae7fb5a8595fd43a9156419f8080891e50139bd4af14f1ba25ebe0152b5e83d115be493372e147742d8bfe3a8269e8ecd27ec055a11055d5405192cda8c8db528f06b120fc2e3f47089897411aaae9e0b0179b2e09afee8e5d56ea05b85694d71186f6d6dba1465c19cfc41f55751c1c7e3e071f0a97733f2ad4a8d7eb5038bb97411c01f77d451d483611c939f1910f388110198c69a2efdce02ad2334a1c39958bd66abb940ef1f42143a65010e383128f291e962c579ec7cb9f24f373554e84ce1a21f459d5ea4ab1a41ec733322f9b95611de75450bf415e60dc15f8d33fdb61f14d9c73c92cd6ace0943403768e8947e8122b2cbbc663a5373940daf22b914730c980c66e87e444db56f000000078c1751517b7f76514a5ea7af097099c03cc64d9416494d5a9f448c2615903650ab7c8c2358619073d84f04034ba7f768b62b4825d8a12f4c0378b2b271eb05f8b3cff514ebdae3b6de637539305437c2bc0bc6c2649961a1d22295035d07f460863a3d0467f01e79c4199bf3dd73a57a58315be6b4e465e43fe66e82dc933ee622598672fbd0c5bae12d8e187c7a6dc8a2c4b3dc57040a759e23594760d76c8d6655c0860e4a1187e89d7451b1507bc5e0ff3eeb28577af943a44afb61d96eca898cb8417551edffc189fe2d24e83f554206c397b80153044e45be32aef5b46deff4625d1d316338bf3521ee32ef50388a067b5c0972ca68797b98b337c09589c307d5adfac00a524ccca6d8d5450a0eea765673fbea3956aa0edf0dc0a2c7318dd61540865a408715c148e406489f7e56d953af3df90585b2dd12e99a4a6878009001b62f9fa0a023041fd77f41be2da2ed746a07bb3fa3864ab5e76be4f98d480fd97280735eb9f44c6bb0b1b02e2ee8c9d1c71c68de3325e6d14f44ef98b68b50ddef96b312c9a17296ecf837591659252f25670d9744c7334abca978eab4d7c40276b876ca682c2c06ba2809082d842c021fadb934bff19025c4dc1d80f6a9fac3cf59a7209c1d73113b87b8d34a8d618a5534db6fbc4492cfb6439a2c088cbbd44febb15f56e1d119bbf1e2bd108325711d56938eeffce12ecc900059822448666fd380701afb94887ff3a73d5ab6e3a9614ec319bb579d02de414db8a02d54f80928255dafc2b7833159aab87daffd5e143e7e939ec2c05496573f7de1aa46492cc29053e0ab0d7a2b524b3cade5e2ee0fbb0aa8f0b340cf139321230da9d50df0e36794ff03927ebdfaeb5b4c88612f9a7cb6660d8a088433ec92cd24ad06e4bb75885b0b7103d524f4f6b080be40484b9138278d95feb40af1c52cbb29f7623675d081c0930866586fee0476a9f21bffe406e3265413f792e0d464e9476becd32bb6af4856aaf4dfdbd6f1a2fea4cbe6df332e324f091fa74e7d9cdf01").unwrap(),
                        proof_version: ConcordiumZKProofVersion::ConcordiumZKProofV4,
                    },
                },
            }],
            linking_proof: LinkingProofV1 {
                created_at: DateTimeUtc::from_str("2023-08-28T23:12:15Z").unwrap().into(),
                proof_value: vec![],
                proof_type: ConcordiumLinkingProofVersion::ConcordiumWeakLinkingProofV1,
            },
        }
    }

    #[test]
    fn convert_presentation_v1() {
        let base_pres_v1 = create_base_presntation_v1();
        let bridge_pres_v1 = create_bridge_presentation_v1();
        let converted = PresentationV1::try_from(base_pres_v1.clone())
            .expect("Could not convert from base's PresentationV1");

        assert_eq!(bridge_pres_v1, converted);
    }
}
