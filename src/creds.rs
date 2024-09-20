use crate::types::*;
use concordium_base::id::{
    constants::{ArCurve, IpPairing, AttributeKind},
    types::IpInfo,
};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap};
use uniffi::deps::anyhow::Context;
use wallet_library::{
    credential::{
        compute_credential_deployment_hash_to_sign, create_unsigned_credential_v1_aux,
        serialize_credential_deployment_payload, CredentialDeploymentDetails,
        CredentialDeploymentPayload, UnsignedCredentialInput,
    },
    identity::{
        create_identity_object_request_v1_aux, create_identity_recovery_request_aux,
        IdentityObjectRequestInput, IdentityRecoveryRequestInput,
    },
    wallet::{
        get_account_public_key_aux, get_account_signing_key_aux,
        get_attribute_commitment_randomness_aux, get_credential_id_aux, get_id_cred_sec_aux,
        get_prf_key_aux, get_signature_blinding_randomness_aux,
        get_verifiable_credential_backup_encryption_key_aux,
        get_verifiable_credential_public_key_aux, get_verifiable_credential_signing_key_aux,
    },
};

/// Implements UDL definition of the same name.
pub fn identity_cred_sec(
    seed: Bytes,
    net: String,
    identity_provider_id: u32,
    identity_index: u32,
) -> Result<Bytes, ConcordiumWalletCryptoError> {
    let fn_desc = "identity_cred_sec(seed, net={net}, identity_provider_id={identity_provider_id}, identity_index={identity_index})";
    let hex = get_id_cred_sec_aux(
        hex::encode(seed),
        net.as_str(),
        identity_provider_id,
        identity_index,
    )
    .map_err(|e| e.to_call_failed(fn_desc.to_string()))?;
    Bytes::try_from(hex.as_str()).map_err(|e| e.to_call_failed(fn_desc.to_string()))
}

/// Implements UDL definition of the same name.
pub fn identity_prf_key(
    seed: Bytes,
    net: String,
    identity_provider_id: u32,
    identity_index: u32,
) -> Result<Bytes, ConcordiumWalletCryptoError> {
    let fn_desc = "identity_prf_key(seed, net={net}, identity_provider_id={identity_provider_id}, identity_index={identity_index})";
    let hex = get_prf_key_aux(
        hex::encode(seed),
        net.as_str(),
        identity_provider_id,
        identity_index,
    )
    .map_err(|e| e.to_call_failed(fn_desc.to_string()))?;
    Bytes::try_from(hex.as_str()).map_err(|e| e.to_call_failed(fn_desc.to_string()))
}

/// Implements UDL definition of the same name.
pub fn identity_attributes_signature_blinding_randomness(
    seed: Bytes,
    net: String,
    identity_provider_id: u32,
    identity_index: u32,
) -> Result<Bytes, ConcordiumWalletCryptoError> {
    let fn_desc = "identity_attributes_signature_blinding_randomness(seed, net={net}, identity_provider_id={identity_provider_id}, identity_index={identity_index})";
    let hex = get_signature_blinding_randomness_aux(
        hex::encode(seed),
        net.as_str(),
        identity_provider_id,
        identity_index,
    )
    .map_err(|e| e.to_call_failed(fn_desc.to_string()))?;
    Bytes::try_from(hex.as_str()).map_err(|e| e.to_call_failed(fn_desc.to_string()))
}

/// Implements UDL definition of the same name.
pub fn account_credential_signing_key(
    seed: Bytes,
    net: String,
    identity_provider_id: u32,
    identity_index: u32,
    credential_counter: u8,
) -> Result<Bytes, ConcordiumWalletCryptoError> {
    let fn_desc = "account_credential_signing_key(seed, net={net}, identity_provider_id={identity_provider_id}, identity_index={identity_index}, credential_counter={credential_counter})";
    let hex = get_account_signing_key_aux(
        hex::encode(seed),
        net.as_str(),
        identity_provider_id,
        identity_index,
        credential_counter.into(),
    )
    .map_err(|e| e.to_call_failed(fn_desc.to_string()))?;
    Bytes::try_from(hex.as_str()).map_err(|e| e.to_call_failed(fn_desc.to_string()))
}

/// Implements UDL definition of the same name.
pub fn account_credential_public_key(
    seed: Bytes,
    net: String,
    identity_provider_id: u32,
    identity_index: u32,
    credential_counter: u8,
) -> Result<Bytes, ConcordiumWalletCryptoError> {
    let fn_desc = "account_credential_public_key(seed, net={net}, identity_provider_id={identity_provider_id}, identity_index={identity_index}, credential_counter={credential_counter})";
    let hex = get_account_public_key_aux(
        hex::encode(seed),
        net.as_str(),
        identity_provider_id,
        identity_index,
        credential_counter.into(),
    )
    .map_err(|e| e.to_call_failed(fn_desc.to_string()))?;
    Bytes::try_from(hex.as_str()).map_err(|e| e.to_call_failed(fn_desc.to_string()))
}

/// Implements UDL definition of the same name.
pub fn account_credential_id(
    seed: Bytes,
    net: String,
    identity_provider_id: u32,
    identity_index: u32,
    credential_counter: u8,
    commitment_key: Bytes,
) -> Result<Bytes, ConcordiumWalletCryptoError> {
    let fn_desc = "account_credential_id(seed, net={net}, identity_provider_id={identity_provider_id}, identity_index={identity_index}, credential_counter={credential_counter}, commitment_key={commitment_key})";
    let hex = get_credential_id_aux(
        hex::encode(seed),
        net.as_str(),
        identity_provider_id,
        identity_index,
        credential_counter,
        &hex::encode(commitment_key),
    )
    .map_err(|e| e.to_call_failed(fn_desc.to_string()))?;
    Bytes::try_from(hex.as_str()).map_err(|e| e.to_call_failed(fn_desc.to_string()))
}

/// Implements UDL definition of the same name.
pub fn account_credential_attribute_commitment_randomness(
    seed: Bytes,
    net: String,
    identity_provider_id: u32,
    identity_index: u32,
    credential_counter: u8,
    attribute: u8,
) -> Result<Bytes, ConcordiumWalletCryptoError> {
    let fn_desc = "account_credential_attribute_commitment_randomness(seed, net={net}, identity_provider_id={identity_provider_id}, identity_index={identity_index}, credential_counter={credential_counter}, attribute={attribute})";
    let hex = get_attribute_commitment_randomness_aux(
        hex::encode(seed),
        net.as_str(),
        identity_provider_id,
        identity_index,
        credential_counter.into(),
        attribute,
    )
    .map_err(|e| e.to_call_failed(fn_desc.to_string()))?;
    Bytes::try_from(hex.as_str()).map_err(|e| e.to_call_failed(fn_desc.to_string()))
}

/// Implements UDL definition of the same name.
pub fn verifiable_credential_signing_key(
    seed: Bytes,
    net: String,
    issuer_index: u64,
    issuer_subindex: u64,
    verifiable_credential_index: u32,
) -> Result<Bytes, ConcordiumWalletCryptoError> {
    let fn_desc = "verifiable_credential_signing_key(seed, net={net}, issuer_index={issuer_index}, issuer_subindex={issuer_subindex}, verifiable_credential_index={verifiable_credential_index})";
    let hex = get_verifiable_credential_signing_key_aux(
        hex::encode(seed),
        net.as_str(),
        issuer_index,
        issuer_subindex,
        verifiable_credential_index,
    )
    .map_err(|e| e.to_call_failed(fn_desc.to_string()))?;
    Bytes::try_from(hex.as_str()).map_err(|e| e.to_call_failed(fn_desc.to_string()))
}

/// Implements UDL definition of the same name.
pub fn verifiable_credential_public_key(
    seed: Bytes,
    net: String,
    issuer_index: u64,
    issuer_subindex: u64,
    verifiable_credential_index: u32,
) -> Result<Bytes, ConcordiumWalletCryptoError> {
    let fn_desc = "verifiable_credential_public_key(seed, net={net}, issuer_index={issuer_index}, issuer_subindex={issuer_subindex}, verifiable_credential_index={verifiable_credential_index})";
    let hex = get_verifiable_credential_public_key_aux(
        hex::encode(seed),
        net.as_str(),
        issuer_index,
        issuer_subindex,
        verifiable_credential_index,
    )
    .map_err(|e| e.to_call_failed(fn_desc.to_string()))?;
    Bytes::try_from(hex.as_str()).map_err(|e| e.to_call_failed(fn_desc.to_string()))
}

/// Implements UDL definition of the same name.
pub fn verifiable_credential_backup_encryption_key(
    seed: Bytes,
    net: String,
) -> Result<Bytes, ConcordiumWalletCryptoError> {
    let fn_desc = "verifiable_credential_backup_encryption_key(seed, net={net}";
    let hex = get_verifiable_credential_backup_encryption_key_aux(hex::encode(seed), net.as_str())
        .map_err(|e| e.to_call_failed(fn_desc.to_string()))?;
    Bytes::try_from(hex.as_str()).map_err(|e| e.to_call_failed(fn_desc.to_string()))
}

/// UniFFI compatible bridge to [`IdentityObjectRequestInput`],
/// providing the implementation of the UDL declaration of the same name.
/// The translation is performed using Serde.
#[derive(Clone, Debug, Serialize)]
pub struct IdentityIssuanceRequestParameters {
    #[serde(rename = "ipInfo")]
    pub ip_info: IdentityProviderInfo,
    #[serde(rename = "globalContext")]
    pub global_context: GlobalContext,
    #[serde(rename = "arsInfos")]
    pub ars_infos: HashMap<u32, AnonymityRevokerInfo>,
    #[serde(rename = "arThreshold")]
    pub ar_threshold: u8,
    #[serde(rename = "prfKey")]
    pub prf_key: Bytes,
    #[serde(rename = "idCredSec")]
    pub id_cred_sec: Bytes,
    #[serde(rename = "blindingRandomness")]
    pub blinding_randomness: Bytes,
}

/// UniFFI compatible bridge to [`IdentityRecoveryRequestInput`],
/// providing the implementation of the UDL declaration of the same name.
/// The translation is performed using Serde.
#[derive(Clone, Debug, Serialize)]
pub struct IdentityRecoveryRequestParameters {
    #[serde(rename = "ipInfo")]
    pub ip_info: IdentityProviderInfo,
    #[serde(rename = "globalContext")]
    pub global_context: GlobalContext,
    #[serde(rename = "timestamp")]
    pub timestamp: u64,
    #[serde(rename = "idCredSec")]
    pub id_cred_sec: Bytes,
}

/// UniFFI compatible bridge to [`concordium_base::id::types::IpInfo<concordium_base::id::constants::IpPairing>`],
/// providing the implementation of the UDL declaration of the same name.
/// The translation is performed using Serde.
#[derive(Clone, Debug, Serialize)]
pub struct IdentityProviderInfo {
    #[serde(rename = "ipIdentity")]
    pub identity: u32,
    #[serde(rename = "ipDescription")]
    pub description: Description,
    #[serde(rename = "ipVerifyKey")]
    pub verify_key: Bytes,
    #[serde(rename = "ipCdiVerifyKey")]
    pub cdi_verify_key: Bytes,
}

impl TryFrom<IdentityProviderInfo> for IpInfo<IpPairing> {
    type Error = serde_json::Error;

    fn try_from(value: IdentityProviderInfo) -> Result<Self, Self::Error> {
        serde_json::to_string(&value).and_then(|s| serde_json::from_str(&s))
    }
}

/// UniFFI compatible bridge to [`concordium_base::id::types::ArInfo<concordium_base::id::constants::ArCurve>`],
/// providing the implementation of the UDL declaration of the same name.
/// The translation is performed using Serde.
#[derive(Clone, Debug, Serialize)]
pub struct AnonymityRevokerInfo {
    #[serde(rename = "arIdentity")]
    pub identity: u32,
    #[serde(rename = "arDescription")]
    pub description: Description,
    #[serde(rename = "arPublicKey")]
    pub public_key: Bytes,
}

/// UniFFI compatible bridge to [`concordium_base::id::types::Description`],
/// providing the implementation of the UDL declaration of the same name.
/// The translation is performed using Serde.
#[derive(Clone, Debug, Serialize)]
pub struct Description {
    #[serde(rename = "name")]
    pub name: String,
    #[serde(rename = "url")]
    pub url: String,
    #[serde(rename = "description")]
    pub description: String,
}

/// UniFFI compatible bridge to [`UnsignedCredentialInput`],
/// providing the implementation of the UDL declaration of the same name.
/// The translation is performed using Serde.
#[derive(Debug, Serialize)]
pub struct AccountCredentialParameters {
    #[serde(rename = "ipInfo")]
    pub ip_info: IdentityProviderInfo,
    #[serde(rename = "globalContext")]
    pub global_context: GlobalContext,
    #[serde(rename = "arsInfos")]
    pub ars_infos: HashMap<u32, AnonymityRevokerInfo>,
    #[serde(rename = "idObject")]
    pub id_object: IdentityObject,
    #[serde(rename = "revealedAttributes")]
    pub revealed_attributes: Vec<u8>,
    #[serde(rename = "credNumber")]
    pub cred_number: u8,
    #[serde(rename = "idCredSec")]
    pub id_cred_sec: Bytes,
    #[serde(rename = "prfKey")]
    pub prf_key: Bytes,
    #[serde(rename = "blindingRandomness")]
    pub blinding_randomness: Bytes,
    #[serde(rename = "attributeRandomness")]
    pub attribute_randomness: HashMap<String, Bytes>,
    #[serde(rename = "credentialPublicKeys")]
    pub credential_public_keys: CredentialPublicKeys,
}

/// UniFFI compatible bridge to [`concordium_base::id::types::IdentityObjectV1<IpPairing,ArCurve,AttributeKind>`],
/// providing the implementation of the UDL declaration of the same name.
/// The translation is performed using Serde.
#[derive(Debug, Serialize)]
pub struct IdentityObject {
    #[serde(rename = "preIdentityObject")]
    pub pre_identity_object: PreIdentityObject,
    #[serde(rename = "attributeList")]
    pub attribute_list: AttributeList,
    #[serde(rename = "signature")]
    pub signature: Bytes,
}

impl TryFrom<IdentityObject>
    for concordium_base::id::types::IdentityObjectV1<IpPairing, ArCurve, AttributeKind>
{
    type Error = serde_json::Error;

    fn try_from(value: IdentityObject) -> Result<Self, Self::Error> {
        serde_json::to_string(&value).and_then(|s| serde_json::from_str(&s))
    }
}

/// UniFFI compatible bridge to [`concordium_base::id::types::PreIdentityObjectV1<concordium_base::id::constants::IpPairing,concordium_base::id::constants::ArCurve>`],
/// providing the implementation of the UDL declaration of the same name.
/// The translation is performed using Serde.
#[derive(Debug, Deserialize, Serialize, PartialEq)]
pub struct PreIdentityObject {
    #[serde(rename = "idCredPub")]
    pub id_cred_pub: Bytes,
    #[serde(rename = "ipArData")]
    pub ip_ar_data: HashMap<u32, ArData>,
    #[serde(rename = "choiceArData")]
    pub choice_ar_data: ChoiceArParameters,
    #[serde(rename = "idCredSecCommitment")]
    pub id_cred_sec_commitment: Bytes,
    #[serde(rename = "prfKeyCommitmentWithIP")]
    pub prf_key_commitment_with_ip: Bytes,
    #[serde(rename = "prfKeySharingCoeffCommitments")]
    pub prf_key_sharing_coeff_commitments: Vec<Bytes>,
    #[serde(rename = "proofsOfKnowledge")]
    pub proofs_of_knowledge: Bytes,
}

/// UniFFI compatible bridge to [`concordium_base::id::types::ChoiceArParameters`],
/// providing the implementation of the UDL declaration of the same name.
/// The translation is performed using Serde.
#[derive(Debug, Deserialize, Serialize, PartialEq)]
pub struct ChoiceArParameters {
    #[serde(rename = "arIdentities")]
    pub ar_identities: Vec<u32>,
    #[serde(rename = "threshold")]
    pub threshold: u8,
}

/// UniFFI compatible bridge to [`concordium_base::id::types::IpArData<concordium_base::id::constants::ArCurve>`],
/// providing the implementation of the UDL declaration of the same name.
/// The translation is performed using Serde.
#[derive(Debug, Deserialize, Serialize, PartialEq)]
pub struct ArData {
    #[serde(rename = "encPrfKeyShare")]
    pub enc_prf_key_share: Bytes,
    #[serde(rename = "proofComEncEq")]
    pub proof_com_enc_eq: Bytes,
}

/// UniFFI compatible bridge to [`concordium_base::id::types::AttributeList<concordium_base::id::constants::IpPairing,concordium_base::id::constants::ArCurve> `],
/// providing the implementation of the UDL declaration of the same name.
/// The translation is performed using Serde.
#[derive(Debug, Serialize)]
pub struct AttributeList {
    #[serde(rename = "validTo")]
    pub valid_to_year_month: String,
    #[serde(rename = "createdAt")]
    pub created_at_year_month: String,
    #[serde(rename = "maxAccounts")]
    pub max_accounts: u8,
    #[serde(rename = "chosenAttributes")]
    pub chosen_attributes: HashMap<String, String>,
}

/* OUTPUTS */

/// UniFFI compatible bridge to [`wallet_library::credential::UnsignedCredentialDeploymentInfoWithRandomness`] (internal),
/// providing the implementation of the UDL declaration of the same name.
/// The translation is performed using Serde.
#[derive(Debug, Deserialize)]
pub struct AccountCredentialResult {
    #[serde(rename = "unsignedCdi")]
    pub credential: AccountCredential,
    #[serde(rename = "randomness")]
    pub randomness: Randomness,
}

/// UniFFI compatible bridge to [`concordium_base::id::types::CommitmentsRandomness<concordium_base::id::constants::ArCurve>`],
/// providing the implementation of the UDL declaration of the same name.
/// The translation is performed using Serde.
#[derive(Debug, Deserialize)]
pub struct Randomness {
    #[serde(rename = "attributesRand")]
    pub attributes_rand: HashMap<String, Bytes>,
    #[serde(rename = "credCounterRand")]
    pub cred_counter_rand: Bytes,
    #[serde(rename = "idCredSecRand")]
    pub id_cred_sec_rand: Bytes,
    #[serde(rename = "maxAccountsRand")]
    pub max_accounts_rand: Bytes,
    #[serde(rename = "prfRand")]
    pub prf_rand: Bytes,
}

/// Implements UDL definition of the same name.
/// The returned string is a versioned [`PreIdentityObject`] encoded as JSON.
pub fn identity_issuance_request_json(
    params: IdentityIssuanceRequestParameters,
) -> Result<String, ConcordiumWalletCryptoError> {
    serde_json::to_string(&params)
        .context("cannot encode request object as JSON")
        .and_then(|json| {
            serde_json::from_str::<IdentityObjectRequestInput>(&json)
                .context("cannot decode request object into internal type")
        })
        .and_then(|input| {
            create_identity_object_request_v1_aux(input).context("cannot create identity")
        })
        .map_err(|e| ConcordiumWalletCryptoError::CallFailed {
            call: "identity_issuance_request_json(...)".to_string(),
            msg: format!("{:#}", e),
        })
}

/// Implements UDL definition of the same name.
/// The returned string is a versioned `IdentityRecoveryRequestResultValue` (defined in `lib_test.rs`) encoded as JSON.
pub fn identity_recovery_request_json(
    params: IdentityRecoveryRequestParameters,
) -> Result<String, ConcordiumWalletCryptoError> {
    serde_json::to_string(&params)
        .context("cannot encode request object as JSON")
        .and_then(|json| {
            serde_json::from_str::<IdentityRecoveryRequestInput>(&json)
                .context("cannot decode request object into internal type")
        })
        .and_then(|input| {
            create_identity_recovery_request_aux(input).context("cannot create identity")
        })
        .map_err(|e| ConcordiumWalletCryptoError::CallFailed {
            call: "identity_recovery_request_json(...)".to_string(),
            msg: format!("{:#}", e),
        })
}

/// UniFFI compatible bridge to [`concordium_base::id::types::UnsignedCredentialDeploymentInfo<concordium_base::id::constants::IpPairing,concordium_base::id::constants::ArCurve,concordium_base::id::constants::AttributeKind>`],
/// providing the implementation of the UDL declaration of the same name.
/// The translation is performed using Serde.
#[derive(Debug, Deserialize, Serialize)]
pub struct AccountCredential {
    #[serde(rename = "arData")]
    pub ar_data: HashMap<u32, ChainArData>,
    #[serde(rename = "credId")]
    pub cred_id: Bytes,
    #[serde(rename = "credentialPublicKeys")]
    pub credential_public_keys: CredentialPublicKeys,
    #[serde(rename = "ipIdentity")]
    pub ip_identity: u32,
    #[serde(rename = "policy")]
    pub policy: Policy,
    #[serde(rename = "proofs")]
    pub proofs: Proofs,
    #[serde(rename = "revocationThreshold")]
    pub revocation_threshold: u8,
}

/// UniFFI compatible bridge to [`concordium_base::id::types::IdOwnershipProofs<concordium_base::id::constants::IpPairing,concordium_base::id::constants::ArCurve>`],
/// providing the implementation of the UDL declaration of the same name.
/// The translation is performed using Serde.
#[derive(Debug, Deserialize, Serialize, PartialEq)]
pub struct Proofs {
    #[serde(rename = "challenge")]
    pub challenge: Bytes,
    #[serde(rename = "commitments")]
    pub commitments: Bytes,
    #[serde(rename = "credCounterLessThanMaxAccounts")]
    pub cred_counter_less_than_max_accounts: Bytes,
    #[serde(rename = "proofIdCredPub")]
    pub proof_id_cred_pub: HashMap<String, Bytes>,
    #[serde(rename = "proofIpSig")]
    pub proof_ip_sig: Bytes,
    #[serde(rename = "proofRegId")]
    pub proof_reg_id: Bytes,
    #[serde(rename = "sig")]
    pub signature: Bytes,
}

/// Implements UDL definition of the same name.
pub fn account_credential(
    params: AccountCredentialParameters,
) -> Result<AccountCredentialResult, ConcordiumWalletCryptoError> {
    serde_json::to_string(&params)
        .context("cannot encode request object as JSON")
        .and_then(|json| {
            serde_json::from_str::<UnsignedCredentialInput>(&json)
                .context("cannot decode request object into internal type")
        })
        .and_then(|input| {
            create_unsigned_credential_v1_aux(input).context("cannot create identity")
        })
        .and_then(|res| {
            serde_json::from_str::<AccountCredentialResult>(&res)
                .context("cannot decode response object into result type")
        })
        .map_err(|e| ConcordiumWalletCryptoError::CallFailed {
            call: "account_credential(...)".to_string(),
            msg: format!("{:#}", e),
        })
}

/// Duplicate of [`CredentialDeploymentDetails`] because that type only supports construction from JSON.
/// It's only used internally and not exported.
#[derive(Debug, Serialize)]
struct CredentialDeploymentPayloadHashInput {
    #[serde(rename = "expiry")]
    expiry_unix_secs: u64,
    #[serde(rename = "unsignedCdi")]
    credential: AccountCredential,
}

/// Implements UDL definition of the same name.
pub fn account_credential_deployment_hash(
    credential: AccountCredential,
    expiry_unix_secs: u64,
) -> Result<Bytes, ConcordiumWalletCryptoError> {
    let input = CredentialDeploymentPayloadHashInput {
        expiry_unix_secs,
        credential,
    };
    let fn_desc = "account_credential_deployment_hash(...)";
    let hex = serde_json::to_string(&input)
        .context("cannot encode request object as JSON")
        .and_then(|json| {
            serde_json::from_str::<CredentialDeploymentDetails>(&json)
                .context("cannot decode request object into internal type")
        })
        .map(compute_credential_deployment_hash_to_sign)
        .map_err(|e| e.to_call_failed(fn_desc.to_string()))?;
    Bytes::try_from(hex.as_str()).map_err(|e| e.to_call_failed(fn_desc.to_string()))
}

/// UniFFI compatible bridge to [`CredentialDeploymentPayload`],
/// providing the implementation of the UDL declaration of the same name.
/// The translation is performed using Serde.
#[derive(Debug, Serialize)]
pub struct SignedAccountCredential {
    #[serde(rename = "unsignedCdi")]
    pub credential: AccountCredential,
    #[serde(rename = "signatures")]
    pub signatures: HashMap<u8, Bytes>,
}

/// Implements UDL definition of the same name.
pub fn account_credential_deployment_signed_payload(
    credential: SignedAccountCredential,
) -> Result<Bytes, ConcordiumWalletCryptoError> {
    let fn_desc = "account_credential_deployment_signed_payload(...)";
    let hex = serde_json::to_string(&credential)
        .context("cannot encode request object as JSON")
        .and_then(|json| {
            serde_json::from_str::<CredentialDeploymentPayload>(&json)
                .context("cannot decode request object into internal type")
        })
        .map(serialize_credential_deployment_payload)
        .map_err(|e| e.to_call_failed(fn_desc.to_string()))?;
    Bytes::try_from(hex.as_str()).map_err(|e| e.to_call_failed(fn_desc.to_string()))
}
