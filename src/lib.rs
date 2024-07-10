use concordium_base::{
    common::{Deserial, Serial},
    contracts_common::Amount,
    encrypted_transfers::{
        self,
        types::{AggregatedDecryptedAmount, SecToPubAmountTransferData},
    },
    id::constants::ArCurve,
};
use rand::thread_rng;
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, io::Read};
use uniffi::deps::anyhow::{self, Context};
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

// UniFFI book: https://mozilla.github.io/uniffi-rs/udl_file_spec.html
uniffi::include_scaffolding!("lib");

/// Error type returned by the bridge functions.
/// A corresponding Swift type will be generated (via the UDL definition).
#[derive(Debug, thiserror::Error)]
pub enum ConcordiumWalletCryptoError {
    /// FFI call failed
    #[error("call {call} failed: {msg}")]
    CallFailed { call: String, msg: String },
}

trait ConvertError
where
    Self: std::fmt::Display,
{
    /// Convert to [`ConcordiumWalletCryptoError::CallFailed`]
    fn to_call_failed(&self, fn_description: &'static str) -> ConcordiumWalletCryptoError {
        ConcordiumWalletCryptoError::CallFailed {
            call: fn_description.to_string(),
            msg: format!("{:#}", self),
        }
    }
}

impl ConvertError for serde_json::Error {}
impl ConvertError for uniffi::deps::anyhow::Error {}

/// Implements UDL definition of the same name.
pub fn identity_cred_sec_hex(
    seed_hex: String,
    net: String,
    identity_provider_id: u32,
    identity_index: u32,
) -> Result<String, ConcordiumWalletCryptoError> {
    get_id_cred_sec_aux(seed_hex, net.as_str(), identity_provider_id, identity_index)
        .map_err(|e| ConcordiumWalletCryptoError::CallFailed {
            call: format!("identity_cred_sec_hex(seed_hex, net={net}, identity_provider_id={identity_provider_id}, identity_index={identity_index})"),
            msg: format!("{:#}", e),
        })
}

/// Implements UDL definition of the same name.
pub fn identity_prf_key_hex(
    seed_hex: String,
    net: String,
    identity_provider_id: u32,
    identity_index: u32,
) -> Result<String, ConcordiumWalletCryptoError> {
    get_prf_key_aux(seed_hex, net.as_str(), identity_provider_id, identity_index)
        .map_err(|e| ConcordiumWalletCryptoError::CallFailed {
            call: format!("identity_prf_key_hex(seed_hex, net={net}, identity_provider_id={identity_provider_id}, identity_index={identity_index})"),
            msg: format!("{:#}", e),
        })
}

/// Implements UDL definition of the same name.
pub fn identity_attributes_signature_blinding_randomness_hex(
    seed_hex: String,
    net: String,
    identity_provider_id: u32,
    identity_index: u32,
) -> Result<String, ConcordiumWalletCryptoError> {
    get_signature_blinding_randomness_aux(seed_hex, net.as_str(), identity_provider_id, identity_index)
        .map_err(|e| ConcordiumWalletCryptoError::CallFailed {
            call: format!("identity_attributes_signature_blinding_randomness_hex(seed_hex, net={net}, identity_provider_id={identity_provider_id}, identity_index={identity_index})"),
            msg: format!("{:#}", e),
        })
}

/// Implements UDL definition of the same name.
pub fn account_credential_signing_key_hex(
    seed_hex: String,
    net: String,
    identity_provider_id: u32,
    identity_index: u32,
    credential_counter: u8,
) -> Result<String, ConcordiumWalletCryptoError> {
    get_account_signing_key_aux(seed_hex, net.as_str(), identity_provider_id, identity_index, credential_counter.into())
        .map_err(|e| ConcordiumWalletCryptoError::CallFailed {
            call: format!("account_credential_signing_key_hex(seed_hex, net={net}, identity_provider_id={identity_provider_id}, identity_index={identity_index}, credential_counter={credential_counter})"),
            msg: format!("{:#}", e),
        })
}

/// Implements UDL definition of the same name.
pub fn account_credential_public_key_hex(
    seed_hex: String,
    net: String,
    identity_provider_id: u32,
    identity_index: u32,
    credential_counter: u8,
) -> Result<String, ConcordiumWalletCryptoError> {
    get_account_public_key_aux(seed_hex, net.as_str(), identity_provider_id, identity_index, credential_counter.into())
        .map_err(|e| ConcordiumWalletCryptoError::CallFailed {
            call: format!("account_credential_public_key_hex(seed_hex, net={net}, identity_provider_id={identity_provider_id}, identity_index={identity_index}, credential_counter={credential_counter})"),
            msg: format!("{:#}", e),
        })
}

/// Implements UDL definition of the same name.
pub fn account_credential_id_hex(
    seed_hex: String,
    net: String,
    identity_provider_id: u32,
    identity_index: u32,
    credential_counter: u8,
    commitment_key: String,
) -> Result<String, ConcordiumWalletCryptoError> {
    get_credential_id_aux(seed_hex, net.as_str(), identity_provider_id, identity_index, credential_counter, commitment_key.as_str())
        .map_err(|e| ConcordiumWalletCryptoError::CallFailed {
            call: format!("account_credential_id_hex(seed_hex, net={net}, identity_provider_id={identity_provider_id}, identity_index={identity_index}, credential_counter={credential_counter}, commitment_key={commitment_key})"),
            msg: format!("{:#}", e),
        })
}

/// Implements UDL definition of the same name.
pub fn account_credential_attribute_commitment_randomness_hex(
    seed_hex: String,
    net: String,
    identity_provider_id: u32,
    identity_index: u32,
    credential_counter: u8,
    attribute: u8,
) -> Result<String, ConcordiumWalletCryptoError> {
    get_attribute_commitment_randomness_aux(seed_hex, net.as_str(), identity_provider_id, identity_index, credential_counter.into(), attribute)
        .map_err(|e| ConcordiumWalletCryptoError::CallFailed {
            call: format!("account_credential_attribute_commitment_randomness_hex(seed_hex, net={net}, identity_provider_id={identity_provider_id}, identity_index={identity_index}, credential_counter={credential_counter}, attribute={attribute})"),
            msg: format!("{:#}", e),
        })
}

/// Implements UDL definition of the same name.
pub fn verifiable_credential_signing_key_hex(
    seed_hex: String,
    net: String,
    issuer_index: u64,
    issuer_subindex: u64,
    verifiable_credential_index: u32,
) -> Result<String, ConcordiumWalletCryptoError> {
    get_verifiable_credential_signing_key_aux(seed_hex, net.as_str(), issuer_index, issuer_subindex, verifiable_credential_index)
        .map_err(|e| ConcordiumWalletCryptoError::CallFailed {
            call: format!("verifiable_credential_signing_key_hex(seed_hex, net={net}, issuer_index={issuer_index}, issuer_subindex={issuer_subindex}, verifiable_credential_index={verifiable_credential_index})"),
            msg: format!("{:#}", e),
        })
}

/// Implements UDL definition of the same name.
pub fn verifiable_credential_public_key_hex(
    seed_hex: String,
    net: String,
    issuer_index: u64,
    issuer_subindex: u64,
    verifiable_credential_index: u32,
) -> Result<String, ConcordiumWalletCryptoError> {
    get_verifiable_credential_public_key_aux(seed_hex, net.as_str(), issuer_index, issuer_subindex, verifiable_credential_index)
        .map_err(|e| ConcordiumWalletCryptoError::CallFailed {
            call: format!("verifiable_credential_public_key_hex(seed_hex, net={net}, issuer_index={issuer_index}, issuer_subindex={issuer_subindex}, verifiable_credential_index={verifiable_credential_index})"),
            msg: format!("{:#}", e),
        })
}

/// Implements UDL definition of the same name.
pub fn verifiable_credential_backup_encryption_key_hex(
    seed_hex: String,
    net: String,
) -> Result<String, ConcordiumWalletCryptoError> {
    get_verifiable_credential_backup_encryption_key_aux(seed_hex, net.as_str()).map_err(|e| {
        ConcordiumWalletCryptoError::CallFailed {
            call: format!("verifiable_credential_backup_encryption_key_hex(seed_hex, net={net}"),
            msg: format!("{:#}", e),
        }
    })
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
    pub prf_key_hex: String,
    #[serde(rename = "idCredSec")]
    pub id_cred_sec_hex: String,
    #[serde(rename = "blindingRandomness")]
    pub blinding_randomness_hex: String,
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
    pub id_cred_sec_hex: String,
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
    pub verify_key_hex: String,
    #[serde(rename = "ipCdiVerifyKey")]
    pub cdi_verify_key_hex: String,
}

/// UniFFI compatible bridge to [`concordium_base::id::types::GlobalContext<concordium_base::id::constants::ArCurve>`],
/// providing the implementation of the UDL declaration of the same name.
/// The translation is performed using Serde.
#[derive(Clone, Debug, Serialize)]
pub struct GlobalContext {
    #[serde(rename = "onChainCommitmentKey")]
    pub on_chain_commitment_key_hex: String,
    #[serde(rename = "bulletproofGenerators")]
    pub bulletproof_generators_hex: String,
    #[serde(rename = "genesisString")]
    pub genesis_string: String,
}

impl TryFrom<GlobalContext> for concordium_base::id::types::GlobalContext<ArCurve> {
    type Error = uniffi::deps::anyhow::Error;

    fn try_from(value: GlobalContext) -> Result<Self, Self::Error> {
        serde_json::to_string(&value)
            .context("cannot encode request object as JSON")
            .and_then(|json| {
                serde_json::from_str::<concordium_base::id::types::GlobalContext<ArCurve>>(&json)
                    .context("cannot decode request object into internal type")
            })
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
    pub public_key_hex: String,
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
    pub id_cred_sec_hex: String,
    #[serde(rename = "prfKey")]
    pub prf_key_hex: String,
    #[serde(rename = "blindingRandomness")]
    pub blinding_randomness_hex: String,
    #[serde(rename = "attributeRandomness")]
    pub attribute_randomness_hex: HashMap<String, String>,
    #[serde(rename = "credentialPublicKeys")]
    pub credential_public_keys: CredentialPublicKeys,
}

/// UniFFI compatible bridge to [`concordium_base::id::types::IdentityObjectV1<concordium_base::id::constants::IpPairing,concordium_base::id::constants::ArCurve,concordium_base::id::constants::AttributeKind>`],
/// providing the implementation of the UDL declaration of the same name.
/// The translation is performed using Serde.
#[derive(Debug, Serialize)]
pub struct IdentityObject {
    #[serde(rename = "preIdentityObject")]
    pub pre_identity_object: PreIdentityObject,
    #[serde(rename = "attributeList")]
    pub attribute_list: AttributeList,
    #[serde(rename = "signature")]
    pub signature_hex: String,
}

/// UniFFI compatible bridge to [`concordium_base::id::types::PreIdentityObjectV1<concordium_base::id::constants::IpPairing,concordium_base::id::constants::ArCurve>`],
/// providing the implementation of the UDL declaration of the same name.
/// The translation is performed using Serde.
#[derive(Debug, Deserialize, Serialize, PartialEq)]
pub struct PreIdentityObject {
    #[serde(rename = "idCredPub")]
    pub id_cred_pub_hex: String,
    #[serde(rename = "ipArData")]
    pub ip_ar_data: HashMap<u32, ArData>,
    #[serde(rename = "choiceArData")]
    pub choice_ar_data: ChoiceArParameters,
    #[serde(rename = "idCredSecCommitment")]
    pub id_cred_sec_commitment_hex: String,
    #[serde(rename = "prfKeyCommitmentWithIP")]
    pub prf_key_commitment_with_ip_hex: String,
    #[serde(rename = "prfKeySharingCoeffCommitments")]
    pub prf_key_sharing_coeff_commitments_hex: Vec<String>,
    #[serde(rename = "proofsOfKnowledge")]
    pub proofs_of_knowledge_hex: String,
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
    pub enc_prf_key_share_hex: String,
    #[serde(rename = "proofComEncEq")]
    pub proof_com_enc_eq_hex: String,
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

/// UniFFI compatible bridge to [`concordium_base::id::types::CredentialPublicKeys`],
/// providing the implementation of the UDL declaration of the same name.
/// The translation is performed using Serde.
#[derive(Debug, Deserialize, Serialize)]
pub struct CredentialPublicKeys {
    #[serde(rename = "keys")]
    pub keys: HashMap<u8, VerifyKey>,
    #[serde(rename = "threshold")]
    pub threshold: u8,
}

/// UniFFI compatible bridge to [`concordium_base::id::types::VerifyKey`],
/// providing the implementation of the UDL declaration of the same name.
/// The translation is performed using Serde.
#[derive(Debug, Deserialize, Serialize)]
pub struct VerifyKey {
    #[serde(rename = "schemeId")]
    pub scheme_id: String,
    #[serde(rename = "verifyKey")]
    pub key_hex: String,
}

/* OUTPUTS */

/// UniFFI compatible bridge to [`wallet_library::credential::UnsignedCredentialDeploymentInfoWithRandomness`] (internal),
/// providing the implementation of the UDL declaration of the same name.
/// The translation is performed using Serde.
#[derive(Debug, Deserialize)]
pub struct AccountCredentialResult {
    #[serde(rename = "unsignedCdi")]
    credential: AccountCredential,
    #[serde(rename = "randomness")]
    randomness: Randomness,
}

/// UniFFI compatible bridge to [`concordium_base::id::types::CommitmentsRandomness<concordium_base::id::constants::ArCurve>`],
/// providing the implementation of the UDL declaration of the same name.
/// The translation is performed using Serde.
#[derive(Debug, Deserialize)]
pub struct Randomness {
    #[serde(rename = "attributesRand")]
    pub attributes_rand_hex: HashMap<String, String>,
    #[serde(rename = "credCounterRand")]
    pub cred_counter_rand_hex: String,
    #[serde(rename = "idCredSecRand")]
    pub id_cred_sec_rand_hex: String,
    #[serde(rename = "maxAccountsRand")]
    pub max_accounts_rand_hex: String,
    #[serde(rename = "prfRand")]
    pub prf_rand_hex: String,
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
    pub cred_id_hex: String,
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

/// UniFFI compatible bridge to [`concordium_base::id::types::ChainArData<concordium_base::id::constants::ArCurve>`],
/// providing the implementation of the UDL declaration of the same name.
/// The translation is performed using Serde.
#[derive(Debug, Deserialize, Serialize)]
pub struct ChainArData {
    #[serde(rename = "encIdCredPubShare")]
    pub enc_id_cred_pub_share_hex: String,
}

/// UniFFI compatible bridge to [`concordium_base::id::types::Policy<concordium_base::id::constants::ArCurve,concordium_base::id::constants::AttributeKind> `],
/// providing the implementation of the UDL declaration of the same name.
/// The translation is performed using Serde.
#[derive(Debug, Deserialize, Serialize)]
pub struct Policy {
    #[serde(rename = "createdAt")]
    pub created_at_year_month: String,
    #[serde(rename = "revealedAttributes")]
    pub revealed_attributes: HashMap<String, String>,
    #[serde(rename = "validTo")]
    pub valid_to_year_month: String,
}

/// UniFFI compatible bridge to [`concordium_base::id::types::IdOwnershipProofs<concordium_base::id::constants::IpPairing,concordium_base::id::constants::ArCurve>`],
/// providing the implementation of the UDL declaration of the same name.
/// The translation is performed using Serde.
#[derive(Debug, Deserialize, Serialize, PartialEq)]
pub struct Proofs {
    #[serde(rename = "challenge")]
    pub challenge_hex: String,
    #[serde(rename = "commitments")]
    pub commitments_hex: String,
    #[serde(rename = "credCounterLessThanMaxAccounts")]
    pub cred_counter_less_than_max_accounts_hex: String,
    #[serde(rename = "proofIdCredPub")]
    pub proof_id_cred_pub_hex: HashMap<String, String>,
    #[serde(rename = "proofIpSig")]
    pub proof_ip_sig_hex: String,
    #[serde(rename = "proofRegId")]
    pub proof_reg_id_hex: String,
    #[serde(rename = "sig")]
    pub signature_hex: String,
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
pub fn account_credential_deployment_hash_hex(
    credential: AccountCredential,
    expiry_unix_secs: u64,
) -> Result<String, ConcordiumWalletCryptoError> {
    let input = CredentialDeploymentPayloadHashInput {
        expiry_unix_secs,
        credential,
    };
    serde_json::to_string(&input)
        .context("cannot encode request object as JSON")
        .and_then(|json| {
            serde_json::from_str::<CredentialDeploymentDetails>(&json)
                .context("cannot decode request object into internal type")
        })
        .map(compute_credential_deployment_hash_to_sign)
        .map_err(|e| ConcordiumWalletCryptoError::CallFailed {
            call: "account_credential_deployment_hash_hex(...)".to_string(),
            msg: format!("{:#}", e),
        })
}

/// UniFFI compatible bridge to [`CredentialDeploymentPayload`],
/// providing the implementation of the UDL declaration of the same name.
/// The translation is performed using Serde.
#[derive(Debug, Serialize)]
pub struct SignedAccountCredential {
    #[serde(rename = "unsignedCdi")]
    pub credential: AccountCredential,
    #[serde(rename = "signatures")]
    pub signatures_hex: HashMap<u8, String>,
}

/// Implements UDL definition of the same name.
pub fn account_credential_deployment_signed_payload_hex(
    credential: SignedAccountCredential,
) -> Result<String, ConcordiumWalletCryptoError> {
    serde_json::to_string(&credential)
        .context("cannot encode request object as JSON")
        .and_then(|json| {
            serde_json::from_str::<CredentialDeploymentPayload>(&json)
                .context("cannot decode request object into internal type")
        })
        .map(serialize_credential_deployment_payload)
        .map_err(|e| ConcordiumWalletCryptoError::CallFailed {
            call: "account_credential_deployment_signed_payload_hex(...)".to_string(),
            msg: format!("{:#}", e),
        })
}

/// UniFFI compatible bridge from [`AggregatedDecryptedAmount<ArCurve>`],
/// providing the implementation of the UDL declaration of the same name.
/// The translation is performed using Serde.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InputEncryptedAmount {
    /// The aggregated encrypted amount as hex.
    pub agg_encrypted_amount: String,
    /// The plaintext corresponding to the aggregated encrypted amount.
    pub agg_amount: u64,
    /// Index such that the `agg_amount` is the sum of all encrypted amounts
    /// on an account with indices strictly below `agg_index`.
    pub agg_index: u64,
}

impl TryFrom<InputEncryptedAmount> for AggregatedDecryptedAmount<ArCurve> {
    type Error = serde_json::Error;

    fn try_from(value: InputEncryptedAmount) -> Result<Self, Self::Error> {
        let agg_encrypted_amount = serde_json::from_str(&value.agg_encrypted_amount)?;
        let agg_amount = Amount {
            micro_ccd: value.agg_amount,
        };
        let agg_index = value.agg_index.into();
        Ok(Self {
            agg_encrypted_amount,
            agg_amount,
            agg_index,
        })
    }
}

/// UniFFI compatible bridge from [`SecToPubAmountTransferData<ArCurve>`],
/// providing the implementation of the UDL declaration of the same name.
/// The translation is performed using Serde.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SecToPubTransferData {
    #[serde(rename = "remainingAmount")]
    serialized_remaining_amount: Vec<u8>,
    transfer_amount: u64,
    index: u64,
    #[serde(rename = "proof")]
    serialized_proof: Vec<u8>,
}

impl From<SecToPubAmountTransferData<ArCurve>> for SecToPubTransferData {
    fn from(value: SecToPubAmountTransferData<ArCurve>) -> Self {
        let mut serialized_remaining_amount = vec![];
        value
            .remaining_amount
            .serial(&mut serialized_remaining_amount);
        let mut serialized_proof = vec![];
        value.proof.serial(&mut serialized_proof);

        SecToPubTransferData {
            serialized_remaining_amount,
            transfer_amount: value.transfer_amount.micro_ccd,
            index: value.index.index,
            serialized_proof,
        }
    }
}

/// Implements UDL definition of the same name.
pub fn sec_to_pub_transfer_data(
    ctx: GlobalContext,
    sender_secret_key: String,
    input_amount: InputEncryptedAmount,
    to_transfer: u64,
) -> Result<SecToPubTransferData, ConcordiumWalletCryptoError> {
    let fn_desc = "sec_to_pub_transfer_data(...)";
    let ctx = concordium_base::id::types::GlobalContext::try_from(ctx)
        .map_err(|e| e.to_call_failed(fn_desc))?;
    let sk: concordium_base::elgamal::SecretKey<ArCurve> =
        serde_json::from_str(&sender_secret_key).map_err(|e| e.to_call_failed(fn_desc))?;
    let input_amount =
        AggregatedDecryptedAmount::try_from(input_amount).map_err(|e| e.to_call_failed(fn_desc))?;
    let to_transfer = Amount {
        micro_ccd: to_transfer,
    };
    let mut csprng = thread_rng();

    let transfer_data = encrypted_transfers::make_sec_to_pub_transfer_data(
        &ctx,
        &sk,
        &input_amount,
        to_transfer,
        &mut csprng,
    )
    .ok_or(ConcordiumWalletCryptoError::CallFailed {
        call: fn_desc.to_string(),
        msg: "Failed to create transfer data".to_string(),
    })?;

    Ok(transfer_data.into())
}

/// Implements UDL definition of the same name.
pub fn deserialize_sec_to_pub_transfer_data(
    bytes: Vec<u8>,
) -> Result<SecToPubTransferData, ConcordiumWalletCryptoError> {
    let fn_name = "deserialize_sec_to_pub_transfer_data(...)";
    let mut bytes = std::io::Cursor::new(bytes);
    let transfer_data =
        SecToPubAmountTransferData::deserial(&mut bytes).map_err(|e| e.to_call_failed(fn_name))?;

    if bytes.bytes().count() != 0 {
        return Err(ConcordiumWalletCryptoError::CallFailed {
            call: fn_name.to_string(),
            msg: "Buffer not exhausted when deserializing type".to_string(),
        });
    }

    Ok(transfer_data.into())
}
