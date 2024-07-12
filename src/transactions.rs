use std::{
    collections::{BTreeMap, HashMap},
    str::FromStr,
};

use concordium_base::{
    base::{AccountThreshold, CredentialRegistrationID},
    common::{types::CredentialIndex, Deserial, Serial},
    contracts_common::{AccountAddress, Amount},
    encrypted_transfers::{
        self,
        types::{AggregatedDecryptedAmount, SecToPubAmountTransferData},
    },
    id::constants::{ArCurve, AttributeKind, IpPairing},
    transactions::{AccountCredentialsMap, ConfigureBakerKeysPayload},
};
use rand::thread_rng;
use serde::{Deserialize, Serialize};
use uniffi::deps::anyhow::{self, Context};

use crate::types::*;

/// UniFFI compatible bridge from [`AggregatedDecryptedAmount<ArCurve>`],
/// providing the implementation of the UDL declaration of the same name.
#[derive(Debug)]
pub struct InputEncryptedAmount {
    /// The aggregated encrypted amount as hex.
    pub agg_encrypted_amount: Bytes,
    /// The plaintext corresponding to the aggregated encrypted amount.
    pub agg_amount: u64,
    /// Index such that the `agg_amount` is the sum of all encrypted amounts
    /// on an account with indices strictly below `agg_index`.
    pub agg_index: u64,
}

impl TryFrom<InputEncryptedAmount> for AggregatedDecryptedAmount<ArCurve> {
    type Error = serde_json::Error;

    fn try_from(value: InputEncryptedAmount) -> Result<Self, Self::Error> {
        let agg_encrypted_amount = serde_json::from_str(&hex::encode(value.agg_encrypted_amount))?;
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
#[derive(Debug)]
pub struct SecToPubTransferData {
    pub serialized_remaining_amount: Bytes,
    pub transfer_amount: u64,
    pub index: u64,
    pub serialized_proof: Bytes,
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
            serialized_remaining_amount: Bytes::from(serialized_remaining_amount),
            transfer_amount: value.transfer_amount.micro_ccd,
            index: value.index.index,
            serialized_proof: Bytes::from(serialized_proof),
        }
    }
}

impl SecToPubTransferData {
    fn create(
        ctx: GlobalContext,
        sender_secret_key: String,
        input_amount: InputEncryptedAmount,
        to_transfer: u64,
    ) -> anyhow::Result<SecToPubTransferData> {
        let ctx = concordium_base::id::types::GlobalContext::try_from(ctx)?;
        let sk: concordium_base::elgamal::SecretKey<ArCurve> =
            serde_json::from_str(&sender_secret_key)
                .context("Failed to parse sender secret key")?;
        let input_amount = AggregatedDecryptedAmount::try_from(input_amount)
            .context("Failed to parse input amount")?;
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
        .context("Failed to create transfer data")?;

        Ok(transfer_data.into())
    }
}

pub struct DeserializeResult<V> {
    pub value: V,
    pub bytes_read: u64,
}

pub type SecToPubTransferDataDeserializeResult = DeserializeResult<SecToPubTransferData>;

/// Implements UDL definition of the same name.
pub fn sec_to_pub_transfer_data(
    ctx: GlobalContext,
    sender_secret_key: String,
    input_amount: InputEncryptedAmount,
    to_transfer: u64,
) -> Result<SecToPubTransferData, ConcordiumWalletCryptoError> {
    SecToPubTransferData::create(ctx, sender_secret_key, input_amount, to_transfer)
        .map_err(|e| e.to_call_failed("sec_to_pub_transfer_data(...)"))
}

/// Implements UDL definition of the same name.
/// Deserialize [`SecToPubTransferData`] from serialization format used by concordium nodes
pub fn deserialize_sec_to_pub_transfer_data(
    bytes: Vec<u8>,
) -> Result<DeserializeResult<SecToPubTransferData>, ConcordiumWalletCryptoError> {
    let fn_name = "deserialize_sec_to_pub_transfer_data";
    let mut bytes = std::io::Cursor::new(bytes);
    let transfer_data =
        SecToPubAmountTransferData::deserial(&mut bytes).map_err(|e| e.to_call_failed(fn_name))?;

    let result = DeserializeResult {
        value: transfer_data.into(),
        bytes_read: bytes.position(),
    };
    Ok(result)
}

type BaseCredentialDeploymentInfo =
    concordium_base::id::types::CredentialDeploymentInfo<IpPairing, ArCurve, AttributeKind>;

/// UniFFI compatible bridge to [`concordium_base::id::types::CredentialDeploymentInfo<concordium_base::id::constants::IpPairing,concordium_base::id::constants::ArCurve,concordium_base::id::constants::AttributeKind>`],
/// providing the implementation of the UDL declaration of the same name.
/// The translation is performed using Serde.
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialDeploymentInfo {
    pub ar_data: HashMap<u32, ChainArData>,
    pub cred_id: Bytes,
    pub credential_public_keys: CredentialPublicKeys,
    pub ip_identity: u32,
    pub policy: Policy,
    pub revocation_threshold: u8,
    pub proofs: Bytes,
}

impl TryFrom<CredentialDeploymentInfo> for BaseCredentialDeploymentInfo {
    type Error = serde_json::Error;

    fn try_from(value: CredentialDeploymentInfo) -> Result<Self, Self::Error> {
        serde_json::to_string(&value).and_then(|json| serde_json::from_str::<Self>(&json))
    }
}

impl TryFrom<BaseCredentialDeploymentInfo> for CredentialDeploymentInfo {
    type Error = serde_json::Error;

    fn try_from(value: BaseCredentialDeploymentInfo) -> Result<Self, Self::Error> {
        serde_json::to_string(&value).and_then(|json| serde_json::from_str::<Self>(&json))
    }
}

/// Implements UDL definition of the same name.
/// Serialize [`CredentialDeploymentInfo`] into serialization format used by concordium nodes
pub fn serialize_credential_deployment_info(
    cred_info: CredentialDeploymentInfo,
) -> Result<Vec<u8>, ConcordiumWalletCryptoError> {
    let fn_desc = "serialize_credential_deployment_info";
    let cred_info =
        BaseCredentialDeploymentInfo::try_from(cred_info).map_err(|e| e.to_call_failed(fn_desc))?;

    let mut bytes = vec![];
    cred_info.serial(&mut bytes);

    Ok(bytes)
}

/// UniFFI compatible bridge to [`concordium_base::transactions::Payload::UpdateCredentials`],
/// providing the implementation of the UDL declaration of the same name.
/// The translation is performed using Serde.
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateCredentialsPayload {
    /// New credentials to add.
    pub new_cred_infos: HashMap<u32, CredentialDeploymentInfo>,
    /// Ids of credentials to remove.
    pub remove_cred_ids: Vec<Bytes>,
    /// The new account threshold.
    pub new_threshold: u8,
}

impl
    TryFrom<(
        BTreeMap<CredentialIndex, BaseCredentialDeploymentInfo>,
        Vec<CredentialRegistrationID>,
        AccountThreshold,
    )> for UpdateCredentialsPayload
{
    type Error = serde_json::Error;

    fn try_from(
        (new_cred_infos, remove_cred_ids, new_threshold): (
            BTreeMap<CredentialIndex, BaseCredentialDeploymentInfo>,
            Vec<CredentialRegistrationID>,
            AccountThreshold,
        ),
    ) -> Result<Self, Self::Error> {
        let json = serde_json::json!({
            "newCredInfos": new_cred_infos,
            "removeCredIds": remove_cred_ids,
            "newThreshold": new_threshold
        });
        serde_json::from_value(json)
    }
}

pub type UpdateCredentialsPayloadDeserializeResult = DeserializeResult<UpdateCredentialsPayload>;

/// Implements UDL definition of the same name.
/// Deserialize [`UpdateCredentialsPayload`] from serialization format used by concordium nodes
pub fn deserialize_update_credentials_payload(
    bytes: Vec<u8>,
) -> Result<DeserializeResult<UpdateCredentialsPayload>, ConcordiumWalletCryptoError> {
    let fn_name = "deserialize_update_credentials_payload";

    let mut bytes = std::io::Cursor::new(bytes);
    let cred_infos =
        AccountCredentialsMap::deserial(&mut bytes).map_err(|e| e.to_call_failed(fn_name))?;
    let remove_cred_ids = Vec::<CredentialRegistrationID>::deserial(&mut bytes)
        .map_err(|e| e.to_call_failed(fn_name))?;
    let new_threshold =
        AccountThreshold::deserial(&mut bytes).map_err(|e| e.to_call_failed(fn_name))?;

    let payload = UpdateCredentialsPayload::try_from((cred_infos, remove_cred_ids, new_threshold))
        .map_err(|e| e.to_call_failed(fn_name))?;

    let result = DeserializeResult {
        value: payload,
        bytes_read: bytes.position(),
    };
    Ok(result)
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BakerKeyPairs {
    pub signature_sign: Bytes,
    pub signature_verify: Bytes,
    pub election_sign: Bytes,
    pub election_verify: Bytes,
    pub aggregation_sign: Bytes,
    pub aggregation_verify: Bytes,
}

impl TryFrom<BakerKeyPairs> for concordium_base::base::BakerKeyPairs {
    type Error = serde_json::Error;

    fn try_from(value: BakerKeyPairs) -> Result<Self, Self::Error> {
        serde_json::to_string(&value).and_then(|s| serde_json::from_str(&s))
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BakerKeysPayload {
    /// New public key for participating in the election lottery.
    pub election_verify_key: Bytes,
    /// New public key for verifying this baker's signatures.
    pub signature_verify_key: Bytes,
    /// New public key for verifying this baker's signature on finalization
    /// records.
    pub aggregation_verify_key: Bytes,
    /// Proof of knowledge of the secret key corresponding to the signature
    /// verification key.
    pub proof_sig: Bytes,
    /// Proof of knowledge of the election secret key.
    pub proof_election: Bytes,
    /// Proof of knowledge of the secret key for signing finalization
    /// records.
    pub proof_aggregation: Bytes,
}

impl TryFrom<ConfigureBakerKeysPayload> for BakerKeysPayload {
    type Error = serde_json::Error;

    fn try_from(value: ConfigureBakerKeysPayload) -> Result<Self, Self::Error> {
        serde_json::to_string(&value).and_then(|s| serde_json::from_str(&s))
    }
}

pub fn make_configure_baker_keys_payload(
    account_base58: String,
    baker_keys: BakerKeyPairs,
) -> Result<BakerKeysPayload, ConcordiumWalletCryptoError> {
    let fn_desc = "make_configure_baker_keys_payload(...)";
    let account = AccountAddress::from_str(&account_base58).map_err(|e| {
        ConcordiumWalletCryptoError::CallFailed {
            call: fn_desc.to_string(),
            msg: format!("{:#}", e),
        }
    })?;
    let baker_keys = concordium_base::base::BakerKeyPairs::try_from(baker_keys)
        .map_err(|e| e.to_call_failed(fn_desc))?;
    let mut csprng = thread_rng();
    let payload = ConfigureBakerKeysPayload::new(&baker_keys, account, &mut csprng);
    payload
        .try_into()
        .map_err(|e: serde_json::Error| e.to_call_failed(fn_desc))
}
