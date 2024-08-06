use std::{
    collections::{BTreeMap, HashMap},
    str::FromStr,
};

use concordium_base::{
    base::{AccountThreshold, CredentialRegistrationID},
    common::{
        deserial_map_no_length, deserial_vector_no_length, types::CredentialIndex, Deserial, Get,
        Serial,
    },
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
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SecToPubTransferData {
    /// Serialized according to the [`Serial`] implementation of [`concordium_base::encrypted_transfers::types::EncryptedAmount`]
    pub remaining_amount: Bytes,
    /// In microCCD. For historic resons, amounts are serialized as strings
    pub transfer_amount: String,
    pub index: u64,
    /// Serialized according to the [`Serial`] implementation of [`concordium_base::encrypted_transfers::types::SecToPubAmountTransferProof`]
    pub proof: Bytes,
}

impl TryFrom<SecToPubTransferData> for SecToPubAmountTransferData<ArCurve> {
    type Error = serde_json::Error;

    fn try_from(value: SecToPubTransferData) -> Result<Self, Self::Error> {
        serde_json::to_string(&value).and_then(|json| serde_json::from_str::<Self>(&json))
    }
}

impl TryFrom<SecToPubAmountTransferData<ArCurve>> for SecToPubTransferData {
    type Error = serde_json::Error;

    fn try_from(value: SecToPubAmountTransferData<ArCurve>) -> Result<Self, Self::Error> {
        serde_json::to_string(&value).and_then(|json| serde_json::from_str::<Self>(&json))
    }
}

impl SecToPubTransferData {
    fn create(
        ctx: GlobalContext,
        sender_secret_key: Bytes,
        input_amount: InputEncryptedAmount,
        to_transfer: u64, // In microCCD
    ) -> anyhow::Result<SecToPubTransferData> {
        let ctx = concordium_base::id::types::GlobalContext::try_from(ctx)?;
        let sk: concordium_base::elgamal::SecretKey<ArCurve> =
            serde_json::to_string(&sender_secret_key)
                .and_then(|v| serde_json::from_str(&v))
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

        Ok(transfer_data.try_into()?)
    }
}

/// Used to communicate how many bytes were read during deserialization of the value `V`, which can then be used as part of deserializing an encompassing structure
pub struct DeserializeResult<V> {
    pub value: V,
    pub bytes_read: u64,
}

pub type SecToPubTransferDataDeserializeResult = DeserializeResult<SecToPubTransferData>;

/// Implements UDL definition of the same name.
pub fn sec_to_pub_transfer_data(
    ctx: GlobalContext,
    sender_secret_key: Bytes,
    input_amount: InputEncryptedAmount,
    to_transfer: u64, // In microCCD
) -> Result<SecToPubTransferData, ConcordiumWalletCryptoError> {
    SecToPubTransferData::create(ctx, sender_secret_key, input_amount, to_transfer)
        .map_err(|e| e.to_call_failed("sec_to_pub_transfer_data(...)".to_string()))
}

/// Implements UDL definition of the same name.
/// Deserialize [`SecToPubTransferData`] from serialization format used by concordium nodes
pub fn deserialize_sec_to_pub_transfer_data(
    bytes: Vec<u8>,
) -> Result<DeserializeResult<SecToPubTransferData>, ConcordiumWalletCryptoError> {
    let fn_name = "deserialize_sec_to_pub_transfer_data";
    let mut bytes = std::io::Cursor::new(bytes);
    let transfer_data = SecToPubAmountTransferData::deserial(&mut bytes)
        .map_err(|e| e.to_call_failed(fn_name.to_string()))?;
    let transfer_data = SecToPubTransferData::try_from(transfer_data)
        .map_err(|e| e.to_call_failed(fn_name.to_string()))?;

    let result = DeserializeResult {
        value: transfer_data,
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
    /// Serialized proofs according to the [`serde::Serialize`] implementation of [`concordium_base::id::types::CredDeploymentProofs<concordium_base::id::constants::IpPairing,concordium_base::id::constants::ArCurve>`]
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
    let fn_name = "serialize_credential_deployment_info";
    let cred_info = BaseCredentialDeploymentInfo::try_from(cred_info)
        .map_err(|e| e.to_call_failed(fn_name.to_string()))?;

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
    pub new_cred_infos: HashMap<u8, CredentialDeploymentInfo>,
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

    let cred_infos_len: u8 = bytes
        .get()
        .map_err(|e| e.to_call_failed(fn_name.to_string()))?;
    let cred_infos: AccountCredentialsMap =
        deserial_map_no_length(&mut bytes, cred_infos_len.into())
            .map_err(|e| e.to_call_failed(fn_name.to_string()))?;

    let remove_cred_ids_len: u8 = bytes
        .get()
        .map_err(|e| e.to_call_failed(fn_name.to_string()))?;
    let remove_cred_ids = deserial_vector_no_length(&mut bytes, remove_cred_ids_len.into())
        .map_err(|e| e.to_call_failed(fn_name.to_string()))?;

    let new_threshold = AccountThreshold::deserial(&mut bytes)
        .map_err(|e| e.to_call_failed(fn_name.to_string()))?;

    let payload = UpdateCredentialsPayload::try_from((cred_infos, remove_cred_ids, new_threshold))
        .map_err(|e| e.to_call_failed(fn_name.to_string()))?;

    let result = DeserializeResult {
        value: payload,
        bytes_read: bytes.position(),
    };
    Ok(result)
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
    let fn_desc = format!("make_configure_baker_keys_payload(account_base58={account_base58}, baker_keys={baker_keys:?})");
    let account =
        AccountAddress::from_str(&account_base58).map_err(|e| e.to_call_failed(fn_desc.clone()))?;
    let baker_keys = concordium_base::base::BakerKeyPairs::try_from(baker_keys)
        .map_err(|e| e.to_call_failed(fn_desc.clone()))?;
    let mut csprng = thread_rng();
    let payload = ConfigureBakerKeysPayload::new(&baker_keys, account, &mut csprng);
    payload
        .try_into()
        .map_err(|e: serde_json::Error| e.to_call_failed(fn_desc))
}
