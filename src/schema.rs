use concordium_base::contracts_common::{
    from_bytes,
    schema::{Type, VersionedModuleSchema, VersionedSchemaError},
    to_bytes, Cursor,
};
use derive_more::From;
use serde_json::Value;

use crate::{ConcordiumWalletCryptoError, ConvertError};

#[repr(u8)]
pub enum ModuleSchemaVersion {
    V0,
    V1,
    V2,
    V3,
}

pub struct ModuleSchema {
    pub value: Vec<u8>,
    pub version: Option<ModuleSchemaVersion>,
}

impl TryFrom<ModuleSchema> for VersionedModuleSchema {
    type Error = VersionedSchemaError;

    fn try_from(value: ModuleSchema) -> Result<Self, Self::Error> {
        VersionedModuleSchema::new(&value.value, &value.version.map(|v| v as u8))
    }
}

#[derive(From)]
pub struct TypeSchema {
    pub value: Vec<u8>,
}

pub fn deserialize_type_value(
    value: Vec<u8>,
    schema: TypeSchema,
) -> Result<String, ConcordiumWalletCryptoError> {
    let value_type: Type = from_bytes(&schema.value)
        .map_err(|e| e.to_call_failed("deserialize_type_value".to_string()))?;
    let mut cursor = Cursor::new(value);
    let json = value_type
        .to_json(&mut cursor)
        .map_err(|e| e.to_call_failed("deserialize_type_value".to_string()))?;
    serde_json::to_string(&json).map_err(|e| e.to_call_failed("deserialize_type_value".to_string()))
}

pub fn serialize_type_value(
    json: String,
    schema: TypeSchema,
) -> Result<Vec<u8>, ConcordiumWalletCryptoError> {
    let value_type: Type = from_bytes(&schema.value)
        .map_err(|e| e.to_call_failed("deserialize_type_value".to_string()))?;
    let json: Value = serde_json::from_str(&json)
        .map_err(|e| e.to_call_failed("deserialize_type_value".to_string()))?;
    value_type
        .serial_value(&json)
        .map_err(|e| e.to_call_failed("deserialize_type_value".to_string()))
}

pub fn get_receive_parameter_schema(
    schema: ModuleSchema,
    contract_name: String,
    function_name: String,
) -> Result<TypeSchema, ConcordiumWalletCryptoError> {
    let fn_desc = format!(
        "get_receive_parameter_schema(schema = ..., contract_name = {}, function_name = {})",
        contract_name, function_name
    );
    let module_schema =
        VersionedModuleSchema::try_from(schema).map_err(|e| e.to_call_failed(fn_desc.clone()))?;
    let schema = module_schema
        .get_receive_param_schema(&contract_name, &function_name)
        .map_err(|e| e.to_call_failed(fn_desc.clone()))?;
    Ok(to_bytes(&schema).into())
}
pub fn get_receive_return_value_schema(
    schema: ModuleSchema,
    contract_name: String,
    function_name: String,
) -> Result<TypeSchema, ConcordiumWalletCryptoError> {
    let fn_desc = format!(
        "get_receive_return_value_schema(schema = ..., contract_name = {}, function_name = {})",
        contract_name, function_name
    );
    let module_schema =
        VersionedModuleSchema::try_from(schema).map_err(|e| e.to_call_failed(fn_desc.clone()))?;
    let schema = module_schema
        .get_receive_return_value_schema(&contract_name, &function_name)
        .map_err(|e| e.to_call_failed(fn_desc.clone()))?;
    Ok(to_bytes(&schema).into())
}
pub fn get_receive_error_schema(
    schema: ModuleSchema,
    contract_name: String,
    function_name: String,
) -> Result<TypeSchema, ConcordiumWalletCryptoError> {
    let fn_desc = format!(
        "get_receive_error_schema(schema = ..., contract_name = {}, function_name = {})",
        contract_name, function_name
    );
    let module_schema =
        VersionedModuleSchema::try_from(schema).map_err(|e| e.to_call_failed(fn_desc.clone()))?;
    let schema = module_schema
        .get_receive_error_schema(&contract_name, &function_name)
        .map_err(|e| e.to_call_failed(fn_desc.clone()))?;
    Ok(to_bytes(&schema).into())
}
pub fn get_init_parameter_schema(
    schema: ModuleSchema,
    contract_name: String,
) -> Result<TypeSchema, ConcordiumWalletCryptoError> {
    let fn_desc = format!(
        "get_init_parameter_schema(schema = ..., contract_name = {})",
        contract_name
    );
    let module_schema =
        VersionedModuleSchema::try_from(schema).map_err(|e| e.to_call_failed(fn_desc.clone()))?;
    let schema = module_schema
        .get_init_param_schema(&contract_name)
        .map_err(|e| e.to_call_failed(fn_desc.clone()))?;
    Ok(to_bytes(&schema).into())
}
pub fn get_init_error_schema(
    schema: ModuleSchema,
    contract_name: String,
) -> Result<TypeSchema, ConcordiumWalletCryptoError> {
    let fn_desc = format!(
        "get_init_error_schema(schema = ..., contract_name = {})",
        contract_name
    );
    let module_schema =
        VersionedModuleSchema::try_from(schema).map_err(|e| e.to_call_failed(fn_desc.clone()))?;
    let schema = module_schema
        .get_init_error_schema(&contract_name)
        .map_err(|e| e.to_call_failed(fn_desc.clone()))?;
    Ok(to_bytes(&schema).into())
}
