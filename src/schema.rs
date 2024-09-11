use concordium_base::contracts_common::{
    from_bytes,
    schema::{Type, VersionedModuleSchema, VersionedSchemaError},
    schema_json, to_bytes, Cursor, ParseError,
};
use derive_more::From;
use serde_json::Value;

/// Error type returned by the bridge functions.
/// A corresponding Swift type will be generated (via the UDL definition).
#[derive(Debug, thiserror::Error)]
pub enum SchemaError {
    /// Failed to convert with schema
    #[error("{0}")]
    Convert(String),
    /// Failed to parse the versioned module schema
    #[error("{0}")]
    ParseSchema(String),
}

impl From<schema_json::ToJsonError> for SchemaError {
    fn from(value: schema_json::ToJsonError) -> Self {
        Self::Convert(format!("{}", value))
    }
}

impl From<schema_json::JsonError> for SchemaError {
    fn from(value: schema_json::JsonError) -> Self {
        Self::Convert(format!("{}", value))
    }
}

impl From<VersionedSchemaError> for SchemaError {
    fn from(value: VersionedSchemaError) -> Self {
        Self::ParseSchema(format!("{}", value))
    }
}

impl From<ParseError> for SchemaError {
    fn from(value: ParseError) -> Self {
        Self::ParseSchema(format!("{}", value))
    }
}

impl From<serde_json::Error> for SchemaError {
    fn from(value: serde_json::Error) -> Self {
        Self::Convert(format!("{}", value))
    }
}

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

pub fn display_type_schema_template(schema: TypeSchema) -> Result<String, SchemaError> {
    let value_type: Type = from_bytes(&schema.value)?;
    let template = value_type.to_json_template();
    Ok(serde_json::to_string(&template)?)
}

pub fn deserialize_type_value(value: Vec<u8>, schema: TypeSchema) -> Result<String, SchemaError> {
    let value_type: Type = from_bytes(&schema.value)?;
    let mut cursor = Cursor::new(value);
    let json = value_type.to_json(&mut cursor)?;
    Ok(serde_json::to_string(&json)?)
}

pub fn serialize_type_value(json: String, schema: TypeSchema) -> Result<Vec<u8>, SchemaError> {
    let value_type: Type = from_bytes(&schema.value)?;
    let json: Value = serde_json::from_str(&json)?;
    Ok(value_type.serial_value(&json)?)
}

pub fn get_receive_parameter_schema(
    schema: ModuleSchema,
    contract_name: String,
    function_name: String,
) -> Result<TypeSchema, SchemaError> {
    let module_schema = VersionedModuleSchema::try_from(schema)?;
    let schema = module_schema.get_receive_param_schema(&contract_name, &function_name)?;
    Ok(to_bytes(&schema).into())
}
pub fn get_receive_return_value_schema(
    schema: ModuleSchema,
    contract_name: String,
    function_name: String,
) -> Result<TypeSchema, SchemaError> {
    let module_schema = VersionedModuleSchema::try_from(schema)?;
    let schema = module_schema.get_receive_return_value_schema(&contract_name, &function_name)?;
    Ok(to_bytes(&schema).into())
}
pub fn get_receive_error_schema(
    schema: ModuleSchema,
    contract_name: String,
    function_name: String,
) -> Result<TypeSchema, SchemaError> {
    let module_schema = VersionedModuleSchema::try_from(schema)?;
    let schema = module_schema.get_receive_error_schema(&contract_name, &function_name)?;
    Ok(to_bytes(&schema).into())
}
pub fn get_init_parameter_schema(
    schema: ModuleSchema,
    contract_name: String,
) -> Result<TypeSchema, SchemaError> {
    let module_schema = VersionedModuleSchema::try_from(schema)?;
    let schema = module_schema.get_init_param_schema(&contract_name)?;
    Ok(to_bytes(&schema).into())
}
pub fn get_init_error_schema(
    schema: ModuleSchema,
    contract_name: String,
) -> Result<TypeSchema, SchemaError> {
    let module_schema = VersionedModuleSchema::try_from(schema)?;
    let schema = module_schema.get_init_error_schema(&contract_name)?;
    Ok(to_bytes(&schema).into())
}
