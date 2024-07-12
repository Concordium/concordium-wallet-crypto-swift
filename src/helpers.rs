//
// pub fn serialize_bytes_list_hex<S: serde::Serializer>(bytes_list: &[Vec<u8>], serializer: S) -> Result<S::Ok, S::Error> {
//     let mut seq = serializer.serialize_seq(Some(bytes_list.len()))?;
//     for bytes in bytes_list {
//         seq.serialize_element(&hex::encode(bytes))?
//     }
//     seq.end()
// }
//
// pub fn deserialize_hex_list_bytes<'de, D: serde::Deserializer<'de>>(des: D) -> Result<Vec<Vec<u8>>, D::Error> {
//     des.deserialize_seq(visitor)
// }

use serde::{Deserialize, Serialize};

use crate::UniffiCustomTypeConverter;

#[repr(transparent)]
#[derive(Debug, Serialize, Deserialize, derive_more::From)]
pub struct Bytes(#[serde(with = "hex")] Vec<u8>);

impl AsRef<[u8]> for Bytes {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl UniffiCustomTypeConverter for Bytes {
    type Builtin = Vec<u8>;

    fn into_custom(val: Self::Builtin) -> uniffi::Result<Self>
    where
        Self: Sized,
    {
        Ok(Bytes(val))
    }

    fn from_custom(obj: Self) -> Self::Builtin {
        obj.0
    }
}
