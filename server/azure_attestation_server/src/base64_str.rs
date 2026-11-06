use base64::prelude::*;

use serde::{Deserialize, Serialize};
use serde::{Deserializer, Serializer};

pub fn serialize<S: Serializer>(v: &String, s: S) -> Result<S::Ok, S::Error> {
    let base64 = BASE64_STANDARD.encode(v);
    String::serialize(&base64, s)
}

pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<String, D::Error> {
    let base64 = String::deserialize(d)?;
    let bytes = BASE64_STANDARD
        .decode(base64.as_bytes())
        .map_err(|e| serde::de::Error::custom(e))?;
    String::from_utf8(bytes).map_err(|e| serde::de::Error::custom(e))
}
