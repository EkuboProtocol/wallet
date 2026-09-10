//! Key material supplied by the owner for import, never a service export.
//! Owned input is erased on drop and diagnostics never render its contents.
//! IPC libraries may retain their own message buffers; this is not a guarantee
//! that every transport copy is erased.

use ekubo_wallet_core::custody::PrivateKeyMaterial;
use serde::{Deserialize, Deserializer, Serialize, Serializer, de};
use zeroize::Zeroizing;

pub struct ImportKey(Zeroizing<String>);

impl ImportKey {
    pub fn from_hex(value: String) -> anyhow::Result<Self> {
        let value = Zeroizing::new(value);
        PrivateKeyMaterial::from_hex(&value)
            .map_err(|_| anyhow::anyhow!("invalid account import key"))?;
        Ok(Self(value))
    }

    pub fn into_material(self) -> anyhow::Result<PrivateKeyMaterial> {
        PrivateKeyMaterial::from_hex(&self.0)
            .map_err(|_| anyhow::anyhow!("invalid account import key"))
    }
}

impl std::fmt::Debug for ImportKey {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ImportKey([REDACTED])")
    }
}

impl Serialize for ImportKey {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for ImportKey {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct KeyVisitor;
        impl de::Visitor<'_> for KeyVisitor {
            type Value = ImportKey;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("an account import key")
            }

            fn visit_str<E: de::Error>(self, value: &str) -> Result<Self::Value, E> {
                // Bound allocation before copying a borrowed transport string.
                if !matches!(value.len(), 64 | 66) {
                    return Err(E::custom("invalid account import key"));
                }
                self.visit_string(value.to_owned())
            }

            fn visit_string<E: de::Error>(self, value: String) -> Result<Self::Value, E> {
                ImportKey::from_hex(value).map_err(|_| E::custom("invalid account import key"))
            }
        }
        deserializer.deserialize_str(KeyVisitor)
    }
}

#[cfg(test)]
#[path = "import_key_test.rs"]
mod tests;
