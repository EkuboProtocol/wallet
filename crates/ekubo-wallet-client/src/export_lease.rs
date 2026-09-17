//! An explicitly authenticated export held for the existing reveal window.
//! Expiry governs UI visibility; it cannot revoke bytes already delivered.

use std::{
    sync::Mutex,
    time::{Duration, Instant},
};

pub const PRIVATE_KEY_REVEAL_DURATION: Duration = Duration::from_secs(30);

pub struct ExportLease {
    value: Mutex<zeroize::Zeroizing<String>>,
    expires_at: Instant,
}

impl serde::Serialize for ExportLease {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct as _;
        use zeroize::Zeroize as _;
        let mut value = self
            .value
            .lock()
            .map_err(|_| serde::ser::Error::custom("export lease is unavailable"))?;
        let remaining_ms = self
            .expires_at
            .saturating_duration_since(Instant::now())
            .as_millis();
        if remaining_ms == 0 {
            value.zeroize();
        }
        let mut record = serializer.serialize_struct("ExportLease", 2)?;
        record.serialize_field("value", value.as_str())?;
        record.serialize_field(
            "remaining_ms",
            &if value.is_empty() { 0 } else { remaining_ms },
        )?;
        record.end()
    }
}

impl<'de> serde::Deserialize<'de> for ExportLease {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Reply {
            value: zeroize::Zeroizing<String>,
            remaining_ms: u64,
        }
        let reply = Reply::deserialize(deserializer)?;
        if u128::from(reply.remaining_ms) > PRIVATE_KEY_REVEAL_DURATION.as_millis()
            || (reply.remaining_ms == 0) != reply.value.is_empty()
        {
            return Err(serde::de::Error::custom("invalid export reveal window"));
        }
        if !reply.value.is_empty() {
            ekubo_wallet_core::custody::PrivateKeyMaterial::from_hex(&reply.value)
                .map_err(|_| serde::de::Error::custom("invalid exported key"))?;
        }
        // Start the remaining display interval on receipt. It is not an
        // authorization token and cannot be used to request another export.
        Ok(Self::new_for_duration(
            reply.value,
            Duration::from_millis(reply.remaining_ms),
        ))
    }
}

impl ExportLease {
    #[must_use]
    pub fn new(value: zeroize::Zeroizing<String>) -> Self {
        Self::new_for_duration(value, PRIVATE_KEY_REVEAL_DURATION)
    }

    fn new_for_duration(value: zeroize::Zeroizing<String>, duration: Duration) -> Self {
        Self {
            value: Mutex::new(value),
            expires_at: Instant::now() + duration,
        }
    }

    #[must_use]
    pub fn concealed(&self) -> bool {
        self.value.lock().map_or(true, |mut value| {
            if Instant::now() >= self.expires_at {
                use zeroize::Zeroize as _;
                value.zeroize();
            }
            value.is_empty()
        })
    }

    /// How much longer the key stays visible. A reveal that vanishes without
    /// warning reads as a bug; a countdown makes the deadline the user's to
    /// plan around.
    #[must_use]
    pub fn remaining(&self) -> Duration {
        if self.concealed() {
            return Duration::ZERO;
        }
        self.expires_at.saturating_duration_since(Instant::now())
    }

    #[must_use]
    pub fn visible_value(&self) -> Option<zeroize::Zeroizing<String>> {
        self.value.lock().ok().and_then(|mut value| {
            if Instant::now() >= self.expires_at {
                use zeroize::Zeroize as _;
                value.zeroize();
            }
            (!value.is_empty()).then(|| zeroize::Zeroizing::new(value.to_string()))
        })
    }
}

#[cfg(test)]
#[path = "export_lease_test.rs"]
mod tests;
