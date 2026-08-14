//! The pairing URI a dapp shows as a QR code or a "copy to clipboard" button.
//!
//! This is the one piece of the protocol a person handles directly, so it is
//! also the one place where a mistake is a typo rather than a bug: a truncated
//! paste, a URI copied from a different dapp, or one that expired while the
//! user was returning to the wallet. Each of those gets its own
//! sentence, because "invalid URI" sends someone to re-copy a URI that was
//! never going to work.
//!
//! The symmetric key is in the URI itself. That is by design — the QR code
//! *is* the key exchange — and it is why a pairing URI is a secret: anyone who
//! reads it can impersonate the dapp for the length of the pairing. Nothing
//! here ever logs one.

use super::crypto::SymKey;
use anyhow::{Context, Result, bail, ensure};
use chrono::{DateTime, Utc};
use url::Url;
use zeroize::Zeroizing;

/// The only relay protocol this wallet speaks.
pub const RELAY_PROTOCOL_IRN: &str = "irn";
/// Pairing links contain two 32-byte hex values plus a handful of routing
/// fields. Keep an intentionally generous ceiling, applied before URL
/// decoding allocates attacker-controlled query values.
const MAX_PAIRING_URI_BYTES: usize = 4 * 1024;

/// A parsed `wc:` pairing URI.
#[derive(Debug)]
pub struct PairingUri {
    /// The relay topic the dapp is listening on for the proposal response.
    pub topic: String,
    /// The key both sides already share, straight out of the URI.
    pub sym_key: SymKey,
    /// Which relay protocol the dapp asked for; always `irn` in practice.
    pub relay_protocol: String,
    /// Optional relay routing data, passed back to the dapp verbatim in every
    /// `relay` object so a relay that uses it keeps working.
    pub relay_data: Option<String>,
    /// When the dapp says this pairing stops being valid.
    pub expiry: Option<DateTime<Utc>>,
}

impl PairingUri {
    /// Parse and validate a pasted URI.
    ///
    /// `now` is passed in rather than read here so that expiry has one
    /// definition and the tests can reach it.
    pub fn parse(input: &str, now: DateTime<Utc>) -> Result<Self> {
        let input = input.trim();
        ensure!(!input.is_empty(), "no pairing URI was given");
        ensure!(
            input.len() <= MAX_PAIRING_URI_BYTES,
            "the pairing URI exceeds {MAX_PAIRING_URI_BYTES} bytes"
        );
        ensure!(
            input.starts_with("wc:"),
            "a WalletConnect pairing URI starts with `wc:`. Copy the link from the dapp's \
             \"connect wallet\" dialog — the QR code and the copy button carry the same URI."
        );
        let url = Url::parse(input).context("the pairing URI is not a valid URI")?;

        // `wc:<topic>@<version>` lands entirely in the path for a scheme with
        // no authority, so the split happens here rather than in the URL crate.
        let path = url.path();
        let (topic, version) = path
            .split_once('@')
            .context("the pairing URI is missing its `@version` suffix, so it is truncated")?;
        ensure!(
            version == "2",
            "this is a WalletConnect v{version} URI, and this wallet speaks v2. Reconnect from a \
             dapp that offers WalletConnect v2."
        );
        ensure!(
            topic.len() == 64 && topic.bytes().all(|byte| byte.is_ascii_hexdigit()),
            "the pairing topic is not 64 hex characters, so the URI was truncated or edited"
        );

        let mut sym_key = None;
        let mut relay_protocol = None;
        let mut relay_data = None;
        let mut expiry_timestamp = None;
        for (name, value) in url.query_pairs() {
            match name.as_ref() {
                "symKey" => sym_key = Some(value.into_owned()),
                "relay-protocol" => relay_protocol = Some(value.into_owned()),
                "relay-data" => relay_data = Some(value.into_owned()),
                "expiryTimestamp" => expiry_timestamp = Some(value.into_owned()),
                // `methods` and anything a later revision adds are ignored
                // rather than refused: an unknown query parameter is how this
                // protocol has always carried forward-compatible hints, and
                // refusing them would break pairing against newer dapps for no
                // security gain. Nothing unknown is acted on.
                _ => {}
            }
        }

        let sym_key = Zeroizing::new(sym_key.context(
            "the pairing URI carries no symKey, so there is no key to encrypt the session with. \
             The URI was probably truncated when it was copied.",
        )?);
        let sym_key = SymKey::from_hex(&sym_key)?;

        let relay_protocol = relay_protocol.unwrap_or_else(|| RELAY_PROTOCOL_IRN.to_owned());
        ensure!(
            relay_protocol == RELAY_PROTOCOL_IRN,
            "the dapp asked for the `{relay_protocol}` relay protocol, and this wallet implements \
             only `{RELAY_PROTOCOL_IRN}`."
        );

        let expiry = match expiry_timestamp {
            None => None,
            Some(timestamp) => {
                let seconds: i64 = timestamp
                    .parse()
                    .context("the pairing URI's expiryTimestamp is not a number")?;
                let expiry = DateTime::from_timestamp(seconds, 0)
                    .context("the pairing URI's expiryTimestamp is not a valid time")?;
                if expiry <= now {
                    bail!(
                        "this pairing URI expired at {expiry}. Pairing URIs are short-lived: go \
                         back to the dapp, ask it to connect again, and paste the new one."
                    );
                }
                Some(expiry)
            }
        };

        Ok(Self {
            topic: topic.to_ascii_lowercase(),
            sym_key,
            relay_protocol,
            relay_data,
            expiry,
        })
    }
}

#[cfg(test)]
#[path = "uri_test.rs"]
mod tests;
