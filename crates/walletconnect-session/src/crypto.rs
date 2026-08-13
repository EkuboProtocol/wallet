//! The `WalletConnect` v2 cryptography, as the reference client defines it.
//!
//! Every constant here is a wire format rather than a choice: a payload this
//! module seals is opened by a dapp running the JavaScript SDK, so "what the
//! reference implementation does" is the specification and any deviation shows
//! up as a session that silently never connects. The three things worth
//! stating, because a reader would otherwise have to go and find them:
//!
//! * the symmetric key is HKDF-SHA256 over the raw X25519 shared secret with
//!   *no salt and no info*, expanded to 32 bytes;
//! * a topic is the lowercase hex SHA-256 of the key's raw bytes, not of its
//!   hex spelling;
//! * envelopes are **padded** standard base64 (`base64pad` in the reference
//!   client's encoding vocabulary), not the URL alphabet and not unpadded.
//!
//! Nothing here consults wallet state or touches a private signing key. This
//! is transport confidentiality between two peers that already agreed on a key
//! out of band; it authorizes nothing on its own, and every request that
//! arrives through it is treated as hostile input by the layers above.

use anyhow::{Context, Result, bail, ensure};
use base64::Engine as _;
use chacha20poly1305::{
    ChaCha20Poly1305, KeyInit,
    aead::{Aead, Payload},
};
use hkdf::Hkdf;
use rand::TryRng as _;
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Symmetric key length, and also the X25519 public key length.
pub const KEY_LENGTH: usize = 32;
/// ChaCha20-Poly1305 nonce length.
const IV_LENGTH: usize = 12;
/// Poly1305 authentication tag length.
const TAG_LENGTH: usize = 16;

const ENVELOPE_TYPE_0: u8 = 0;
const ENVELOPE_TYPE_1: u8 = 1;

/// The reference client's `base64pad`: the standard alphabet, with padding.
const BASE64: base64::engine::general_purpose::GeneralPurpose =
    base64::engine::general_purpose::STANDARD;
/// JWT segments use the URL alphabet without padding, as JWTs always do.
const BASE64URL: base64::engine::general_purpose::GeneralPurpose =
    base64::engine::general_purpose::URL_SAFE_NO_PAD;

/// A sealed envelope no larger than this is refused before any allocation.
///
/// The relay will deliver whatever a peer publishes, and a decrypted payload
/// becomes a `serde_json` parse. One megabyte is far beyond any legitimate
/// session request — the largest realistic one is a typed-data payload — and
/// well under anything that would matter for memory.
pub(super) const MAX_ENVELOPE_BYTES: usize = 1024 * 1024;

/// Fill a buffer from the platform CSPRNG, or fail loudly.
///
/// A silent fallback to a weaker source is the one outcome that must not
/// happen: every byte this produces is either a secret key or a nonce, and
/// both are load-bearing.
fn random_bytes(buffer: &mut [u8]) -> Result<()> {
    rand::rng()
        .try_fill_bytes(buffer)
        .map_err(|error| anyhow::anyhow!("the platform random number generator failed: {error}"))
}

/// A 32-byte symmetric key shared with exactly one peer.
///
/// Wrapped rather than passed as a bare array so that it zeroizes on drop and
/// so that a topic can only be derived from something that really is a key.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SymKey([u8; KEY_LENGTH]);

/// Deliberately not derived. A derived `Debug` would print live key material
/// into whatever a caller formatted the containing value with — an error
/// message, a log line, a panic — and every type that holds one would inherit
/// the leak.
impl std::fmt::Debug for SymKey {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("SymKey(<redacted>)")
    }
}

impl SymKey {
    /// The key a pairing URI carried, as lowercase hex.
    pub fn from_hex(value: &str) -> Result<Self> {
        let bytes = hex::decode(value).context("symmetric key must be hex")?;
        let bytes: [u8; KEY_LENGTH] = bytes
            .try_into()
            .map_err(|_| anyhow::anyhow!("symmetric key must be {KEY_LENGTH} bytes"))?;
        // An all-zero key is not a key. It is what a peer sends when its own
        // key derivation silently failed, and accepting it would mean
        // "encrypting" every later payload under a value the whole world knows.
        ensure!(
            bytes != [0u8; KEY_LENGTH],
            "symmetric key is all zero, which is never a real key"
        );
        Ok(Self(bytes))
    }

    /// The relay topic this key addresses: hex of the SHA-256 of its raw
    /// bytes. Deriving it from the hex spelling instead is the classic way to
    /// end up subscribed to a topic nobody publishes to.
    #[must_use]
    pub fn topic(&self) -> String {
        hex::encode(Sha256::digest(self.0))
    }
}

/// One X25519 key pair, used for exactly one session handshake.
///
/// The secret never leaves this type and zeroizes on drop. It is unrelated to
/// the wallet's signing key: it establishes a transport secret with a dapp and
/// can authorize nothing.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct KeyAgreement {
    secret: [u8; KEY_LENGTH],
}

impl std::fmt::Debug for KeyAgreement {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("KeyAgreement(<redacted>)")
    }
}

impl KeyAgreement {
    /// A fresh key pair from the platform CSPRNG.
    pub fn generate() -> Result<Self> {
        let mut secret = [0u8; KEY_LENGTH];
        random_bytes(&mut secret)?;
        Ok(Self { secret })
    }

    /// The public key to hand the peer, as lowercase hex — the spelling every
    /// field in the protocol uses.
    #[must_use]
    pub fn public_key_hex(&self) -> String {
        hex::encode(x25519_dalek::x25519(
            self.secret,
            x25519_dalek::X25519_BASEPOINT_BYTES,
        ))
    }

    /// The session key shared with `peer_public_key_hex`.
    ///
    /// The all-zero check is the low-order-point guard: a peer that sends one
    /// of the small-order X25519 points forces the shared secret to zero
    /// regardless of this side's secret, which would let it fix the session key
    /// without knowing anything. `x25519` clamps the scalar itself.
    pub fn derive(&self, peer_public_key_hex: &str) -> Result<SymKey> {
        let peer = hex::decode(peer_public_key_hex).context("peer public key must be hex")?;
        let peer: [u8; KEY_LENGTH] = peer
            .try_into()
            .map_err(|_| anyhow::anyhow!("peer public key must be {KEY_LENGTH} bytes"))?;
        let mut shared = x25519_dalek::x25519(self.secret, peer);
        ensure!(
            shared != [0u8; KEY_LENGTH],
            "peer public key is a low-order point, so the shared secret would be a constant"
        );
        // HKDF-SHA256 with no salt and no info, expanded to 32 bytes. The
        // reference client passes neither, and RFC 5869 defines an absent salt
        // as HashLen zero bytes, which is exactly what `None` means here.
        let hkdf = Hkdf::<Sha256>::new(None, &shared);
        let mut key = [0u8; KEY_LENGTH];
        let expanded = hkdf.expand(&[], &mut key);
        shared.zeroize();
        expanded.map_err(|error| anyhow::anyhow!("session key derivation failed: {error}"))?;
        Ok(SymKey(key))
    }
}

/// A decoded typed envelope.
///
/// Kept as a type of its own so that the sender public key a type 1 envelope
/// carries is reachable without decrypting, which is the order the protocol
/// needs it in: that key is what the receiver derives the opening key from.
#[derive(Debug)]
pub enum Envelope {
    /// Both peers already share a key.
    Type0 {
        iv: [u8; IV_LENGTH],
        sealed: Vec<u8>,
    },
    /// The sender included its public key because the receiver does not have
    /// it yet and must run the key agreement to open this.
    Type1 {
        sender_public_key: [u8; KEY_LENGTH],
        iv: [u8; IV_LENGTH],
        sealed: Vec<u8>,
    },
}

impl Envelope {
    /// Parse a relay message.
    ///
    /// Every length is checked before it is used as an index: this is
    /// attacker-supplied text off a public relay, and a truncated envelope is
    /// the cheapest thing in the world to send.
    pub fn decode(message: &str) -> Result<Self> {
        ensure!(
            message.len() <= MAX_ENVELOPE_BYTES,
            "relay message is larger than {MAX_ENVELOPE_BYTES} bytes"
        );
        let bytes = BASE64
            .decode(message)
            .context("relay message is not valid base64")?;
        let (&envelope_type, rest) = bytes
            .split_first()
            .context("relay message is empty, so it carries no envelope type")?;
        match envelope_type {
            ENVELOPE_TYPE_0 => {
                let (iv, sealed) = split_iv(rest)?;
                Ok(Self::Type0 { iv, sealed })
            }
            ENVELOPE_TYPE_1 => {
                ensure!(
                    rest.len() > KEY_LENGTH,
                    "type 1 envelope is too short to hold a sender public key"
                );
                let (public_key, rest) = rest.split_at(KEY_LENGTH);
                let sender_public_key: [u8; KEY_LENGTH] =
                    public_key.try_into().expect("split at KEY_LENGTH");
                let (iv, sealed) = split_iv(rest)?;
                Ok(Self::Type1 {
                    sender_public_key,
                    iv,
                    sealed,
                })
            }
            // Type 2 exists for link mode, where the payload travels
            // unencrypted over a platform deep link rather than the relay.
            // Nothing here speaks link mode, and treating an unencrypted
            // envelope as if it had been authenticated is exactly the mistake
            // worth refusing outright.
            other => bail!("unsupported WalletConnect envelope type {other}"),
        }
    }

    /// The sender's public key, when the envelope type carries one.
    #[must_use]
    pub const fn sender_public_key(&self) -> Option<&[u8; KEY_LENGTH]> {
        match self {
            Self::Type0 { .. } => None,
            Self::Type1 {
                sender_public_key, ..
            } => Some(sender_public_key),
        }
    }

    /// Decrypt and return the UTF-8 payload.
    ///
    /// ChaCha20-Poly1305 authenticates, so a failure here means the message was
    /// not produced by a holder of this key — forged, replayed onto the wrong
    /// topic, or simply addressed to a session this side has already rotated
    /// past. All of those are the same answer: refuse it.
    pub fn open(&self, key: &SymKey) -> Result<String> {
        let (iv, sealed) = match self {
            Self::Type0 { iv, sealed } | Self::Type1 { iv, sealed, .. } => (iv, sealed),
        };
        let cipher = ChaCha20Poly1305::new((&key.0).into());
        let plaintext = cipher
            .decrypt(
                iv.into(),
                Payload {
                    msg: sealed,
                    aad: &[],
                },
            )
            .map_err(|_| {
                anyhow::anyhow!(
                    "the relay message failed authenticated decryption, so it was not sent by the \
                     peer this key is shared with"
                )
            })?;
        String::from_utf8(plaintext).context("decrypted payload is not valid UTF-8")
    }
}

fn split_iv(bytes: &[u8]) -> Result<([u8; IV_LENGTH], Vec<u8>)> {
    ensure!(
        bytes.len() >= IV_LENGTH + TAG_LENGTH,
        "envelope is too short to hold a nonce and an authentication tag"
    );
    let (iv, sealed) = bytes.split_at(IV_LENGTH);
    Ok((iv.try_into().expect("split at IV_LENGTH"), sealed.to_vec()))
}

/// Seal a payload as a type 0 envelope: the encoding for every message sent
/// once both peers share a key, which is every message this wallet sends.
///
/// The nonce is fresh per call and never reused, which is what
/// ChaCha20-Poly1305 requires of a fixed key.
pub fn seal(key: &SymKey, plaintext: &str) -> Result<String> {
    let mut iv = [0u8; IV_LENGTH];
    random_bytes(&mut iv)?;
    let cipher = ChaCha20Poly1305::new((&key.0).into());
    let sealed = cipher
        .encrypt(
            (&iv).into(),
            Payload {
                msg: plaintext.as_bytes(),
                aad: &[],
            },
        )
        .map_err(|_| anyhow::anyhow!("failed to seal a WalletConnect payload"))?;
    let mut envelope = Vec::with_capacity(1 + IV_LENGTH + sealed.len());
    envelope.push(ENVELOPE_TYPE_0);
    envelope.extend_from_slice(&iv);
    envelope.extend_from_slice(&sealed);
    Ok(BASE64.encode(envelope))
}

/// The relay's client identity key.
///
/// The relay authenticates clients with a short-lived Ed25519 JWT rather than
/// a bearer secret, so this key is an identity for a websocket connection and
/// nothing else. It is generated per run: persisting it would create a stable
/// identifier the relay operator could correlate across sessions, and nothing
/// in the protocol needs it to survive a restart.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct ClientIdentity {
    seed: [u8; 32],
}

impl std::fmt::Debug for ClientIdentity {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ClientIdentity(<redacted>)")
    }
}

impl ClientIdentity {
    pub fn generate() -> Result<Self> {
        let mut seed = [0u8; 32];
        random_bytes(&mut seed)?;
        Ok(Self { seed })
    }

    /// This client's `did:key` identifier, as the `iss` claim spells it.
    #[must_use]
    pub fn did_key(&self) -> String {
        let signing = ed25519_dalek::SigningKey::from_bytes(&self.seed);
        did_key(signing.verifying_key().as_bytes())
    }

    /// A signed relay authentication token for `audience`, valid for `ttl`
    /// seconds from `issued_at`.
    ///
    /// `sub` is a fresh random value per token, exactly as the reference client
    /// does it; the relay treats it as an opaque connection identifier.
    pub fn relay_jwt(&self, audience: &str, issued_at: i64, ttl: i64) -> Result<String> {
        let mut subject = [0u8; 32];
        random_bytes(&mut subject)?;
        let header = serde_json::json!({ "alg": "EdDSA", "typ": "JWT" });
        let payload = serde_json::json!({
            "iss": self.did_key(),
            "sub": hex::encode(subject),
            "aud": audience,
            "iat": issued_at,
            "exp": issued_at.saturating_add(ttl),
        });
        let signing_input = format!(
            "{}.{}",
            BASE64URL.encode(serde_json::to_vec(&header)?),
            BASE64URL.encode(serde_json::to_vec(&payload)?)
        );
        let signing = ed25519_dalek::SigningKey::from_bytes(&self.seed);
        let signature = ed25519_dalek::Signer::sign(&signing, signing_input.as_bytes());
        Ok(format!(
            "{signing_input}.{}",
            BASE64URL.encode(signature.to_bytes())
        ))
    }
}

/// The multicodec prefix identifying an Ed25519 public key, as
/// `did:key` requires: `0xed 0x01`, varint-encoded.
const MULTICODEC_ED25519: [u8; 2] = [0xed, 0x01];

/// `did:key:z…` for an Ed25519 public key.
///
/// The `z` is the multibase tag for base58btc, and it prefixes the encoding
/// rather than participating in it — an Ed25519 key always renders as
/// `did:key:z6Mk…`.
#[must_use]
fn did_key(public_key: &[u8; 32]) -> String {
    let mut multicodec = Vec::with_capacity(MULTICODEC_ED25519.len() + public_key.len());
    multicodec.extend_from_slice(&MULTICODEC_ED25519);
    multicodec.extend_from_slice(public_key);
    format!("did:key:z{}", bs58::encode(multicodec).into_string())
}

#[cfg(test)]
#[path = "crypto_test.rs"]
mod tests;
