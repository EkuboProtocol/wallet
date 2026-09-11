//! Service-only key wrapping, independent of OS storage. This module grants no
//! owner authorization and exposes no IPC endpoint. Platform custody must own
//! the wrapping key, derive bindings from protected configuration, and pin the
//! enrolled envelope digest. Never persist the wrapped data key beside its
//! wrapping key: the wrapped data key belongs only in the desktop login keyring.

use anyhow::{Result, ensure};
use chacha20poly1305::{KeyInit as _, XChaCha20Poly1305, aead::AeadInOut as _};
use rand::TryRng as _;
use sha2::{Digest as _, Sha256};
use subtle::ConstantTimeEq as _;
use uuid::Uuid;
use zeroize::Zeroizing;

const MAGIC: &[u8; 8] = b"EKUBOKEY";
const VERSION: u8 = 1;
const HEADER: usize = 10;
const NONCE_END: usize = HEADER + 24;
const DATA_END: usize = NONCE_END + 32;
pub const SEALED_KEY_BYTES: usize = DATA_END + 16;

#[derive(Clone, Copy)]
enum Purpose {
    Data = 1,
    Database = 2,
    Account = 3,
}

/// A cryptographic binding, not evidence of OS identity. Callers must obtain
/// canonical, platform-prefixed identities and UUIDs from protected state.
#[derive(Clone, Copy)]
pub struct CustodyBinding([u8; 32]);

impl CustodyBinding {
    pub fn new(owner: &str, service: &str, profile: Uuid, generation: Uuid) -> Result<Self> {
        ensure!(
            !owner.is_empty()
                && owner.len() <= 256
                && !service.is_empty()
                && service.len() <= 256
                && owner != service
                && !profile.is_nil()
                && !generation.is_nil(),
            "invalid custody identity binding"
        );
        // Fixed v1 serialization: strings are separate JSON tuple elements,
        // preventing concatenation ambiguity. Do not change without versioning.
        let encoded = serde_json::to_vec(&(
            "ekubo-wallet-custody-v1",
            owner,
            service,
            profile,
            generation,
        ))?;
        Ok(Self(Sha256::digest(encoded).into()))
    }
}

/// Ciphertext safe to relay through the desktop. Its digest, not these bytes,
/// is pinned in protected service state. It contains no usable data key.
#[derive(Clone)]
pub struct WrappedDataKey([u8; SEALED_KEY_BYTES]);

/// Public metadata with protected-state authority. Only read it from an
/// OS-validated service file; neither this metadata nor the expected identities
/// may be supplied by the desktop's unlock request.
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CustodyEnrollment {
    version: u8,
    generation: Uuid,
    wrapped_key_digest: [u8; 32],
}

impl CustodyEnrollment {
    pub fn new(generation: Uuid, wrapped: &WrappedDataKey) -> Result<Self> {
        ensure!(!generation.is_nil(), "invalid custody generation");
        Ok(Self {
            version: VERSION,
            generation,
            wrapped_key_digest: wrapped.digest(),
        })
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        ensure!(bytes.len() <= 4096, "custody enrollment is oversized");
        let enrollment: Self = serde_json::from_slice(bytes)?;
        ensure!(
            enrollment.version == VERSION && !enrollment.generation.is_nil(),
            "invalid custody enrollment"
        );
        Ok(enrollment)
    }

    pub fn unlock(
        &self,
        wrapping: &WrappingKey,
        owner: &str,
        service: &str,
        profile: Uuid,
        wrapped: &WrappedDataKey,
    ) -> Result<DataCipher> {
        ensure!(
            self.version == VERSION,
            "unsupported custody enrollment version"
        );
        let binding = CustodyBinding::new(owner, service, profile, self.generation)?;
        wrapping.unlock(binding, wrapped, &self.wrapped_key_digest)
    }
}

impl WrappedDataKey {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        validate_header(bytes, Purpose::Data)?;
        Ok(Self(
            bytes.try_into().expect("validated fixed envelope length"),
        ))
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    #[must_use]
    pub fn digest(&self) -> [u8; 32] {
        Sha256::digest(self.0).into()
    }
}

/// Loaded only from service-owned protected storage. It is not serializable or
/// clonable, and has no key-export method. The caller already owns the material
/// supplied to this constructor; construction itself establishes no authority.
pub struct WrappingKey(XChaCha20Poly1305);

impl WrappingKey {
    #[must_use]
    pub fn from_material(material: Zeroizing<[u8; 32]>) -> Self {
        let key = Self(cipher(&material));
        // Take ownership so the input buffer is erased before returning.
        drop(material);
        key
    }

    /// Internal provisioning/rotation only. The host must authenticate changes
    /// to enrollment and commit the envelope's digest transactionally.
    pub fn enroll(&self, binding: CustodyBinding) -> Result<(DataCipher, WrappedDataKey)> {
        let mut material = Zeroizing::new([0_u8; 32]);
        random_bytes(material.as_mut())?;
        let wrapped = WrappedDataKey(seal(
            &self.0,
            binding,
            Purpose::Data,
            Uuid::nil(),
            &material,
        )?);
        Ok((
            DataCipher {
                cipher: cipher(&material),
                binding,
            },
            wrapped,
        ))
    }

    /// Bootstrap only; never expose a general unwrap RPC. The expected digest
    /// must come from protected enrollment, not from the desktop relay.
    pub fn unlock(
        &self,
        binding: CustodyBinding,
        wrapped: &WrappedDataKey,
        expected_digest: &[u8; 32],
    ) -> Result<DataCipher> {
        ensure!(
            bool::from(wrapped.digest().ct_eq(expected_digest)),
            "custody envelope does not match protected enrollment"
        );
        let material = open(
            &self.0,
            binding,
            Purpose::Data,
            Uuid::nil(),
            wrapped.as_bytes(),
        )?;
        Ok(DataCipher {
            cipher: cipher(&material),
            binding,
        })
    }
}

/// The service's in-memory data-key capability. No master-key export, arbitrary
/// payload encryption, or access to a desktop credential store is provided.
pub struct DataCipher {
    cipher: XChaCha20Poly1305,
    binding: CustodyBinding,
}

impl DataCipher {
    pub fn seal_database_key(&self, material: &[u8; 32]) -> Result<[u8; SEALED_KEY_BYTES]> {
        seal(
            &self.cipher,
            self.binding,
            Purpose::Database,
            Uuid::nil(),
            material,
        )
    }

    pub fn open_database_key(&self, sealed: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
        open(
            &self.cipher,
            self.binding,
            Purpose::Database,
            Uuid::nil(),
            sealed,
        )
    }

    pub fn seal_account_key(
        &self,
        instance: Uuid,
        material: &[u8; 32],
    ) -> Result<[u8; SEALED_KEY_BYTES]> {
        ensure!(!instance.is_nil(), "account key requires a wallet instance");
        seal(
            &self.cipher,
            self.binding,
            Purpose::Account,
            instance,
            material,
        )
    }

    pub fn open_account_key(&self, instance: Uuid, sealed: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
        ensure!(!instance.is_nil(), "account key requires a wallet instance");
        open(
            &self.cipher,
            self.binding,
            Purpose::Account,
            instance,
            sealed,
        )
    }
}

fn cipher(material: &[u8; 32]) -> XChaCha20Poly1305 {
    XChaCha20Poly1305::new_from_slice(material).expect("fixed 256-bit key")
}

fn random_bytes(bytes: &mut [u8]) -> Result<()> {
    rand::rngs::SysRng
        .try_fill_bytes(bytes)
        .map_err(|_| anyhow::anyhow!("operating-system randomness is unavailable"))
}

fn associated_data(binding: CustodyBinding, purpose: Purpose, subject: Uuid) -> [u8; 58] {
    let mut data = [0; 58];
    data[..8].copy_from_slice(MAGIC);
    data[8] = VERSION;
    data[9] = purpose as u8;
    data[10..42].copy_from_slice(&binding.0);
    data[42..].copy_from_slice(subject.as_bytes());
    data
}

fn validate_header(bytes: &[u8], purpose: Purpose) -> Result<()> {
    ensure!(
        bytes.len() == SEALED_KEY_BYTES
            && &bytes[..8] == MAGIC
            && bytes[8] == VERSION
            && bytes[9] == purpose as u8,
        "invalid encrypted custody key format"
    );
    Ok(())
}

fn seal(
    cipher: &XChaCha20Poly1305,
    binding: CustodyBinding,
    purpose: Purpose,
    subject: Uuid,
    material: &[u8; 32],
) -> Result<[u8; SEALED_KEY_BYTES]> {
    let mut nonce = [0; 24];
    random_bytes(&mut nonce)?;
    seal_with_nonce(cipher, binding, purpose, subject, material, nonce)
}

fn seal_with_nonce(
    cipher: &XChaCha20Poly1305,
    binding: CustodyBinding,
    purpose: Purpose,
    subject: Uuid,
    material: &[u8; 32],
    nonce: [u8; 24],
) -> Result<[u8; SEALED_KEY_BYTES]> {
    let aad = associated_data(binding, purpose, subject);
    let mut buffer = Zeroizing::new(*material);
    let tag = cipher
        .encrypt_inout_detached((&nonce).into(), &aad, buffer.as_mut_slice().into())
        .map_err(|_| anyhow::anyhow!("cannot encrypt custody key"))?;
    let mut sealed = [0; SEALED_KEY_BYTES];
    sealed[..HEADER].copy_from_slice(&aad[..HEADER]);
    sealed[HEADER..NONCE_END].copy_from_slice(&nonce);
    sealed[NONCE_END..DATA_END].copy_from_slice(buffer.as_ref());
    sealed[DATA_END..].copy_from_slice(&tag);
    Ok(sealed)
}

fn open(
    cipher: &XChaCha20Poly1305,
    binding: CustodyBinding,
    purpose: Purpose,
    subject: Uuid,
    sealed: &[u8],
) -> Result<Zeroizing<[u8; 32]>> {
    validate_header(sealed, purpose)?;
    let nonce: &[u8; 24] = sealed[HEADER..NONCE_END].try_into().expect("fixed nonce");
    let tag: &[u8; 16] = sealed[DATA_END..].try_into().expect("fixed tag");
    let mut buffer = Zeroizing::new([0; 32]);
    buffer.copy_from_slice(&sealed[NONCE_END..DATA_END]);
    cipher
        .decrypt_inout_detached(
            nonce.into(),
            &associated_data(binding, purpose, subject),
            buffer.as_mut_slice().into(),
            tag.into(),
        )
        .map_err(|_| anyhow::anyhow!("custody key authentication failed"))?;
    Ok(buffer)
}

#[cfg(test)]
#[path = "custody_envelope_test.rs"]
mod tests;
