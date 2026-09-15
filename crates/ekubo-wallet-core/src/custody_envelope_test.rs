use super::*;

fn binding() -> CustodyBinding {
    CustodyBinding::new(
        "linux:uid:1000",
        "linux:uid:2000",
        Uuid::from_u128(1),
        Uuid::from_u128(2),
    )
    .unwrap()
}

fn wrapping() -> WrappingKey {
    WrappingKey::from_material(Zeroizing::new([0x11; 32]))
}

#[test]
fn linux_and_windows_use_the_same_enrollment_and_credential_contract() {
    for (owner, service) in [
        ("linux:uid:1000", "linux:uid:2000"),
        (
            "windows:sid:S-1-5-21-1-2-3-1000",
            "windows:sid:S-1-5-80-1-2-3-4-5",
        ),
    ] {
        let profile = Uuid::new_v4();
        let generation = Uuid::new_v4();
        let instance = Uuid::new_v4();
        let binding = CustodyBinding::new(owner, service, profile, generation).unwrap();
        let (data, wrapped) = wrapping().enroll(binding).unwrap();
        let account = data.seal_account_key(instance, &[0x22; 32]).unwrap();
        let database = data.seal_database_key(&[0x33; 32]).unwrap();
        let metadata =
            serde_json::to_vec(&CustodyEnrollment::new(generation, &wrapped).unwrap()).unwrap();
        let ciphertext = wrapped.as_bytes().to_vec();
        drop(data);

        // Simulate restart: the OS adapter reloads protected metadata and KEK;
        // the desktop supplies only the opaque envelope, with no key export.
        let enrollment = CustodyEnrollment::from_bytes(&metadata).unwrap();
        let wrapped = WrappedDataKey::from_bytes(&ciphertext).unwrap();
        let data = enrollment
            .unlock(&wrapping(), owner, service, profile, &wrapped)
            .unwrap();
        assert_eq!(
            *data.open_account_key(instance, &account).unwrap(),
            [0x22; 32]
        );
        assert_eq!(*data.open_database_key(&database).unwrap(), [0x33; 32]);
        assert!(data.open_database_key(&account).is_err());
        assert!(data.open_account_key(Uuid::new_v4(), &account).is_err());
        assert!(
            enrollment
                .unlock(&wrapping(), service, owner, profile, &wrapped)
                .is_err()
        );
    }
}

#[test]
fn enrollment_metadata_is_bounded_versioned_and_bound_at_unlock() {
    let wrapping = wrapping();
    let (_, wrapped) = wrapping.enroll(binding()).unwrap();
    let enrolled = CustodyEnrollment::new(Uuid::from_u128(2), &wrapped).unwrap();
    let encoded = serde_json::to_vec(&enrolled).unwrap();
    let read = CustodyEnrollment::from_bytes(&encoded).unwrap();
    assert!(
        read.unlock(
            &wrapping,
            "linux:uid:1000",
            "linux:uid:2000",
            Uuid::from_u128(1),
            &wrapped
        )
        .is_ok()
    );
    assert!(
        read.unlock(
            &wrapping,
            "linux:uid:1001",
            "linux:uid:2000",
            Uuid::from_u128(1),
            &wrapped
        )
        .is_err()
    );
    for (field, value) in [
        ("version", serde_json::json!(2)),
        ("generation", serde_json::json!(Uuid::nil())),
        ("untrusted", serde_json::json!(true)),
        ("wrapped_key_digest", serde_json::json!([1, 2])),
    ] {
        let mut altered = serde_json::to_value(&enrolled).unwrap();
        altered[field] = value;
        assert!(CustodyEnrollment::from_bytes(&serde_json::to_vec(&altered).unwrap()).is_err());
    }
    assert!(CustodyEnrollment::from_bytes(&vec![b' '; 4097]).is_err());
}

#[test]
fn v1_format_matches_an_independent_libsodium_vector() {
    // Independently produced with libsodium 1.0.22's
    // crypto_aead_xchacha20poly1305_ietf_encrypt (combined mode).
    // Key=11*32, payload=22*32, nonce=33*24. AAD is the ten-byte
    // header, SHA-256 of the documented binding tuple, and UUID(3).
    let expected = hex::decode(concat!(
        "454b55424f4b45590103",
        "333333333333333333333333333333333333333333333333",
        "988655ab5a492115a0b60a86eccfdcf4a9655edc6e9156aec946b458b235dd63",
        "e4a74d82ba0cfead3c68233f0ecc3404"
    ))
    .unwrap();
    assert_eq!(
        hex::encode(binding().0),
        "e50719714dc6663c7727e17afb8ce2347a78ce53430a563ca061a56bb261a1e3"
    );
    let key = cipher(&[0x11; 32]);
    let sealed = seal_with_nonce(
        &key,
        binding(),
        Purpose::Account,
        Uuid::from_u128(3),
        &[0x22; 32],
        [0x33; 24],
    )
    .unwrap();
    assert_eq!(sealed.as_slice(), expected);
    assert_eq!(
        *open(
            &key,
            binding(),
            Purpose::Account,
            Uuid::from_u128(3),
            &expected
        )
        .unwrap(),
        [0x22; 32]
    );
}

#[test]
fn enrolled_keys_survive_wrapping_key_reload_without_exposing_the_data_key() {
    let (data, wrapped) = wrapping().enroll(binding()).unwrap();
    let account = Uuid::new_v4();
    let database = data.seal_database_key(&[0x22; 32]).unwrap();
    let private = data.seal_account_key(account, &[0x33; 32]).unwrap();
    let digest = wrapped.digest();
    let relayed = WrappedDataKey::from_bytes(wrapped.as_bytes()).unwrap();
    drop(data);
    let reopened = wrapping().unlock(binding(), &relayed, &digest).unwrap();
    assert_eq!(*reopened.open_database_key(&database).unwrap(), [0x22; 32]);
    assert_eq!(
        *reopened.open_account_key(account, &private).unwrap(),
        [0x33; 32]
    );
    assert!(reopened.open_database_key(&private).is_err());
    assert!(reopened.open_account_key(account, &database).is_err());
    assert!(reopened.open_account_key(Uuid::new_v4(), &private).is_err());
    assert!(reopened.open_account_key(Uuid::nil(), &private).is_err());
    assert!(reopened.seal_account_key(Uuid::nil(), &[0; 32]).is_err());
}

#[test]
fn every_modified_header_nonce_ciphertext_and_tag_byte_is_rejected() {
    let key = wrapping();
    let (data, wrapped) = key.enroll(binding()).unwrap();
    let sealed = data.seal_database_key(&[0x22; 32]).unwrap();
    for index in 0..SEALED_KEY_BYTES {
        let mut changed = sealed;
        changed[index] ^= 1;
        assert!(
            data.open_database_key(&changed).is_err(),
            "credential byte {index}"
        );
        let mut changed = wrapped.as_bytes().to_vec();
        changed[index] ^= 1;
        if let Ok(changed) = WrappedDataKey::from_bytes(&changed) {
            assert!(key.unlock(binding(), &changed, &wrapped.digest()).is_err());
            // Even replacing the expected hash cannot repair a forged AEAD tag.
            assert!(key.unlock(binding(), &changed, &changed.digest()).is_err());
        }
    }
}

#[test]
fn envelopes_cannot_cross_owner_service_profile_or_generation() {
    let key = wrapping();
    let (_, wrapped) = key.enroll(binding()).unwrap();
    let profile = Uuid::from_u128(1);
    let generation = Uuid::from_u128(2);
    for other in [
        CustodyBinding::new("linux:uid:1001", "linux:uid:2000", profile, generation).unwrap(),
        CustodyBinding::new("linux:uid:1000", "linux:uid:2001", profile, generation).unwrap(),
        CustodyBinding::new(
            "linux:uid:1000",
            "linux:uid:2000",
            Uuid::new_v4(),
            generation,
        )
        .unwrap(),
        CustodyBinding::new("linux:uid:1000", "linux:uid:2000", profile, Uuid::new_v4()).unwrap(),
        CustodyBinding::new(
            "windows:sid:S-1-5-21-1",
            "windows:sid:S-1-5-80-1-2-3-4-5",
            profile,
            generation,
        )
        .unwrap(),
    ] {
        assert!(key.unlock(other, &wrapped, &wrapped.digest()).is_err());
    }
    let wrong_key = WrappingKey::from_material(Zeroizing::new([0x44; 32]));
    assert!(
        wrong_key
            .unlock(binding(), &wrapped, &wrapped.digest())
            .is_err()
    );
}

#[test]
fn protected_digest_rejects_old_enrollment_even_under_the_same_binding() {
    let key = wrapping();
    let (old_data, old) = key.enroll(binding()).unwrap();
    let (new_data, current) = key.enroll(binding()).unwrap();
    assert_ne!(old.digest(), current.digest());
    assert!(key.unlock(binding(), &old, &current.digest()).is_err());
    assert!(key.unlock(binding(), &current, &current.digest()).is_ok());
    let sealed = new_data.seal_database_key(&[0x22; 32]).unwrap();
    assert!(old_data.open_database_key(&sealed).is_err());
}

#[test]
fn malformed_lengths_legacy_plaintext_and_future_versions_fail_closed() {
    let (data, wrapped) = wrapping().enroll(binding()).unwrap();
    for length in 0..SEALED_KEY_BYTES {
        assert!(WrappedDataKey::from_bytes(&wrapped.as_bytes()[..length]).is_err());
        assert!(
            data.open_database_key(&wrapped.as_bytes()[..length])
                .is_err()
        );
    }
    let mut oversized = wrapped.as_bytes().to_vec();
    oversized.push(0);
    assert!(WrappedDataKey::from_bytes(&oversized).is_err());
    assert!(data.open_database_key(&oversized).is_err());
    oversized.truncate(SEALED_KEY_BYTES);
    oversized[8] = 2;
    assert!(WrappedDataKey::from_bytes(&oversized).is_err());
    assert!(data.open_database_key(&[0x22; 32]).is_err());
}

#[test]
fn bindings_are_unambiguous_and_key_material_is_configured_to_zeroize() {
    fn assert_zeroize<T: zeroize::ZeroizeOnDrop + Send + Sync>() {}
    assert_zeroize::<XChaCha20Poly1305>();
    let profile = Uuid::from_u128(1);
    let generation = Uuid::from_u128(2);
    assert_ne!(
        CustodyBinding::new("a", "bc", profile, generation)
            .unwrap()
            .0,
        CustodyBinding::new("ab", "c", profile, generation)
            .unwrap()
            .0
    );
    for (owner, service, profile, generation) in [
        ("", "service", profile, generation),
        ("owner", "owner", profile, generation),
        ("owner", "service", Uuid::nil(), generation),
        ("owner", "service", profile, Uuid::nil()),
    ] {
        assert!(CustodyBinding::new(owner, service, profile, generation).is_err());
    }
    let (data, _) = wrapping().enroll(binding()).unwrap();
    let first = data.seal_database_key(&[0x22; 32]).unwrap();
    let second = data.seal_database_key(&[0x22; 32]).unwrap();
    assert_ne!(&first[HEADER..NONCE_END], &second[HEADER..NONCE_END]);
}
