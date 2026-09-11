use super::*;
use std::cell::RefCell;

fn relay() -> WrappedDataKey {
    crate::custody_envelope::WrappingKey::from_material(zeroize::Zeroizing::new([0x44; 32]))
        .enroll(
            crate::custody_envelope::CustodyBinding::new(
                "owner",
                "service",
                Uuid::new_v4(),
                Uuid::new_v4(),
            )
            .unwrap(),
        )
        .unwrap()
        .1
}

#[test]
fn relay_persistence_reads_back_and_never_overwrites_existing_or_unreadable_entries() {
    let relay = relay();
    let value = RefCell::new(None::<Vec<u8>>);
    persist_with(
        &relay,
        || value.borrow().clone().ok_or(keyring::Error::NoEntry),
        |bytes| {
            *value.borrow_mut() = Some(bytes.to_vec());
            Ok(())
        },
    )
    .unwrap();
    assert_eq!(
        value.borrow().as_ref().unwrap().as_slice(),
        relay.as_bytes()
    );
    persist_with(
        &relay,
        || Ok(relay.as_bytes().to_vec()),
        |_| panic!("exact retry must not write"),
    )
    .unwrap();
    assert!(
        persist_with(
            &relay,
            || Ok(vec![0; 3]),
            |_| panic!("conflicting entry must not be overwritten")
        )
        .is_err()
    );
    assert!(
        persist_with(
            &relay,
            || Err(keyring::Error::NoStorageAccess(Box::new(
                std::io::Error::other("synthetic")
            ))),
            |_| panic!("read failure must not write")
        )
        .is_err()
    );
}

#[test]
fn relay_persistence_rejects_failed_write_or_mismatched_readback() {
    let relay = relay();
    assert!(
        persist_with(
            &relay,
            || Err(keyring::Error::NoEntry),
            |_| Err(keyring::Error::NoStorageAccess(Box::new(
                std::io::Error::other("synthetic")
            )))
        )
        .is_err()
    );
    let mut reads = 0;
    assert!(
        persist_with(
            &relay,
            || {
                reads += 1;
                if reads == 1 {
                    Err(keyring::Error::NoEntry)
                } else {
                    Ok(vec![1; 3])
                }
            },
            |_| Ok(())
        )
        .is_err()
    );
}

#[cfg(target_os = "linux")]
#[test]
fn receipt_cannot_be_replayed_for_another_nonce_profile_or_relay() {
    let relay = relay();
    let profile = Uuid::new_v4();
    let nonce = Uuid::new_v4();
    let receipt = RelayReceipt {
        profile,
        nonce,
        relay_digest: relay.digest(),
    };
    receipt.verify(profile, nonce, &relay).unwrap();
    assert!(receipt.verify(profile, Uuid::new_v4(), &relay).is_err());
    assert!(receipt.verify(Uuid::new_v4(), nonce, &relay).is_err());
    let wrong = RelayReceipt {
        profile,
        nonce,
        relay_digest: [0; 32],
    };
    assert!(wrong.verify(profile, nonce, &relay).is_err());
}
