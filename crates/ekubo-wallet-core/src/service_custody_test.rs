use super::*;
use crate::custody_envelope::CustodyBinding;
use std::io::Cursor;

fn fixture(owner: &str, service: &str) -> (Vec<u8>, WrappedDataKey) {
    let binding =
        CustodyBinding::new(owner, service, Uuid::from_u128(1), Uuid::from_u128(2)).unwrap();
    let (_, wrapped) = WrappingKey::from_material(Zeroizing::new([0x11; 32]))
        .enroll(binding)
        .unwrap();
    let enrollment = CustodyEnrollment::new(Uuid::from_u128(2), &wrapped).unwrap();
    (serde_json::to_vec(&enrollment).unwrap(), wrapped)
}

fn unlock(
    custody: &ServiceCustody,
    metadata: &[u8],
    wrapped: &WrappedDataKey,
    owner: &str,
    service: &str,
) -> Result<()> {
    custody.unlock(
        Cursor::new(metadata),
        Cursor::new([0x11; 32]),
        owner,
        service,
        Uuid::from_u128(1),
        wrapped,
    )
}

#[test]
fn both_platform_bindings_unlock_and_restart_with_the_same_encrypted_keys() {
    for (owner, service) in [
        ("linux:uid:1000", "linux:uid:2000"),
        (
            "windows:sid:S-1-5-21-1-2-3-1000",
            "windows:sid:S-1-5-80-1-2-3-4-5",
        ),
    ] {
        let (metadata, wrapped) = fixture(owner, service);
        let custody = ServiceCustody::default();
        assert!(custody.cipher().is_err());
        assert!(unlock(&custody, &metadata, &wrapped, service, owner).is_err());
        assert!(custody.cipher().is_err());
        unlock(&custody, &metadata, &wrapped, owner, service).unwrap();
        let cipher = custody.cipher().unwrap();
        let instance = Uuid::new_v4();
        let account = cipher.seal_account_key(instance, &[0x22; 32]).unwrap();
        let database = cipher.seal_database_key(&[0x33; 32]).unwrap();
        unlock(&custody, &metadata, &wrapped, owner, service).unwrap();
        assert!(Arc::ptr_eq(&cipher, &custody.cipher().unwrap()));
        drop(cipher);
        drop(custody);
        let reopened = ServiceCustody::default();
        assert!(reopened.cipher().is_err());
        unlock(&reopened, &metadata, &wrapped, owner, service).unwrap();
        let cipher = reopened.cipher().unwrap();
        assert_eq!(*cipher.open_database_key(&database).unwrap(), [0x33; 32]);
        assert_eq!(
            *cipher.open_account_key(instance, &account).unwrap(),
            [0x22; 32]
        );
        assert!(cipher.open_account_key(Uuid::new_v4(), &account).is_err());
    }
}

#[test]
fn new_enrollment_cannot_replace_a_running_cipher() {
    let (metadata, wrapped) = fixture("owner", "service");
    let custody = ServiceCustody::default();
    unlock(&custody, &metadata, &wrapped, "owner", "service").unwrap();
    let cipher = custody.cipher().unwrap();
    let (new_metadata, replacement) = fixture("owner", "service");
    assert!(unlock(&custody, &new_metadata, &replacement, "owner", "service").is_err());
    assert!(Arc::ptr_eq(&cipher, &custody.cipher().unwrap()));
}

#[test]
fn corrupt_wrapping_material_and_oversized_metadata_leave_custody_locked() {
    let custody = ServiceCustody::default();
    let (metadata, wrapped) = fixture("owner", "service");
    for material in [vec![], vec![0x11; 31], vec![0x11; 33], vec![0x22; 32]] {
        assert!(
            custody
                .unlock(
                    Cursor::new(&metadata),
                    Cursor::new(material),
                    "owner",
                    "service",
                    Uuid::from_u128(1),
                    &wrapped
                )
                .is_err()
        );
        assert!(custody.cipher().is_err());
    }
    assert!(unlock(&custody, &vec![b' '; 4097], &wrapped, "owner", "service").is_err());
    assert!(custody.cipher().is_err());
    unlock(&custody, &metadata, &wrapped, "owner", "service").unwrap();
}

#[test]
fn fixed_key_reads_reject_truncation_trailing_data_and_io_errors() {
    struct Broken;
    impl Read for Broken {
        fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
            Err(std::io::Error::other("synthetic I/O failure"))
        }
    }
    assert_eq!(
        *read_fixed::<32>(Cursor::new([0x11; 32])).unwrap(),
        [0x11; 32]
    );
    assert!(read_fixed::<32>(Cursor::new([0x11; 31])).is_err());
    assert!(read_fixed::<32>(Cursor::new([0x11; 33])).is_err());
    assert!(read_fixed::<32>(Broken).is_err());
}
