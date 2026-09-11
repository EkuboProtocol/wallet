use super::*;

#[test]
fn service_credentials_accept_only_database_and_non_nil_account_instances() {
    let id = uuid::Uuid::new_v4();
    assert_eq!(
        Credential::parse("org.ekubo.wallet.db", "default").unwrap(),
        Credential::Database
    );
    assert_eq!(
        Credential::parse("org.ekubo.wallet.private-key.instance", &id.to_string()).unwrap(),
        Credential::Account(id)
    );
    for (service, user) in [
        ("org.ekubo.wallet.db", "other"),
        ("org.ekubo.wallet.private-key.instance", "../wrapping.key"),
        (
            "org.ekubo.wallet.private-key.instance",
            "00000000-0000-0000-0000-000000000000",
        ),
        ("org.ekubo.wallet.private-key", "default"),
        ("org.ekubo.wallet.custody-envelope", "default"),
    ] {
        assert!(Credential::parse(service, user).is_err());
    }
}

#[test]
fn service_file_routing_is_confined_to_four_fixed_profile_files() {
    let root = Path::new(r"C:\ProgramData\EkuboWallet\Owners\profile");
    for name in ["wallet.db", "wallet.lock", "config.lock", "lifecycle.lock"] {
        assert!(database_file(root, &root.join(name)).is_ok());
    }
    for path in [
        root.to_owned(),
        root.join("../wallet.db"),
        root.join("sub/wallet.db"),
        root.join("wallet.db:stream"),
        root.join("wrapping.key"),
        root.join("service.lock"),
        PathBuf::from(r"C:\Users\owner\wallet.db"),
    ] {
        assert!(database_file(root, &path).is_err(), "{}", path.display());
    }
}

#[test]
fn only_a_missing_final_native_name_maps_to_missing_credential() {
    use windows::Win32::Foundation::{
        STATUS_ACCESS_DENIED, STATUS_OBJECT_NAME_NOT_FOUND, STATUS_OBJECT_PATH_NOT_FOUND,
    };
    for (status, missing) in [
        (STATUS_OBJECT_NAME_NOT_FOUND, true),
        (STATUS_OBJECT_PATH_NOT_FOUND, false),
        (STATUS_ACCESS_DENIED, false),
    ] {
        let error =
            anyhow::Error::new(windows::core::Error::from(status)).context("opening credential");
        assert_eq!(is_missing_credential(&error), missing);
    }
    assert!(!is_missing_credential(&anyhow::anyhow!(
        "invalid ciphertext"
    )));
    assert!(!is_missing_credential(
        &std::io::Error::from(std::io::ErrorKind::NotFound).into()
    ));
}
