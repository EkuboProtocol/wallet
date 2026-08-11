use super::*;

#[test]
fn legacy_directory_is_archived_without_importing_it() {
    let root = tempfile::tempdir().unwrap();
    let data = root.path().join("wallet");
    fs::create_dir(&data).unwrap();
    fs::write(data.join("policies.db"), b"legacy database").unwrap();
    fs::write(data.join("config.json"), b"legacy config").unwrap();

    let archived = prepare_desktop_data_dir(&data).unwrap().unwrap();
    assert_eq!(
        fs::read(archived.join("policies.db")).unwrap(),
        b"legacy database"
    );
    assert_eq!(
        fs::read(archived.join("config.json")).unwrap(),
        b"legacy config"
    );
    assert!(data.join(DESKTOP_MARKER).is_file());
    assert!(!data.join("policies.db").exists());
}

#[test]
fn migration_is_idempotent() {
    let root = tempfile::tempdir().unwrap();
    let data = root.path().join("wallet");
    assert!(prepare_desktop_data_dir(&data).unwrap().is_none());
    fs::write(data.join("config.json"), b"desktop config").unwrap();
    assert!(prepare_desktop_data_dir(&data).unwrap().is_none());
    assert_eq!(
        fs::read(data.join("config.json")).unwrap(),
        b"desktop config"
    );
}
