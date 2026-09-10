use super::*;

// Public synthetic test scalar, unrelated to any installed wallet credential.
fn scalar() -> String {
    format!("{:064x}", 1)
}

#[test]
fn import_round_trip_preserves_the_address_and_redacts_diagnostics() {
    for value in [scalar(), format!("0x{}", scalar())] {
        let key = ImportKey::from_hex(value.clone()).unwrap();
        assert_eq!(format!("{key:?}"), "ImportKey([REDACTED])");
        let wire = serde_json::to_string(&key).unwrap();
        assert_eq!(serde_json::from_str::<String>(&wire).unwrap(), value);
        let restored: ImportKey = serde_json::from_str(&wire).unwrap();
        assert_eq!(
            restored
                .into_material()
                .unwrap()
                .address()
                .to_string()
                .to_ascii_lowercase(),
            "0x7e5f4552091a69125d5dfcb7b8c2659029395bdf"
        );
    }
}

#[test]
fn invalid_imports_are_rejected_without_echoing_the_input() {
    for value in [
        "sensitive-marker".repeat(8),
        "0".repeat(64),
        "f".repeat(64),
        "1".repeat(1000),
    ] {
        assert_eq!(
            ImportKey::from_hex(value.clone()).unwrap_err().to_string(),
            "invalid account import key"
        );
        let wire = serde_json::to_string(&value).unwrap();
        let error = serde_json::from_str::<ImportKey>(&wire)
            .unwrap_err()
            .to_string();
        assert!(error.starts_with("invalid account import key"));
        assert!(!error.contains(&value));
    }
}
