use super::*;

#[test]
fn installed_profiles_never_open_local_authority_even_when_service_startup_fails() {
    for fail in [false, true] {
        let result = select(
            true,
            Ok(true),
            || -> Result<()> { panic!("local custody must remain unopened") },
            || {
                anyhow::ensure!(!fail, "service unavailable");
                Ok(())
            },
        );
        assert_eq!(result.is_err(), fail);
    }
}

#[test]
fn invalid_installation_metadata_never_falls_back_to_local_or_service() {
    let result = select::<()>(
        true,
        Err(anyhow::anyhow!("unsafe metadata")),
        || panic!("local fallback"),
        || panic!("service startup"),
    );
    assert!(result.unwrap_err().to_string().contains("unsafe metadata"));
}

#[test]
fn macos_absent_profile_uses_its_separate_local_path() {
    assert_eq!(
        select(
            false,
            Ok(false),
            || Ok(42),
            || panic!("unexpected service activation")
        )
        .unwrap(),
        42
    );
}

#[test]
fn service_platforms_require_setup_instead_of_creating_local_authority() {
    let error = select::<()>(
        true,
        Ok(false),
        || panic!("local custody opened"),
        || panic!("missing service activated"),
    )
    .unwrap_err()
    .to_string();
    assert!(error.contains("signed Ekubo Wallet 2 installer"));
}
