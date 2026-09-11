use super::*;

#[test]
fn installed_profiles_never_open_local_authority_even_when_service_startup_fails() {
    for fail in [false, true] {
        let result = select(
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
        Err(anyhow::anyhow!("unsafe metadata")),
        || panic!("local fallback"),
        || panic!("service startup"),
    );
    assert!(result.unwrap_err().to_string().contains("unsafe metadata"));
}

#[test]
fn absent_profile_uses_the_existing_local_path() {
    assert_eq!(
        select(
            Ok(false),
            || Ok(42),
            || panic!("unexpected service activation")
        )
        .unwrap(),
        42
    );
}
