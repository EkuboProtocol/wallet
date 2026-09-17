//! Run with default production features, NEVER `--all-features`. The child
//! isolates the system-bus address so this refusal test cannot prompt a human
//! or touch a running wallet. No `TestHumanPresence` or `for_test` proof is used.
#![cfg(all(
    not(feature = "test-hooks"),
    any(target_os = "linux", target_os = "windows")
))]

#[test]
fn protected_mutations_require_native_authentication() {
    const CHILD: &str = "EKUBO_OWNER_PRESENCE_BOUNDARY_CHILD";
    if std::env::var_os(CHILD).is_none() {
        let scratch = tempfile::tempdir().unwrap();
        let result = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "protected_mutations_require_native_authentication",
                "--nocapture",
            ])
            .env(CHILD, scratch.path())
            .env(
                "DBUS_SYSTEM_BUS_ADDRESS",
                format!("unix:path={}/absent-bus", scratch.path().display()),
            )
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "{}\n{}",
            String::from_utf8_lossy(&result.stdout),
            String::from_utf8_lossy(&result.stderr)
        );
        return;
    }
    let directory =
        std::path::PathBuf::from(std::env::var_os(CHILD).unwrap()).join("must-not-exist");
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        for document in [
            ekubo_wallet_core::legal::LegalDocument::TermsOfService,
            ekubo_wallet_core::legal::LegalDocument::PrivacyPolicy,
        ] {
            let error = ekubo_wallet_core::human_presence::accept_legal(
                &directory,
                document,
                &document.digest(),
            )
            .await
            .unwrap_err();
            assert!(
                error
                    .downcast_ref::<ekubo_wallet_core::human_presence::HumanPresenceError>()
                    .is_some(),
                "{error:#}"
            );
        }
        let error = ekubo_wallet_core::human_presence::clear_activity_history(&directory)
            .await
            .unwrap_err();
        assert!(
            error
                .downcast_ref::<ekubo_wallet_core::human_presence::HumanPresenceError>()
                .is_some(),
            "{error:#}"
        );
        let error = ekubo_wallet_core::human_presence::delete_stopped_automation(
            &directory,
            uuid::Uuid::new_v4(),
        )
        .await
        .unwrap_err();
        assert!(
            error
                .downcast_ref::<ekubo_wallet_core::human_presence::HumanPresenceError>()
                .is_some(),
            "{error:#}"
        );
    });
    assert!(
        !directory.exists(),
        "a refused call must not even open persistent state"
    );
}
