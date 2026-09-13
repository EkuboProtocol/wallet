use super::*;

#[test]
fn pending_cleanup_overrides_populated_accounts_and_continue_marker_but_complete_never_reenters() {
    let binding = ekubo_wallet_core::legacy_move::MoveBinding {
        profile: uuid::Uuid::new_v4(),
        source: std::env::temp_dir().join("source"),
        preserved_profiles: vec![],
        retained_shared_accounts: vec![uuid::Uuid::new_v4()],
    };
    let pending = MoveStatus::PendingCleanup {
        digest: [1; 32],
        binding: binding.clone(),
    };
    for empty in [false, true] {
        for continued in [false, true] {
            assert!(show_move(&pending, empty, continued));
            assert!(!show_move(
                &MoveStatus::Complete {
                    binding: binding.clone(),
                    shared_database_credential_retained: true,
                },
                empty,
                continued
            ));
        }
    }
    assert!(show_move(&MoveStatus::Baseline, true, false));
    assert!(!show_move(&MoveStatus::Baseline, false, false));
    assert!(!show_move(&MoveStatus::Baseline, true, true));
}

#[test]
fn setup_routes_only_fixed_coordinator_actions() {
    assert_eq!(SetupAction::Install.argument(), "--owner");
    assert_eq!(SetupAction::Resume.argument(), "--resume-owner");
    assert_eq!(SetupAction::DiscardUnused.argument(), "--discard-unused");
    assert!(coordinator_path().unwrap().is_absolute());
}

#[test]
fn setup_and_first_run_choice_precede_authority_and_execution_activation() {
    let source = include_str!("desktop.rs");
    let startup = source
        .split_once("fn run_desktop_with_visibility(")
        .unwrap()
        .1;
    let enrollment = startup.find("service_setup::run(").unwrap();
    let connection = startup.find("DesktopStartup::open(").unwrap();
    let choice = startup.find("service_setup::first_run(").unwrap();
    let lease = startup
        .find("DesktopStartup::start_service_session(")
        .unwrap();
    let capture = startup.find("InitialDesktopState::capture(").unwrap();
    assert!(enrollment < connection);
    assert!(connection < choice && choice < lease && lease < capture);
    let adapter = include_str!("desktop_startup.rs");
    let service_open = adapter
        .split_once("fn service(runtime:")
        .unwrap()
        .1
        .split_once("fn start_service_session(")
        .unwrap()
        .0;
    assert!(!service_open.contains("start_desktop_session()"));
}
