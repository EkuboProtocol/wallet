use super::*;

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
    let lease = startup
        .find("DesktopStartup::start_service_session(")
        .unwrap();
    let capture = startup.find("InitialDesktopState::capture(").unwrap();
    assert!(enrollment < connection);
    assert!(connection < lease && lease < capture);
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
