use super::*;
use ekubo_wallet_core::policy_store::DatabaseKey;

#[test]
fn owner_management_can_find_disabled_configured_chains() {
    let directory = tempfile::tempdir().unwrap();
    let store = ConfigStore::new(directory.path());
    let mut config = store.load().unwrap();
    let chain_id = config.networks[0].chain_id;
    config.networks[0].disabled = true;

    assert!(contains_configured_chain(&config, chain_id));
    assert!(!contains_configured_chain(&config, u64::MAX));
}

#[test]
fn exact_review_payloads_escape_invisible_and_bidirectional_text() {
    let rendered = escape_review_payload("safe\namount\u{202e}123\u{200b}");
    assert!(rendered.starts_with("safe\namount"));
    assert!(rendered.contains("\\u{202e}"));
    assert!(rendered.contains("\\u{200b}"));
    assert!(!rendered.contains('\u{202e}'));
    assert!(!rendered.contains('\u{200b}'));
}

#[derive(Default)]
struct TestClipboard(Mutex<Option<String>>);

impl Clipboard for TestClipboard {
    fn read_text(&self) -> Result<Option<String>> {
        Ok(self.0.lock().unwrap().clone())
    }

    fn write_text(&self, value: &str) -> Result<()> {
        *self.0.lock().unwrap() = Some(value.to_owned());
        Ok(())
    }

    fn clear(&self) -> Result<()> {
        *self.0.lock().unwrap() = None;
        Ok(())
    }
}

#[test]
fn export_lease_conceals_and_conditionally_clears_its_clipboard_value() {
    let clipboard = Arc::new(TestClipboard::default());
    let lease = ExportLease::new_for_duration(
        zeroize::Zeroizing::new("secret".to_owned()),
        Duration::from_millis(20),
    );
    lease.copy_explicitly(clipboard.clone()).unwrap();
    assert_eq!(clipboard.read_text().unwrap().as_deref(), Some("secret"));
    std::thread::sleep(Duration::from_millis(50));
    assert!(lease.concealed());
    assert_eq!(clipboard.read_text().unwrap(), None);

    let clipboard = Arc::new(TestClipboard::default());
    let lease = ExportLease::new_for_duration(
        zeroize::Zeroizing::new("secret".to_owned()),
        Duration::from_millis(20),
    );
    lease.copy_explicitly(clipboard.clone()).unwrap();
    clipboard.write_text("new clipboard value").unwrap();
    std::thread::sleep(Duration::from_millis(50));
    assert_eq!(
        clipboard.read_text().unwrap().as_deref(),
        Some("new clipboard value")
    );
}

#[tokio::test]
async fn notification_preview_preference_is_owner_controlled_and_persisted() {
    let directory = tempfile::tempdir().unwrap();
    let database = directory.path().join("wallet.db");
    let desktop = DesktopStore::open(&database, &DatabaseKey::new([13; 32])).unwrap();
    let owner = OwnerApi {
        config: ConfigStore::open(directory.path(), DatabaseKey::new([13; 32])),
        desktop: Arc::new(Mutex::new(desktop)),
        events: EventBus::default(),
    };
    let mut events = owner.event_bus().subscribe();

    assert!(!owner.detailed_notification_previews().unwrap());
    owner
        .set_detailed_notification_previews(true)
        .await
        .unwrap();
    assert!(owner.detailed_notification_previews().unwrap());
    assert!(matches!(
        events.try_recv().unwrap().kind,
        DomainEventKind::ConfigurationChanged
    ));

    owner
        .set_detailed_notification_previews(false)
        .await
        .unwrap();
    assert!(!owner.detailed_notification_previews().unwrap());
}

#[tokio::test]
async fn automatic_update_preference_is_owner_controlled_and_persisted() {
    let directory = tempfile::tempdir().unwrap();
    let database = directory.path().join("wallet.db");
    let desktop = DesktopStore::open(&database, &DatabaseKey::new([19; 32])).unwrap();
    let owner = OwnerApi {
        config: ConfigStore::open(directory.path(), DatabaseKey::new([19; 32])),
        desktop: Arc::new(Mutex::new(desktop)),
        events: EventBus::default(),
    };

    assert!(owner.automatic_update_checks().unwrap());
    owner.set_automatic_update_checks(false).await.unwrap();
    assert!(!owner.automatic_update_checks().unwrap());
}

#[test]
fn appearance_preference_is_core_owned_and_publishes_configuration_changes() {
    let directory = tempfile::tempdir().unwrap();
    let database = directory.path().join("wallet.db");
    let desktop = DesktopStore::open(&database, &DatabaseKey::new([20; 32])).unwrap();
    let owner = OwnerApi {
        config: ConfigStore::open(directory.path(), DatabaseKey::new([20; 32])),
        desktop: Arc::new(Mutex::new(desktop)),
        events: EventBus::default(),
    };
    let mut events = owner.event_bus().subscribe();

    assert_eq!(
        owner.appearance_preference().unwrap(),
        AppearancePreference::System
    );
    owner
        .set_appearance_preference(AppearancePreference::Dark)
        .unwrap();
    assert_eq!(
        owner.appearance_preference().unwrap(),
        AppearancePreference::Dark
    );
    assert!(matches!(
        events.try_recv().unwrap().kind,
        DomainEventKind::ConfigurationChanged
    ));
}

#[test]
fn policy_revision_revalidation_handles_initial_and_replacement_writes() {
    assert!(ensure_optional_revision(None, None).is_ok());
    assert!(ensure_optional_revision(Some(3), Some(3)).is_ok());
    assert!(ensure_optional_revision(None, Some(1)).is_err());
    assert!(ensure_optional_revision(Some(1), None).is_err());
    assert!(ensure_optional_revision(Some(2), Some(3)).is_err());
}

#[test]
fn owner_token_imports_select_only_enabled_networks() {
    let directory = tempfile::tempdir().unwrap();
    let database = directory.path().join("wallet.db");
    let desktop = DesktopStore::open(&database, &DatabaseKey::new([17; 32])).unwrap();
    let owner = OwnerApi {
        config: ConfigStore::open(directory.path(), DatabaseKey::new([17; 32])),
        desktop: Arc::new(Mutex::new(desktop)),
        events: EventBus::default(),
    };
    let snapshot = owner.snapshot().unwrap();
    let mut expected = snapshot
        .networks
        .iter()
        .filter(|network| !network.disabled)
        .map(|network| network.chain_id)
        .collect::<Vec<_>>();
    expected.sort_unstable();

    assert_eq!(owner.enabled_token_import_chains(&[]).unwrap(), expected);
    let disabled = snapshot
        .networks
        .iter()
        .find(|network| network.disabled)
        .expect("defaults include disabled networks");
    assert!(
        owner
            .enabled_token_import_chains(&[disabled.chain_id])
            .is_err()
    );
}

#[tokio::test]
async fn owner_network_reset_persists_defaults_and_publishes_the_change() {
    let directory = tempfile::tempdir().unwrap();
    let database = directory.path().join("wallet.db");
    let desktop = DesktopStore::open(&database, &DatabaseKey::new([23; 32])).unwrap();
    let owner = OwnerApi {
        config: ConfigStore::open(directory.path(), DatabaseKey::new([23; 32])),
        desktop: Arc::new(Mutex::new(desktop)),
        events: EventBus::default(),
    };
    owner
        .config
        .update_for_test(|config| {
            config.networks[0].display_name = Some("Owner-edited name".into());
            Ok(())
        })
        .unwrap();
    let reviewed = owner.networks().unwrap();
    let mut events = owner.event_bus().subscribe();

    let reset = owner.reset_networks_to_defaults(&reviewed).await.unwrap();

    assert_eq!(reset, ekubo_wallet_core::config::default_networks());
    assert_eq!(owner.networks().unwrap(), reset);
    assert!(matches!(
        events.try_recv().unwrap().kind,
        DomainEventKind::ConfigurationChanged
    ));
    assert_eq!(
        owner.network_presets().len(),
        ekubo_wallet_core::networks::known_networks().len()
    );
}
