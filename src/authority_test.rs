use super::*;
use ekubo_wallet_core::policy_store::DatabaseKey;

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

#[test]
fn policy_revision_revalidation_handles_initial_and_replacement_writes() {
    assert!(ensure_optional_revision(None, None).is_ok());
    assert!(ensure_optional_revision(Some(3), Some(3)).is_ok());
    assert!(ensure_optional_revision(None, Some(1)).is_err());
    assert!(ensure_optional_revision(Some(1), None).is_err());
    assert!(ensure_optional_revision(Some(2), Some(3)).is_err());
}
