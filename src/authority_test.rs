use super::*;

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
