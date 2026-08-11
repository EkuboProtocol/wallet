use super::*;

struct MemoryPicker(Mutex<Option<CapturedFrame>>);

impl ScreenPicker for MemoryPicker {
    fn capture_once(&self) -> Result<Option<CapturedFrame>> {
        Ok(self.0.lock().unwrap().take())
    }
}

fn pairing_uri(topic: &str, key: &str) -> String {
    format!(
        "wc:{}@2?relay-protocol=irn&symKey={}",
        topic.repeat(32),
        key.repeat(32)
    )
}

fn qr_frame(contents: &[String]) -> CapturedFrame {
    let codes = contents
        .iter()
        .map(|content| {
            qrcode::QrCode::new(content.as_bytes())
                .unwrap()
                .render::<Luma<u8>>()
                .quiet_zone(true)
                .min_dimensions(240, 240)
                .build()
        })
        .collect::<Vec<_>>();
    let gap = 32_u32;
    let width = codes
        .iter()
        .map(GrayImage::width)
        .sum::<u32>()
        .saturating_add(gap.saturating_mul(u32::try_from(codes.len().saturating_sub(1)).unwrap()));
    let height = codes.iter().map(GrayImage::height).max().unwrap_or(1);
    let mut rgba = vec![255; usize::try_from(width * height * 4).unwrap()];
    let mut offset_x = 0_u32;
    for code in codes {
        for (x, y, pixel) in code.enumerate_pixels() {
            let index = usize::try_from(((y * width) + offset_x + x) * 4).unwrap();
            rgba[index] = pixel.0[0];
            rgba[index + 1] = pixel.0[0];
            rgba[index + 2] = pixel.0[0];
            rgba[index + 3] = 255;
        }
        offset_x = offset_x.saturating_add(code.width()).saturating_add(gap);
    }
    CapturedFrame {
        width,
        height,
        rgba,
    }
}

#[test]
fn malformed_and_expired_uris_never_create_sessions() {
    let mut manager = WalletConnectManager::default();
    assert!(manager.begin_uri("not-walletconnect").is_err());
    assert!(manager.sessions().is_empty());
    let expired = format!(
        "wc:{}@2?relay-protocol=irn&symKey={}&expiryTimestamp=1",
        "11".repeat(32),
        "22".repeat(32)
    );
    assert!(manager.begin_uri(&expired).is_err());
    assert!(manager.sessions().is_empty());
}

#[test]
fn manager_keeps_multiple_sessions_only_in_memory() {
    let mut manager = WalletConnectManager::default();
    for byte in ["11", "33"] {
        let uri = format!(
            "wc:{}@2?relay-protocol=irn&symKey={}",
            byte.repeat(32),
            "22".repeat(32)
        );
        manager.begin_uri(&uri).unwrap();
    }
    assert_eq!(manager.sessions().len(), 2);
    manager.disconnect_all();
    assert!(manager.sessions().is_empty());
}

#[test]
fn disconnect_cancels_the_live_session() {
    let mut manager = WalletConnectManager::default();
    let uri = format!(
        "wc:{}@2?relay-protocol=irn&symKey={}",
        "44".repeat(32),
        "55".repeat(32)
    );
    let (start, summary) = manager.begin_uri(&uri).unwrap();
    assert!(!start.shutdown.is_cancelled());
    let removed = manager.disconnect(summary.id).unwrap();
    assert_eq!(removed.id, summary.id);
    assert!(start.shutdown.is_cancelled());
    assert!(manager.sessions().is_empty());
}

#[test]
fn live_status_updates_preserve_the_dapp_name() {
    let mut manager = WalletConnectManager::default();
    let uri = format!(
        "wc:{}@2?relay-protocol=irn&symKey={}",
        "66".repeat(32),
        "77".repeat(32)
    );
    let (_, summary) = manager.begin_uri(&uri).unwrap();
    manager.update(
        summary.id,
        SessionStatus::Connected,
        Some("Example".into()),
        1,
    );
    manager.update(summary.id, SessionStatus::Connected, None, 0);
    let current = manager.sessions().pop().unwrap();
    assert_eq!(current.dapp_name.as_deref(), Some("Example"));
    assert_eq!(current.active_requests, 0);
}

#[test]
fn screen_scan_decodes_multiple_valid_pairings_and_keeps_only_qr_crops() {
    let first = pairing_uri("11", "22");
    let second = pairing_uri("33", "44");
    let full_frame = qr_frame(&[first.clone(), second.clone()]);
    let full_width = full_frame.width;
    let picker = MemoryPicker(Mutex::new(Some(full_frame)));

    let mut choices = scan_screen(&picker).unwrap().unwrap();
    assert_eq!(choices.len(), 2);
    let previews = choices.take_previews();
    assert_eq!(previews.len(), 2);
    assert!(previews.iter().all(|preview| preview.width < full_width));
    assert!(previews.iter().all(|preview| {
        preview.rgba.len() == usize::try_from(preview.width * preview.height * 4).unwrap()
    }));
    let selected = choices.take(0).unwrap();
    assert!(selected.as_str() == first || selected.as_str() == second);
}

#[test]
fn screen_scan_ignores_non_walletconnect_codes_and_handles_cancellation() {
    let invalid = "https://example.com/not-a-pairing".to_owned();
    let picker = MemoryPicker(Mutex::new(Some(qr_frame(&[invalid]))));
    assert!(scan_screen(&picker).unwrap().unwrap().is_empty());

    let cancelled = MemoryPicker(Mutex::new(None));
    assert!(scan_screen(&cancelled).unwrap().is_none());
}

#[test]
fn screen_scan_rejects_frames_with_inconsistent_dimensions() {
    let picker = MemoryPicker(Mutex::new(Some(CapturedFrame {
        width: 10,
        height: 10,
        rgba: vec![0; 12],
    })));
    assert!(scan_screen(&picker).is_err());
}

#[cfg(target_os = "macos")]
#[test]
fn macos_picker_output_is_decoded_with_bounded_png_dimensions() {
    let original = qr_frame(&[pairing_uri("55", "66")]);
    let image =
        image::RgbaImage::from_raw(original.width, original.height, original.rgba.clone()).unwrap();
    let mut encoded = Cursor::new(Vec::new());
    image::DynamicImage::ImageRgba8(image)
        .write_to(&mut encoded, image::ImageFormat::Png)
        .unwrap();

    let decoded = decode_png_capture(encoded.get_ref()).unwrap();
    assert_eq!(
        (decoded.width, decoded.height),
        (original.width, original.height)
    );
    assert_eq!(decoded.rgba.as_slice(), original.rgba.as_slice());
}
