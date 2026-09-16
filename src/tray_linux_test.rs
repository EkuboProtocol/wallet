use super::*;

fn snapshot(pending_reviews: usize) -> TraySnapshot {
    TraySnapshot {
        pending_reviews,
        mcp_online: true,
        walletconnect_sessions: 1,
    }
}

#[test]
fn tray_identity_is_distinct_from_v1() {
    let item = StatusNotifierItem(SharedState {
        snapshot: Arc::new(RwLock::new(snapshot(0))),
        pixmap: Arc::new(RwLock::new(Vec::new())),
        revision: Arc::new(AtomicU32::new(1)),
    });
    assert_eq!(item.id(), "ekubo-wallet-v2");
    assert_ne!(item.id(), "ekubo-wallet");
}

#[test]
fn dbus_menu_layout_contains_the_complete_stable_order() {
    let layout = layout(0, &snapshot(2), &[]).unwrap();
    assert_eq!(layout.children.len(), 8);
    let properties = menu_properties(MENU_REVIEWS, &snapshot(2)).unwrap();
    let label = properties["label"].downcast_ref::<Str<'_>>().unwrap();
    assert_eq!(label.as_str(), "2 requests waiting for you");
}

#[test]
fn disabled_review_item_does_not_queue_a_command() {
    let state = SharedState {
        snapshot: Arc::new(RwLock::new(snapshot(0))),
        pixmap: Arc::new(RwLock::new(Vec::new())),
        revision: Arc::new(AtomicU32::new(1)),
    };
    let menu = DbusMenu(state);
    assert!(
        menu.event(MENU_REVIEWS, "clicked".into(), OwnedValue::from(0_u8), 0)
            .is_err()
    );
}

#[test]
fn linux_icon_pixmap_is_argb_and_exactly_square() {
    for dark_mode in [false, true] {
        let pixmaps = icon_pixmap(dark_mode).unwrap();
        assert_eq!(pixmaps.len(), 1);
        let (width, height, bytes) = &pixmaps[0];
        assert_eq!((*width, *height), (32, 32));
        assert_eq!(bytes.len(), 32 * 32 * 4);
    }
}

#[test]
fn linux_icon_pixmap_is_monochrome_for_each_theme() {
    for (dark_mode, bright) in [(false, false), (true, true)] {
        let (_, _, bytes) = &icon_pixmap(dark_mode).unwrap()[0];
        let mut opaque = 0_u64;
        let mut total = 0_u64;
        let (pixels, _) = bytes.as_chunks::<4>();
        for pixel in pixels {
            let [alpha, red, green, blue] = [pixel[0], pixel[1], pixel[2], pixel[3]];
            if alpha == 0 {
                continue;
            }
            assert_eq!(
                (red, green, blue),
                (red, red, red),
                "tray pixel is not monochrome"
            );
            opaque += 1;
            total += u64::from(red);
        }
        assert!(opaque > 0, "tray icon has no visible pixels");
        if bright {
            assert!(total > 200 * opaque, "dark-mode tray icon is not bright");
        } else {
            assert!(total < 55 * opaque, "light-mode tray icon is not dark");
        }
    }
}
