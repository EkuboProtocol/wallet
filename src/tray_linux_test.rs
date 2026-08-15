use super::*;

fn snapshot(pending_reviews: usize) -> TraySnapshot {
    TraySnapshot {
        pending_reviews,
        mcp_online: true,
        walletconnect_sessions: 1,
    }
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
        pixmap: Arc::new(Vec::new()),
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
    let pixmaps = icon_pixmap().unwrap();
    assert_eq!(pixmaps.len(), 1);
    let (width, height, bytes) = &pixmaps[0];
    assert_eq!((*width, *height), (32, 32));
    assert_eq!(bytes.len(), 32 * 32 * 4);
}
