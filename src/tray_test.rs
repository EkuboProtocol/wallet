use super::*;

#[test]
fn tray_icon_has_valid_dimensions() {
    assert!(wallet_icon(false).is_ok());
    assert!(wallet_icon(true).is_ok());
}

#[test]
fn application_badge_is_hidden_at_zero_and_exact_above_zero() {
    assert_eq!(application_badge_label(0), None);
    assert_eq!(application_badge_label(1).as_deref(), Some("1"));
    assert_eq!(application_badge_label(137).as_deref(), Some("137"));
}

#[cfg(target_os = "macos")]
#[test]
fn macos_tray_artwork_is_inset_without_changing_its_canvas() {
    let source = image::load_from_memory_with_format(
        include_bytes!("../assets/tray/light_mode_tray_icon.png"),
        image::ImageFormat::Png,
    )
    .unwrap()
    .into_rgba8();
    let source_dimensions = source.dimensions();
    let inset = scaled_tray_artwork(&source);

    assert_eq!(inset.dimensions(), source_dimensions);
    assert_eq!(inset.get_pixel(0, 0).0[3], 0);
    assert_eq!(
        inset
            .get_pixel(source_dimensions.0 - 1, source_dimensions.1 - 1)
            .0[3],
        0
    );
}

#[cfg(target_os = "macos")]
#[test]
fn macos_uses_one_high_contrast_template_source_for_every_appearance() {
    #[allow(clippy::cast_precision_loss)]
    fn mean_luminance(encoded: &[u8]) -> f32 {
        let image = image::load_from_memory_with_format(encoded, image::ImageFormat::Png)
            .unwrap()
            .into_rgba8();
        let (total, count) = image.pixels().filter(|pixel| pixel.0[3] > 0).fold(
            (0_u64, 0_u64),
            |(total, count), pixel| {
                let [red, green, blue, _] = pixel.0;
                (
                    total + u64::from(red) + u64::from(green) + u64::from(blue),
                    count + 3,
                )
            },
        );
        total as f32 / count as f32
    }

    assert!(mean_luminance(macos_tray_artwork()) > 220.0);
    assert!(wallet_icon(false).is_ok());
    assert!(wallet_icon(true).is_ok());
}

#[test]
fn native_menu_ids_map_to_the_expected_commands() {
    assert_eq!(command_for_id(OPEN_ID), Some(TrayCommand::OpenWallet));
    assert_eq!(
        command_for_id(REVIEWS_ID),
        Some(TrayCommand::OpenRoute(Route::Activity))
    );
    assert_eq!(
        command_for_id(CONNECT_ID),
        Some(TrayCommand::OpenRoute(Route::WalletConnect))
    );
    assert_eq!(
        command_for_id(SETTINGS_ID),
        Some(TrayCommand::OpenRoute(Route::Settings))
    );
    assert_eq!(
        command_for_id(UPDATES_ID),
        Some(TrayCommand::CheckForUpdates)
    );
    assert_eq!(command_for_id(QUIT_ID), Some(TrayCommand::Quit));
    assert_eq!(command_for_id("unknown"), None);
}

#[test]
fn no_two_menu_items_issue_the_same_command() {
    // The agent-status line used to open Settings, which is what the
    // `Settings` item is for. A menu with two ways to do one thing reads as
    // though they differ.
    let commands = [
        OPEN_ID,
        REVIEWS_ID,
        CONNECT_ID,
        SETTINGS_ID,
        UPDATES_ID,
        QUIT_ID,
    ]
    .map(command_for_id)
    .to_vec();
    for (index, command) in commands.iter().enumerate() {
        assert!(command.is_some(), "menu item {index} does nothing");
        assert!(
            !commands[index + 1..].contains(command),
            "two menu items issue {command:?}"
        );
    }
    // The status line reports and nothing else.
    assert_eq!(command_for_id(AGENTS_ID), None);
}

#[test]
fn menu_labels_are_finished_sentences_without_trailing_ellipses() {
    let idle = TraySnapshot {
        pending_reviews: 0,
        mcp_online: false,
        connected_agents: 0,
        walletconnect_sessions: 0,
    };
    let busy = TraySnapshot {
        pending_reviews: 3,
        mcp_online: true,
        connected_agents: 2,
        walletconnect_sessions: 1,
    };

    assert_eq!(review_menu_text(0), "Nothing waiting for you");
    assert_eq!(review_menu_text(1), "1 request waiting for you");
    assert_eq!(review_menu_text(3), "3 requests waiting for you");

    assert_eq!(agent_menu_text(&idle), "Agents cannot connect right now");
    assert_eq!(
        agent_menu_text(&busy),
        "Ready for agents · 2 agents and 1 dapp connected"
    );
    assert_eq!(
        agent_menu_text(&TraySnapshot {
            connected_agents: 1,
            walletconnect_sessions: 0,
            ..busy.clone()
        }),
        "Ready for agents · 1 agent connected"
    );
    assert_eq!(
        agent_menu_text(&TraySnapshot {
            connected_agents: 0,
            walletconnect_sessions: 0,
            ..busy.clone()
        }),
        "Ready for agents · nothing connected"
    );

    assert_eq!(tray_tooltip(&idle), "Ekubo Wallet");
    assert_eq!(
        tray_tooltip(&busy),
        "Ekubo Wallet — 3 requests waiting for you"
    );

    for text in [
        review_menu_text(0),
        review_menu_text(2),
        agent_menu_text(&idle),
        agent_menu_text(&busy),
        tray_tooltip(&busy),
    ] {
        assert!(!text.contains('…'), "{text} still trails an ellipsis");
        assert!(
            !text.contains("(s)"),
            "{text} still uses a form-field plural"
        );
    }
}
