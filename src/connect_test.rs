//! Tests for [`super`].

use super::*;

fn example_dapp() -> AppMetadata {
    AppMetadata {
        name: "Example".to_owned(),
        url: "https://example.com".to_owned(),
        ..AppMetadata::default()
    }
}

#[test]
fn the_methods_offered_exclude_the_two_that_cannot_be_reviewed_or_tracked() {
    // `eth_sign` signs a bare digest, so no review can show what it
    // authorizes. `eth_signTransaction` hands signed bytes to the dapp, which
    // breaks the record this wallet reconciles nonces and cancellations from.
    assert!(!SUPPORTED_METHODS.contains(&"eth_sign"));
    assert!(!SUPPORTED_METHODS.contains(&"eth_signTransaction"));
    assert!(!SUPPORTED_METHODS.contains(&"wallet_addEthereumChain"));
    for expected in [
        "eth_sendTransaction",
        "personal_sign",
        "eth_signTypedData_v4",
        "eth_accounts",
    ] {
        assert!(
            SUPPORTED_METHODS.contains(&expected),
            "{expected} is missing"
        );
    }
}

#[test]
fn the_logged_request_records_what_the_dapp_asked_for_and_did_not_get() {
    let proposed = dapp_request::TransactionRequest {
        from: Address::ZERO,
        to: Address::ZERO,
        data: alloy::primitives::Bytes::new(),
        value: alloy::primitives::U256::ZERO,
        suggested_gas: Some(alloy::primitives::U256::from(21_000)),
        overridden: vec!["nonce".to_owned(), "gasPrice".to_owned()],
    };
    let line = describe_dapp_request(&example_dapp(), &proposed);
    // The log is a running account of who asked for what, and which site asked
    // is the first thing it has to answer; "a dapp" alone does not.
    assert!(line.contains("Example"), "{line}");
    assert!(line.contains("21000"), "{line}");
    assert!(line.contains("nonce, gasPrice"), "{line}");
    assert!(line.contains("ignored"), "{line}");
}

#[test]
fn a_logged_request_from_a_plain_proposal_stays_plain() {
    let proposed = dapp_request::TransactionRequest {
        from: Address::ZERO,
        to: Address::ZERO,
        data: alloy::primitives::Bytes::new(),
        value: alloy::primitives::U256::ZERO,
        suggested_gas: None,
        overridden: Vec::new(),
    };
    // The host, not the URL: it is the part a reader can compare against the
    // address bar they opened the site from.
    assert_eq!(
        describe_dapp_request(&example_dapp(), &proposed),
        "Example (example.com) proposed a transaction"
    );

    // A dapp that named itself nothing still produces a readable line.
    assert_eq!(
        describe_dapp_request(&AppMetadata::default(), &proposed),
        "an unnamed dapp proposed a transaction"
    );
}

/// The plan source names the dapp, but always behind the prefix: the same
/// field holds a TLS-proved host for a fetched plan, and a dapp free to call
/// itself anything must not be able to produce a value that reads like one.
#[test]
fn the_plan_source_marks_the_dapps_account_of_itself_as_claimed() {
    assert_eq!(
        describe_plan_source(&example_dapp()),
        "WalletConnect: Example (example.com)"
    );
    assert_eq!(
        describe_plan_source(&AppMetadata::default()),
        "WalletConnect: an unnamed dapp"
    );

    // A dapp naming itself after somewhere else still cannot produce a value
    // that reads as a verified host.
    let impostor = AppMetadata {
        name: "ekubo.org".to_owned(),
        url: "https://claim-rewards.xyz".to_owned(),
        ..AppMetadata::default()
    };
    let source = describe_plan_source(&impostor);
    assert!(source.starts_with("WalletConnect: "), "{source}");
    assert!(source.contains("claim-rewards.xyz"), "{source}");
}

/// The store validates this string on write *and* on read, and a value it
/// refuses fails the whole request — which is how every dapp transaction came
/// to die on "stored plan source is not a vetted host name". Nothing else
/// crosses the two modules, so this test does.
#[test]
fn every_plan_source_this_session_produces_is_one_the_store_accepts() {
    let long_name = "ﷺ".repeat(400);
    for dapp in [
        example_dapp(),
        AppMetadata::default(),
        AppMetadata {
            name: long_name,
            url: "https://example.com".to_owned(),
            ..AppMetadata::default()
        },
        AppMetadata {
            name: "Line\u{202e}break".to_owned(),
            url: "not a url".to_owned(),
            ..AppMetadata::default()
        },
    ] {
        let source = describe_plan_source(&dapp);
        assert!(
            source.len() <= crate::pending::MAX_PLAN_SOURCE_BYTES,
            "{} bytes: {source}",
            source.len()
        );
        crate::pending::validate_plan_source(Some(&source))
            .unwrap_or_else(|error| panic!("the store refuses `{source}`: {error}"));
    }
}

#[test]
fn an_empty_list_reads_as_none_rather_than_as_nothing() {
    assert_eq!(join_or_none(&[]), "none");
    assert_eq!(
        join_or_none(&["eip155:1".to_owned(), "eip155:10".to_owned()]),
        "eip155:1, eip155:10"
    );
}

#[test]
fn the_batch_methods_are_offered_together_or_not_at_all() {
    // A dapp told atomicity is supported will send `wallet_sendCalls` and then
    // poll `wallet_getCallsStatus`. Advertising the capability without both is
    // an answer that strands it.
    for method in [
        "wallet_getCapabilities",
        "wallet_sendCalls",
        "wallet_getCallsStatus",
    ] {
        assert!(SUPPORTED_METHODS.contains(&method), "{method} is missing");
    }
}

#[test]
fn a_batch_id_survives_the_round_trip_and_nothing_else_parses_as_one() {
    let request_id = uuid::Uuid::from_u128(0x0123_4567_89ab_cdef_0123_4567_89ab_cdef);
    let id = batch_id(request_id);
    assert_eq!(id, "0x0123456789abcdef0123456789abcdef");
    assert_eq!(parse_batch_id(&id), Some(request_id));
    // A dapp asking about an id this wallet never minted gets "unknown batch",
    // which needs these to fail rather than panic.
    for wrong in ["0x", "0xnothex", "0x0123", &"0xab".repeat(40)] {
        assert_eq!(parse_batch_id(wrong), None, "{wrong} parsed as a batch id");
    }
}

/// The one status EIP-5792 defines that this wallet can never report is 600,
/// partial revert — a multi-call plan is one `revertOnFailure` batch, so there
/// is no half-executed outcome to describe.
#[test]
fn every_record_status_maps_to_a_batch_status_and_none_is_partial() {
    use crate::pending::PendingStatus::{
        AwaitingApproval, Broadcast, Cancelled, Cancelling, Confirmed, Rejected, Replaced,
        Reverted, Signed, Submitting,
    };

    for pending in [AwaitingApproval, Signed, Submitting, Broadcast, Cancelling] {
        assert_eq!(calls_status_code(pending), 100, "{pending:?}");
    }
    assert_eq!(calls_status_code(Confirmed), 200);
    // Onchain and reverted as a whole, which is 500 rather than 400: gas was
    // charged and the dapp needs to know the difference.
    assert_eq!(calls_status_code(Reverted), 500);
    for offchain in [Rejected, Cancelled, Replaced] {
        assert_eq!(calls_status_code(offchain), 400, "{offchain:?}");
    }
}

#[test]
fn a_reported_receipt_carries_every_field_the_spec_names() {
    use alloy::primitives::B256;

    let receipt = crate::rpc::ReceiptDetails {
        succeeded: true,
        block_number: 0x123,
        block_hash: B256::repeat_byte(0xbb),
        gas_used: 21_000,
        effective_gas_price: 1_000_000_000,
        logs: vec![crate::rpc::ReceiptLog {
            address: Address::repeat_byte(0xcc),
            topics: vec![B256::repeat_byte(0xdd)],
            data: vec![0x01, 0x02],
        }],
    };
    let json = receipt_json("0xfeed", &receipt);
    assert_eq!(json["status"], "0x1");
    assert_eq!(json["blockNumber"], "0x123");
    assert_eq!(json["gasUsed"], "0x5208");
    assert_eq!(json["transactionHash"], "0xfeed");
    assert_eq!(json["blockHash"].as_str().unwrap().len(), 66);
    assert_eq!(json["logs"][0]["data"], "0x0102");
    assert_eq!(json["logs"][0]["topics"].as_array().unwrap().len(), 1);
}

/// The session screen must not blink out when a request is merely answered.
///
/// Suspending the idle surface leaves the alternate screen, and the session
/// loop re-enters it on its next turn — so a `suspend_idle` covering every
/// request made the whole screen flash on every answer, including for methods
/// that draw nothing at all. Only a path that actually draws may release it.
///
/// Read from the source because there is nothing else to read: the defect is a
/// terminal doing something visible, and no assertion about a return value
/// catches it.
#[test]
fn answering_a_request_does_not_release_the_session_screen() {
    let source = include_str!("connect.rs");
    let start = source
        .find("async fn handle_request")
        .expect("handle_request is gone");
    let body = &source[start..];
    let end = body[1..]
        .find("\n    fn ")
        .or_else(|| body[1..].find("\n    async fn "))
        .expect("handle_request has no successor")
        + 1;
    // The call, not the name: the comment in that body explains why the call
    // is absent, and a test that cannot tell them apart fails on the
    // explanation.
    assert!(
        !body[..end].contains("self.suspend_idle("),
        "handle_request suspends the idle surface for every request, which flashes the session \
         screen on each answer. Suspend inside the path that draws instead."
    );
}

/// A batch's status has to be read from the chain, not from storage.
///
/// A broadcast record is written as `Broadcast` and nothing moves it to
/// `Confirmed` except a reconciliation against the chain. Answering
/// `wallet_getCallsStatus` from the stored row alone therefore reports 100,
/// "not completed", for a batch that mined long ago — and keeps reporting it
/// for as long as the dapp polls, because polling is not what settles a
/// record.
///
/// `eth_sendTransaction` hides this: it hands back a transaction hash and the
/// dapp watches the chain itself, so the wallet is never asked. Only the batch
/// path routes status through this wallet, which is why only the batch path
/// can be wrong about it.
#[test]
fn a_batch_status_is_reconciled_against_the_chain_before_it_is_reported() {
    let source = include_str!("connect.rs");
    let start = source
        .find("async fn calls_status")
        .expect("calls_status is gone");
    let body = &source[start..];
    let end = body[1..]
        .find("\n    fn ")
        .or_else(|| body[1..].find("\n    async fn "))
        .expect("calls_status has no successor")
        + 1;
    assert!(
        body[..end].contains("reconcile_record("),
        "calls_status answers from the stored record without reconciling, so a mined batch \
         reports as pending for as long as the dapp asks"
    );
}

mod legal_currency_tests {
    //! Acceptance is live state, so a session cannot rest on having checked it.

    /// The window this closes is the long one. `run` checks acceptance before
    /// the session exists; a session then lasts as long as the dapp keeps it
    /// open. Publishing new terms makes an existing acceptance stale -- the
    /// status is derived from the current document digests -- so a session
    /// opened this morning would keep signing all day under documents the
    /// owner has not accepted, while the MCP server refuses every tool call
    /// and every CLI command refuses on entry.
    ///
    /// Pinned in the source because standing this up behaviourally means a
    /// paired relay, a settled session, and a dapp: the property is that the
    /// check is in `dispatch`, before the method is looked at, so a method
    /// added later is covered by having been dispatched rather than by someone
    /// remembering.
    #[test]
    fn every_dapp_request_rechecks_acceptance_before_its_method_is_read() {
        let source = include_str!("connect.rs");
        let body = source
            .split_once("async fn dispatch(&self, request: &DappRequest<'_>)")
            .expect("dispatch is declared")
            .1;
        let checked = body
            .find("legal::require_current_acceptance")
            .expect("dispatch rechecks acceptance");
        let matched = body.find("match request.method").expect("it dispatches");
        assert!(
            checked < matched,
            "acceptance must be checked before the method is looked at, so a new method \
             cannot be added without it"
        );
        let replaced = body
            .find("refuse_replaced_account")
            .expect("it also rechecks the account");
        assert!(
            checked < replaced,
            "a wallet disabled by lapsed terms is refused for that reason, not for a \
             later one"
        );
    }

    /// And the claim in the kernel matches what the kernel does. The sentence
    /// this replaces said the signing paths repeated the check as defense in
    /// depth. They do not -- `load_matching_signer`, which every signature in
    /// the process passes through, never sees it -- and a comment asserting a
    /// security property the code does not have is worse than no comment,
    /// because it is what a reader checks instead of the code.
    #[test]
    fn the_kernel_does_not_claim_a_check_it_does_not_make() {
        let legal = include_str!("../crates/ekubo-wallet-core/src/legal.rs");
        assert!(
            !legal.contains("the signing paths repeat it as defense in depth"),
            "the signing paths do not call this"
        );
        assert!(
            legal.contains("It is **not** called by the signing paths themselves"),
            "and the doc comment says so, with what closing that would take"
        );
    }
}

mod disconnect_intent_tests {
    //! A disconnect asked for once stays asked for.

    /// The flag has to belong to the session, not to the surface that happened
    /// to be on screen when the key was pressed. `suspend_idle` drops the view
    /// around every review and `enter_idle` builds a new one, so a `q`,
    /// Escape, or Ctrl-C that lands while relay delivery wins the session
    /// `select!` used to set a flag on a view that was then thrown away --
    /// and the replacement started out saying no. The disconnect was not
    /// delayed, it was gone, and the dapp stayed connected to a person who
    /// believed they had left.
    ///
    /// Read from the source because standing the race up needs a relay, a
    /// settled session, and a terminal. What is checkable is the ownership:
    /// one flag, constructed once with the session, handed to each view.
    #[test]
    fn the_disconnect_flag_outlives_the_screen_that_recorded_it() {
        let screen = include_str!("connect_screen.rs");
        assert!(
            !screen.contains("let quit = Arc::new(AtomicBool::new(false));"),
            "an idle view must not mint its own disconnect flag; it is handed the session's"
        );
        assert!(
            screen.contains("pub fn start(state: Arc<Mutex<SessionState>>, quit: Arc<AtomicBool>)"),
            "the view takes the flag rather than making one"
        );

        let connect = include_str!("connect.rs");
        assert_eq!(
            connect.matches("Arc::new(AtomicBool::new(false))").count(),
            1,
            "exactly one disconnect flag exists, and the session owns it"
        );
        assert!(
            connect.contains("IdleView::start(Arc::clone(&self.state), Arc::clone(&self.quit))"),
            "every view started shares that one flag"
        );
    }

    /// And a request arriving after the answer was given does not undo it. The
    /// session loop selects between the relay and the quit future, so delivery
    /// can win that race and reach dispatch with the disconnect already asked
    /// for. The loop honours it on its next turn; this is what keeps the
    /// interval from being one more signature.
    #[test]
    fn a_request_that_won_the_race_is_refused_rather_than_handled() {
        let connect = include_str!("connect.rs");
        let body = connect
            .split_once("async fn dispatch(&self, request: &DappRequest<'_>)")
            .expect("dispatch is declared")
            .1;
        let quit = body
            .find("self.quit_pending()")
            .expect("dispatch checks it");
        let matched = body.find("match request.method").expect("it dispatches");
        assert!(
            quit < matched,
            "the disconnect is honoured before the method is looked at"
        );
    }
}

mod fresh_input_tests {
    //! A keystroke typed at one surface is not an answer to the next one.

    /// `confirm_review` starts its decision on the safe answer, but a buffered
    /// `Tab` toggles it and a buffered `Enter` returns it -- so two keystrokes
    /// typed at whatever was previously on the terminal affirm a document
    /// nobody saw. It is the shared confirmation behind legal acceptance,
    /// policy proposals, network proposals, and direct network edits.
    ///
    /// `approve_tui` and the inline prompts already drained. The fix is not a
    /// third call site but the one door: `Screen::enter` is the only route
    /// into the alternate screen, so draining there covers every full-screen
    /// surface that exists and every one added later.
    #[test]
    fn entering_the_alternate_screen_discards_earlier_keystrokes() {
        let fullscreen = include_str!("fullscreen.rs");
        let enter = fullscreen
            .split_once("pub(crate) fn enter() -> Result<Self> {")
            .expect("Screen::enter is declared")
            .1;
        let body = enter.split_once("\n    }").expect("its body ends").0;
        let drained = body
            .find("drain_type_ahead")
            .expect("entering a screen drains what was typed at the last one");
        let raw = body
            .find("enable_raw_mode")
            .expect("raw mode is enabled first");
        let entered = body
            .find("EnterAlternateScreen")
            .expect("the screen is then entered");
        assert!(
            raw < drained,
            "drain after enabling raw mode, or the keystrokes are still in the line discipline"
        );
        assert!(
            drained < entered,
            "drain before the screen exists, so nothing can be read at it first"
        );
    }

    /// And that door is the only one. A surface that entered the alternate
    /// screen by itself would skip the drain without changing this file.
    #[test]
    fn there_is_exactly_one_route_into_the_alternate_screen() {
        let mut entries = 0;
        for source in [
            include_str!("fullscreen.rs"),
            include_str!("approve_tui.rs"),
            include_str!("pager.rs"),
            include_str!("tx_browser.rs"),
            include_str!("connect_screen.rs"),
        ] {
            entries += source
                .lines()
                .filter(|line| {
                    line.contains("EnterAlternateScreen") && !line.trim_start().starts_with("//")
                })
                .filter(|line| !line.contains("terminal::{"))
                .count();
        }
        assert_eq!(
            entries, 1,
            "every full-screen surface must take the terminal through `Screen::enter`"
        );
    }
}
