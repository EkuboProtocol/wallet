//! Tests for [`super`].

use super::*;

const PROJECT_ID: &str = "0123456789abcdef0123456789abcdef";
const USER_AGENT: &str = "wc-2/rust-test-wallet-1.0/cli";

fn config(url: &str) -> RelayConfig {
    RelayConfig::new(Url::parse(url).unwrap(), PROJECT_ID, USER_AGENT)
}

#[test]
fn the_connection_url_carries_the_token_the_project_and_the_agent() {
    let identity = ClientIdentity::generate().unwrap();
    let url = authenticated_url(&config(DEFAULT_RELAY_URL), &identity).unwrap();
    let query: std::collections::HashMap<_, _> = url.query_pairs().into_owned().collect();
    assert!(query.contains_key("auth"));
    assert_eq!(query.get("projectId").map(String::as_str), Some(PROJECT_ID));
    assert_eq!(query.get("ua").map(String::as_str), Some(USER_AGENT));
}

#[test]
fn the_token_audience_is_the_relay_without_its_query_string() {
    use base64::Engine as _;

    let identity = ClientIdentity::generate().unwrap();
    // A relay URL that already carries a query, and a trailing slash: signing
    // the full URL would sign the token into its own audience.
    let url = authenticated_url(&config("wss://relay.example.org/?region=eu"), &identity).unwrap();
    let query: std::collections::HashMap<_, _> = url.query_pairs().into_owned().collect();
    let payload = query["auth"].split('.').nth(1).unwrap().to_owned();
    let payload: serde_json::Value = serde_json::from_slice(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(payload)
            .unwrap(),
    )
    .unwrap();
    assert_eq!(payload["aud"], "wss://relay.example.org");
    // The relay's own parameters survive alongside the ones added here.
    assert_eq!(query.get("region").map(String::as_str), Some("eu"));
}

#[test]
fn relay_call_ids_are_timestamps_rather_than_a_counter() {
    // A counter starting at 1 is answered `Invalid request ID` by the relay on
    // the first `irn_subscribe`, so the session pairs and then never hears
    // anything. The id has to look like microseconds since the epoch.
    let salt = AtomicU16::new(0);
    let first = next_call_id(&salt);
    let second = next_call_id(&salt);
    let now_micros =
        u64::try_from(chrono::Utc::now().timestamp_millis()).unwrap() * 1000 + 1_000_000;
    assert!(first > 1_700_000_000_000_000, "{first}");
    assert!(first < now_micros, "{first}");
    // Two calls in the same millisecond still get different ids, or the second
    // one's answer would wake the first one's caller.
    assert_ne!(first, second);
}

#[tokio::test]
async fn a_plaintext_relay_is_refused_rather_than_downgraded_to() {
    // The URL carries a bearer token and every topic this wallet subscribes
    // to. Over `ws:` both are readable by anything on the path.
    let identity = ClientIdentity::generate().unwrap();
    let error = RelayConnection::connect(&config("ws://relay.example.org"), &identity)
        .await
        .map(|_| ())
        .expect_err("a plaintext relay was accepted");
    assert!(format!("{error}").contains("wss:"), "{error}");
}

#[tokio::test]
async fn a_host_that_never_finishes_the_handshake_is_given_up_on() {
    // Bound and never accepted: the kernel completes the TCP handshake from
    // the backlog, so the connection is established and then nothing is ever
    // read or written. That is the shape a deadline is for — a peer that is
    // reachable and silent, rather than one that refuses — and before this
    // there was no deadline on opening a connection at all, only on calls
    // made over one already open.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind a stalled host");
    let port = listener.local_addr().expect("the bound address").port();

    let identity = ClientIdentity::generate().unwrap();
    let stalled = config(&format!("wss://127.0.0.1:{port}"));
    let opening = RelayConnection::connect_within(&stalled, &identity, Duration::from_millis(250));
    // A second deadline, well above the one under test, so that a build
    // without the first fails here rather than hanging the suite. A
    // regression test for a missing timeout has to end either way.
    let error = tokio::time::timeout(Duration::from_secs(10), opening)
        .await
        .expect("opening a connection was never given up on")
        .map(|_| ())
        .expect_err("a host that never answered was treated as a relay");

    assert!(
        format!("{error}").contains("did not finish opening"),
        "{error}"
    );
}

#[test]
fn a_delivered_message_is_acknowledged_before_it_is_read() {
    // The relay redelivers anything it was not told arrived. Acknowledging
    // only well-formed payloads would mean a malformed one is redelivered
    // forever, so the ack goes out before the payload is even inspected.
    let pending: PendingCalls = Arc::new(Mutex::new(HashMap::new()));
    let subscribed: Subscriptions = Arc::new(Mutex::new(std::collections::HashSet::new()));
    let (incoming, mut incoming_rx) = mpsc::channel(8);
    let (outgoing, mut outgoing_rx) = mpsc::channel(8);

    dispatch(
        &json!({
            "id": 42, "jsonrpc": "2.0", "method": "irn_subscription",
            "params": { "id": "sub", "data": { "nonsense": true } },
        })
        .to_string(),
        &pending,
        &subscribed,
        &incoming,
        &outgoing,
    );
    let ack = outgoing_rx.try_recv().expect("no acknowledgement was sent");
    assert!(ack.to_text().unwrap().contains("\"id\":42"));
    assert!(
        incoming_rx.try_recv().is_err(),
        "a payload with no topic was forwarded as a message"
    );
}

#[test]
fn a_delivered_message_reaches_the_consumer_with_its_topic() {
    let pending: PendingCalls = Arc::new(Mutex::new(HashMap::new()));
    let subscribed: Subscriptions = Arc::new(Mutex::new(std::collections::HashSet::new()));
    subscribed.lock().unwrap().insert("abc".to_owned());
    let (incoming, mut incoming_rx) = mpsc::channel(8);
    let (outgoing, _outgoing_rx) = mpsc::channel(8);

    dispatch(
        &json!({
            "id": 1, "jsonrpc": "2.0", "method": "irn_subscription",
            "params": { "id": "sub", "data": { "topic": "abc", "message": "AAAA" } },
        })
        .to_string(),
        &pending,
        &subscribed,
        &incoming,
        &outgoing,
    );
    let delivered = incoming_rx.try_recv().expect("nothing was forwarded");
    assert_eq!(delivered.topic, "abc");
    assert_eq!(delivered.message, "AAAA");
}

#[test]
fn a_response_wakes_exactly_the_call_that_is_waiting_for_it() {
    let pending: PendingCalls = Arc::new(Mutex::new(HashMap::new()));
    let subscribed: Subscriptions = Arc::new(Mutex::new(std::collections::HashSet::new()));
    let (incoming, _incoming_rx) = mpsc::channel(8);
    let (outgoing, _outgoing_rx) = mpsc::channel(8);
    let (sender, receiver) = oneshot::channel();
    pending.lock().unwrap().insert(9, sender);

    dispatch(
        &json!({ "id": 9, "jsonrpc": "2.0", "result": "subscription-id" }).to_string(),
        &pending,
        &subscribed,
        &incoming,
        &outgoing,
    );
    assert_eq!(
        receiver.blocking_recv().unwrap().unwrap(),
        "subscription-id"
    );
    assert!(pending.lock().unwrap().is_empty());
}

#[test]
fn a_relay_error_reaches_the_waiting_call_as_an_error() {
    let pending: PendingCalls = Arc::new(Mutex::new(HashMap::new()));
    let subscribed: Subscriptions = Arc::new(Mutex::new(std::collections::HashSet::new()));
    let (incoming, _incoming_rx) = mpsc::channel(8);
    let (outgoing, _outgoing_rx) = mpsc::channel(8);
    let (sender, receiver) = oneshot::channel();
    pending.lock().unwrap().insert(3, sender);

    dispatch(
        &json!({
            "id": 3, "jsonrpc": "2.0",
            "error": { "code": 401, "message": "invalid project id" },
        })
        .to_string(),
        &pending,
        &subscribed,
        &incoming,
        &outgoing,
    );
    let answer = receiver.blocking_recv().unwrap();
    assert_eq!(answer.unwrap_err(), "invalid project id");
}

#[test]
fn a_frame_that_is_not_json_is_ignored_rather_than_fatal() {
    let pending: PendingCalls = Arc::new(Mutex::new(HashMap::new()));
    let subscribed: Subscriptions = Arc::new(Mutex::new(std::collections::HashSet::new()));
    let (incoming, mut incoming_rx) = mpsc::channel(8);
    let (outgoing, mut outgoing_rx) = mpsc::channel(8);
    dispatch(
        "not json at all",
        &pending,
        &subscribed,
        &incoming,
        &outgoing,
    );
    assert!(incoming_rx.try_recv().is_err());
    assert!(outgoing_rx.try_recv().is_err());
}

#[test]
fn a_message_on_a_topic_nobody_subscribed_to_is_acknowledged_and_dropped() {
    // The relay is trusted for liveness and nothing else. A topic this
    // connection never asked for has no key that opens it and no session that
    // wants it, so holding the strings costs memory and buys nothing.
    let pending: PendingCalls = Arc::new(Mutex::new(HashMap::new()));
    let subscribed: Subscriptions = Arc::new(Mutex::new(std::collections::HashSet::new()));
    subscribed.lock().unwrap().insert("ours".to_owned());
    let (incoming, mut incoming_rx) = mpsc::channel(8);
    let (outgoing, mut outgoing_rx) = mpsc::channel(8);

    dispatch(
        &json!({
            "id": 7, "jsonrpc": "2.0", "method": "irn_subscription",
            "params": { "id": "sub", "data": { "topic": "theirs", "message": "AAAA" } },
        })
        .to_string(),
        &pending,
        &subscribed,
        &incoming,
        &outgoing,
    );
    assert!(incoming_rx.try_recv().is_err());
    // Acknowledged all the same: it will not become deliverable on a second
    // attempt, and an unacknowledged message is redelivered forever.
    assert!(
        outgoing_rx
            .try_recv()
            .expect("no acknowledgement")
            .to_text()
            .unwrap()
            .contains("\"id\":7")
    );
}

#[test]
fn an_oversized_payload_is_refused_before_it_is_queued() {
    // The envelope's own bound, applied at the door rather than after
    // dequeue. A megabyte that is going to be refused is still a megabyte held
    // while the owner reads an approval.
    let pending: PendingCalls = Arc::new(Mutex::new(HashMap::new()));
    let subscribed: Subscriptions = Arc::new(Mutex::new(std::collections::HashSet::new()));
    subscribed.lock().unwrap().insert("ours".to_owned());
    let (incoming, mut incoming_rx) = mpsc::channel(8);
    let (outgoing, _outgoing_rx) = mpsc::channel(8);

    let huge = "A".repeat(crate::crypto::MAX_ENVELOPE_BYTES + 1);
    dispatch(
        &json!({
            "id": 8, "jsonrpc": "2.0", "method": "irn_subscription",
            "params": { "id": "sub", "data": { "topic": "ours", "message": huge } },
        })
        .to_string(),
        &pending,
        &subscribed,
        &incoming,
        &outgoing,
    );
    assert!(incoming_rx.try_recv().is_err());
}

#[test]
fn a_full_queue_withholds_the_acknowledgement_rather_than_growing() {
    // The backpressure the unbounded channel had none of. The session loop
    // stops consuming while the owner reads an approval, which is exactly when
    // a hostile peer would flood; a relay redelivers what it was not
    // acknowledged for, so a full queue loses nothing.
    let pending: PendingCalls = Arc::new(Mutex::new(HashMap::new()));
    let subscribed: Subscriptions = Arc::new(Mutex::new(std::collections::HashSet::new()));
    subscribed.lock().unwrap().insert("ours".to_owned());
    let (incoming, _incoming_rx) = mpsc::channel(1);
    let (outgoing, mut outgoing_rx) = mpsc::channel(8);

    let deliver = |id: u64| {
        dispatch(
            &json!({
                "id": id, "jsonrpc": "2.0", "method": "irn_subscription",
                "params": { "id": "sub", "data": { "topic": "ours", "message": "AAAA" } },
            })
            .to_string(),
            &pending,
            &subscribed,
            &incoming,
            &outgoing,
        );
    };
    deliver(1);
    assert!(
        outgoing_rx
            .try_recv()
            .expect("the first one fits")
            .to_text()
            .unwrap()
            .contains("\"id\":1")
    );

    deliver(2);
    assert!(
        outgoing_rx.try_recv().is_err(),
        "a message that did not fit must not be acknowledged, or the relay stops redelivering it"
    );
}
