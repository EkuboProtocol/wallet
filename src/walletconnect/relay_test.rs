//! Tests for [`super`].

use super::*;

fn config(url: &str) -> RelayConfig {
    RelayConfig {
        url: Url::parse(url).unwrap(),
        project_id: "abc123".to_owned(),
    }
}

#[test]
fn the_connection_url_carries_the_token_the_project_and_the_agent() {
    let identity = ClientIdentity::generate().unwrap();
    let url = authenticated_url(&config(DEFAULT_RELAY_URL), &identity).unwrap();
    let query: std::collections::HashMap<_, _> = url.query_pairs().into_owned().collect();
    assert!(query.contains_key("auth"));
    assert_eq!(query.get("projectId").map(String::as_str), Some("abc123"));
    assert!(
        query.get("ua").is_some_and(|ua| ua.starts_with("wc-2/")),
        "{query:?}"
    );
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

#[test]
fn a_delivered_message_is_acknowledged_before_it_is_read() {
    // The relay redelivers anything it was not told arrived. Acknowledging
    // only well-formed payloads would mean a malformed one is redelivered
    // forever, so the ack goes out before the payload is even inspected.
    let pending: PendingCalls = Arc::new(Mutex::new(HashMap::new()));
    let (incoming, mut incoming_rx) = mpsc::unbounded_channel();
    let (outgoing, mut outgoing_rx) = mpsc::unbounded_channel();

    dispatch(
        &json!({
            "id": 42, "jsonrpc": "2.0", "method": "irn_subscription",
            "params": { "id": "sub", "data": { "nonsense": true } },
        })
        .to_string(),
        &pending,
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
    let (incoming, mut incoming_rx) = mpsc::unbounded_channel();
    let (outgoing, _outgoing_rx) = mpsc::unbounded_channel();

    dispatch(
        &json!({
            "id": 1, "jsonrpc": "2.0", "method": "irn_subscription",
            "params": { "id": "sub", "data": { "topic": "abc", "message": "AAAA" } },
        })
        .to_string(),
        &pending,
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
    let (incoming, _incoming_rx) = mpsc::unbounded_channel();
    let (outgoing, _outgoing_rx) = mpsc::unbounded_channel();
    let (sender, receiver) = oneshot::channel();
    pending.lock().unwrap().insert(9, sender);

    dispatch(
        &json!({ "id": 9, "jsonrpc": "2.0", "result": "subscription-id" }).to_string(),
        &pending,
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
    let (incoming, _incoming_rx) = mpsc::unbounded_channel();
    let (outgoing, _outgoing_rx) = mpsc::unbounded_channel();
    let (sender, receiver) = oneshot::channel();
    pending.lock().unwrap().insert(3, sender);

    dispatch(
        &json!({
            "id": 3, "jsonrpc": "2.0",
            "error": { "code": 401, "message": "invalid project id" },
        })
        .to_string(),
        &pending,
        &incoming,
        &outgoing,
    );
    let answer = receiver.blocking_recv().unwrap();
    assert_eq!(answer.unwrap_err(), "invalid project id");
}

#[test]
fn a_frame_that_is_not_json_is_ignored_rather_than_fatal() {
    let pending: PendingCalls = Arc::new(Mutex::new(HashMap::new()));
    let (incoming, mut incoming_rx) = mpsc::unbounded_channel();
    let (outgoing, mut outgoing_rx) = mpsc::unbounded_channel();
    dispatch("not json at all", &pending, &incoming, &outgoing);
    assert!(incoming_rx.try_recv().is_err());
    assert!(outgoing_rx.try_recv().is_err());
}
