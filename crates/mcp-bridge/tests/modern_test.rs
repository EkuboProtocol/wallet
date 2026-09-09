use serde_json::{Value, json};
use std::{
    io::{BufRead as _, BufReader, Write as _},
    process::{Child, ChildStdin, Command, Stdio},
    sync::mpsc::{self, Receiver},
    time::Duration,
};

#[path = "../../../bridge_protocol.rs"]
mod bridge_protocol;
use bridge_protocol::{BRIDGE_PROTOCOL_META_KEY, BRIDGE_PROTOCOL_VERSION};

fn request(id: u64, method: &str) -> Value {
    json!({"jsonrpc":"2.0","id":id,"method":method,"params":{"_meta":{
        "io.modelcontextprotocol/protocolVersion":"2026-07-28",
        "io.modelcontextprotocol/clientCapabilities":{}
    }}})
}

struct Harness {
    child: Child,
    stdin: ChildStdin,
    responses: Receiver<Value>,
}

impl Harness {
    fn new(home: &std::path::Path) -> Self {
        let mut child = Command::new(env!("CARGO_BIN_EXE_ekubo-wallet-mcp-bridge"))
            .args(["--client", "codex"])
            .env("EKUBO_WALLET_HOME", home)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let stdin = child.stdin.take().unwrap();
        let stdout = child.stdout.take().unwrap();
        let (tx, responses) = mpsc::channel();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                let Ok(line) = line else {
                    break;
                };
                let value = serde_json::from_str(&line).unwrap();
                if tx.send(value).is_err() {
                    break;
                }
            }
        });
        Self {
            child,
            stdin,
            responses,
        }
    }
    fn send(&mut self, value: &Value) {
        serde_json::to_writer(&mut self.stdin, value).unwrap();
        self.stdin.write_all(b"\n").unwrap();
        self.stdin.flush().unwrap();
    }
    fn receive(&self) -> Value {
        self.responses
            .recv_timeout(Duration::from_secs(5))
            .expect("bridge response")
    }
}

impl Drop for Harness {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[test]
fn offline_discovery_and_metadata_errors_keep_the_bridge_alive() {
    let home = tempfile::tempdir().unwrap();
    let mut harness = Harness::new(home.path());
    harness.send(&request(1, "server/discover"));
    let result = harness.receive()["result"].clone();
    assert_eq!(result["supportedVersions"], json!(["2026-07-28"]));
    assert_eq!(result["resultType"], "complete");
    assert_eq!(result["ttlMs"], 0);
    assert_eq!(result["cacheScope"], "private");
    assert_eq!(
        result["_meta"][BRIDGE_PROTOCOL_META_KEY],
        BRIDGE_PROTOCOL_VERSION
    );
    let mut unsupported = request(2, "tools/list");
    unsupported["params"]["_meta"]["io.modelcontextprotocol/protocolVersion"] = json!("2099-01-01");
    harness.send(&unsupported);
    assert_eq!(harness.receive()["error"]["code"], -32022);
    harness.send(&json!({"jsonrpc":"2.0","id":3,"method":"tools/list","params":{}}));
    assert_eq!(harness.receive()["error"]["code"], -32602);
    harness.send(&request(4, "tools/list"));
    let offline = harness.receive();
    assert!(offline.get("error").is_some());
    assert!(
        offline.get("result").is_none(),
        "do not cache a false empty catalog"
    );
    harness.send(&request(5, "server/discover"));
    assert_eq!(harness.receive()["id"], 5);
}

#[test]
fn a_probe_without_modern_metadata_can_fall_back_to_legacy_initialization() {
    let home = tempfile::tempdir().unwrap();
    let mut harness = Harness::new(home.path());
    harness.send(&json!({"jsonrpc":"2.0","id":1,"method":"server/discover","params":{}}));
    assert_eq!(harness.receive()["error"]["code"], -32602);
    harness.send(&json!({"jsonrpc":"2.0","id":2,"method":"initialize","params":{
        "protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"test","version":"1"}
    }}));
    assert_eq!(harness.receive()["result"]["protocolVersion"], "2025-11-25");
}

#[cfg(unix)]
fn read(reader: &mut BufReader<std::os::unix::net::UnixStream>) -> Value {
    let mut line = String::new();
    reader.read_line(&mut line).unwrap();
    serde_json::from_str(&line).unwrap()
}

#[cfg(unix)]
fn write(stream: &mut std::os::unix::net::UnixStream, message: &Value) {
    serde_json::to_writer(&mut *stream, message).unwrap();
    stream.write_all(b"\n").unwrap();
}

#[cfg(unix)]
fn accept(
    listener: &std::os::unix::net::UnixListener,
    protocol: u32,
) -> (
    std::os::unix::net::UnixStream,
    BufReader<std::os::unix::net::UnixStream>,
) {
    let (mut stream, _) = listener.accept().unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let mut reader = BufReader::new(stream.try_clone().unwrap());
    assert_eq!(read(&mut reader), json!({"client":"codex"}));
    let discover = read(&mut reader);
    assert_eq!(discover["method"], "server/discover");
    write(
        &mut stream,
        &json!({"jsonrpc":"2.0","id":discover["id"],"result":{
            "supportedVersions":["2026-07-28"],"capabilities":{"tools":{},"resources":{}},
            "resultType":"complete","ttlMs":0,"cacheScope":"private",
            "_meta":{BRIDGE_PROTOCOL_META_KEY:protocol,
                "io.modelcontextprotocol/serverInfo":{"name":"test-wallet","version":"9.0.0"}}
        }}),
    );
    (stream, reader)
}

#[cfg(unix)]
fn reply(id: &Value) -> Value {
    json!({"jsonrpc":"2.0","id":id,"result":{"tools":[],"resultType":"complete","ttlMs":0,"cacheScope":"private"}})
}

#[cfg(unix)]
#[test]
fn ordinary_first_request_and_per_request_metadata_are_forwarded_unchanged() {
    let home = tempfile::tempdir().unwrap();
    let listener = std::os::unix::net::UnixListener::bind(home.path().join("mcp.sock")).unwrap();
    let mut second = request(2, "tools/list");
    second["params"]["_meta"]["io.modelcontextprotocol/clientCapabilities"] =
        json!({"elicitation":{"form":{}}});
    let expected = second.clone();
    let wallet = std::thread::spawn(move || {
        let (mut stream, mut reader) = accept(&listener, BRIDGE_PROTOCOL_VERSION);
        assert_eq!(read(&mut reader), request(1, "tools/list"));
        write(&mut stream, &reply(&json!(1)));
        assert_eq!(read(&mut reader), expected);
        write(&mut stream, &reply(&json!(2)));
    });
    let mut harness = Harness::new(home.path());
    harness.send(&request(1, "tools/list"));
    assert_eq!(harness.receive(), reply(&json!(1)));
    harness.send(&second);
    assert_eq!(harness.receive(), reply(&json!(2)));
    wallet.join().unwrap();
}

#[cfg(unix)]
#[test]
fn disconnect_reconnects_without_replaying_a_tool_call() {
    let home = tempfile::tempdir().unwrap();
    let listener = std::os::unix::net::UnixListener::bind(home.path().join("mcp.sock")).unwrap();
    let wallet = std::thread::spawn(move || {
        {
            let (_stream, mut reader) = accept(&listener, BRIDGE_PROTOCOL_VERSION);
            assert_eq!(read(&mut reader)["method"], "tools/call");
            // The request may have executed; lose its response deliberately.
        }
        let (mut stream, mut reader) = accept(&listener, BRIDGE_PROTOCOL_VERSION);
        let next = read(&mut reader);
        assert_eq!(next, request(2, "tools/list"), "never replay the tool call");
        write(&mut stream, &reply(&next["id"]));
    });
    let mut harness = Harness::new(home.path());
    let mut call = request(1, "tools/call");
    call["params"]["name"] = json!("test_mutation");
    call["params"]["arguments"] = json!({});
    harness.send(&call);
    assert!(
        harness.receive()["error"]["message"]
            .as_str()
            .unwrap()
            .contains("may have executed")
    );
    harness.send(&request(2, "tools/list"));
    assert_eq!(harness.receive(), reply(&json!(2)));
    wallet.join().unwrap();
}

#[cfg(unix)]
#[test]
fn incompatible_wallet_receives_no_business_requests() {
    let home = tempfile::tempdir().unwrap();
    let listener = std::os::unix::net::UnixListener::bind(home.path().join("mcp.sock")).unwrap();
    let wallet = std::thread::spawn(move || {
        let (_stream, mut reader) = accept(&listener, BRIDGE_PROTOCOL_VERSION + 1);
        let mut line = String::new();
        assert_eq!(reader.read_line(&mut line).unwrap(), 0);
    });
    let mut harness = Harness::new(home.path());
    harness.send(&request(1, "tools/list"));
    assert!(
        harness.receive()["error"]["message"]
            .as_str()
            .unwrap()
            .contains("bridge protocol")
    );
    wallet.join().unwrap();
}

#[cfg(unix)]
#[test]
fn cancellation_is_forwarded_and_late_results_are_suppressed() {
    let home = tempfile::tempdir().unwrap();
    let listener = std::os::unix::net::UnixListener::bind(home.path().join("mcp.sock")).unwrap();
    let wallet = std::thread::spawn(move || {
        let (mut stream, mut reader) = accept(&listener, BRIDGE_PROTOCOL_VERSION);
        assert_eq!(read(&mut reader)["id"], 1);
        assert_eq!(read(&mut reader)["method"], "notifications/cancelled");
        assert_eq!(read(&mut reader)["id"], 2);
        write(&mut stream, &reply(&json!(1)));
        write(&mut stream, &reply(&json!(2)));
    });
    let mut harness = Harness::new(home.path());
    harness.send(&request(1, "tools/list"));
    harness.send(
        &json!({"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":1}}),
    );
    harness.send(&request(2, "tools/list"));
    assert_eq!(harness.receive(), reply(&json!(2)));
    wallet.join().unwrap();
}

#[cfg(unix)]
#[test]
fn wallet_startup_after_offline_discovery_requires_no_new_bridge_process() {
    let home = tempfile::tempdir().unwrap();
    let mut harness = Harness::new(home.path());
    harness.send(&request(1, "server/discover"));
    assert_eq!(harness.receive()["result"]["ttlMs"], 0);
    let listener = std::os::unix::net::UnixListener::bind(home.path().join("mcp.sock")).unwrap();
    let wallet = std::thread::spawn(move || {
        let (mut stream, mut reader) = accept(&listener, BRIDGE_PROTOCOL_VERSION);
        let next = read(&mut reader);
        assert_eq!(next, request(2, "tools/list"));
        let mut result = reply(&next["id"]);
        result["result"]["tools"] = json!([{"name":"wallet_list","inputSchema":{"type":"object"}}]);
        write(&mut stream, &result);
    });
    harness.send(&request(2, "tools/list"));
    assert_eq!(
        harness.receive()["result"]["tools"][0]["name"],
        "wallet_list"
    );
    wallet.join().unwrap();
}

#[cfg(unix)]
#[test]
fn partial_wallet_frames_survive_concurrent_client_requests() {
    let home = tempfile::tempdir().unwrap();
    let listener = std::os::unix::net::UnixListener::bind(home.path().join("mcp.sock")).unwrap();
    let (ready_tx, ready_rx) = mpsc::channel();
    let wallet = std::thread::spawn(move || {
        let (mut stream, mut reader) = accept(&listener, BRIDGE_PROTOCOL_VERSION);
        assert_eq!(read(&mut reader)["id"], 1);
        let bytes = serde_json::to_vec(&reply(&json!(1))).unwrap();
        let midpoint = bytes.len() / 2;
        stream.write_all(&bytes[..midpoint]).unwrap();
        ready_tx.send(()).unwrap();
        assert_eq!(read(&mut reader)["id"], 2);
        stream.write_all(&bytes[midpoint..]).unwrap();
        stream.write_all(b"\n").unwrap();
        write(&mut stream, &reply(&json!(2)));
    });
    let mut harness = Harness::new(home.path());
    harness.send(&request(1, "tools/list"));
    ready_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    harness.send(&request(2, "tools/list"));
    assert_eq!(harness.receive(), reply(&json!(1)));
    assert_eq!(harness.receive(), reply(&json!(2)));
    wallet.join().unwrap();
}
