use serde_json::{Value, json};
use std::{
    io::{BufRead as _, BufReader, Write as _},
    process::{Command, Stdio},
    sync::mpsc,
    time::Duration,
};

const BUILD_VERSION: &str = env!("EKUBO_WALLET_BUILD_VERSION");

#[path = "../../../bridge_protocol.rs"]
mod bridge_protocol;
use bridge_protocol::{BRIDGE_PROTOCOL_META_KEY, BRIDGE_PROTOCOL_VERSION};

/// The offline capability set recorded for each bridge protocol version.
///
/// The bridge answers `initialize` alone whenever the wallet is down, and a
/// harness keeps that answer for the whole session — so a bridge that fails to
/// claim a capability the wallet has makes it unreachable for that session no
/// matter what the wallet serves afterwards. Once the bridge stopped requiring
/// an exact build match, nothing else tied the two sides' capability sets
/// together, and that failure is silent.
///
/// So the set is pinned per protocol version. Changing the capabilities makes
/// this table's current row wrong; the fix is to bump
/// `BRIDGE_PROTOCOL_VERSION` and append a row, never to edit the row of a
/// version that has shipped.
const CAPABILITY_CONTRACT: &[(u32, &str)] = &[(
    1,
    r#"{"resources":{"listChanged":true},"tools":{"listChanged":true}}"#,
)];

/// Canonical form: parsed and re-serialized, so whitespace and key order in
/// the source file cannot make this pass or fail on their own.
fn canonical(text: &str) -> String {
    let value: std::collections::BTreeMap<String, Value> = serde_json::from_str(text).unwrap();
    serde_json::to_string(&value).unwrap()
}

#[test]
fn the_offline_capabilities_match_the_protocol_version() {
    let declared = include_str!("../src/offline_capabilities.json");
    let Some((_, recorded)) = CAPABILITY_CONTRACT
        .iter()
        .find(|(version, _)| *version == BRIDGE_PROTOCOL_VERSION)
    else {
        panic!(
            "bridge protocol {BRIDGE_PROTOCOL_VERSION} has no recorded capability set; \
             append one to CAPABILITY_CONTRACT"
        )
    };
    assert_eq!(
        canonical(declared),
        canonical(recorded),
        "the offline capability set changed without a bridge protocol bump; a capability the \
         wallet has and the bridge does not claim is unreachable for a whole agent session"
    );
}

fn send(stdin: &mut std::process::ChildStdin, value: &Value) {
    serde_json::to_writer(&mut *stdin, &value).unwrap();
    stdin.write_all(b"\n").unwrap();
    stdin.flush().unwrap();
}

fn receive(stdout: &mut BufReader<std::process::ChildStdout>) -> Value {
    let mut line = String::new();
    stdout.read_line(&mut line).unwrap();
    serde_json::from_str(&line).unwrap()
}

#[test]
fn initializes_and_stays_useful_before_wallet_startup() {
    let home = tempfile::tempdir().unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_ekubo-wallet-mcp-bridge"))
        .args(["--client", "codex"])
        .env("EKUBO_WALLET_HOME", home.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = BufReader::new(child.stdout.take().unwrap());
    send(
        &mut stdin,
        &json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"test","version":"1"}}}),
    );
    let initialized = receive(&mut stdout);
    assert_eq!(initialized["id"], 1);
    assert_eq!(
        initialized["result"]["serverInfo"]["version"],
        BUILD_VERSION
    );
    assert_eq!(
        initialized["result"]["capabilities"]["tools"]["listChanged"],
        true
    );
    // Announced even with no wallet to serve them: a harness records this
    // answer once and never asks again, so a session that starts before the
    // wallet must still be able to read wallet:// resources afterwards.
    assert_eq!(
        initialized["result"]["capabilities"]["resources"]["listChanged"],
        true
    );
    send(
        &mut stdin,
        &json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
    );
    send(
        &mut stdin,
        &json!({"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}),
    );
    let tools = receive(&mut stdout);
    assert_eq!(tools["result"], json!({"tools":[]}));
    send(
        &mut stdin,
        &json!({"jsonrpc":"2.0","id":3,"method":"resources/list","params":{}}),
    );
    assert_eq!(receive(&mut stdout)["result"], json!({"resources":[]}));
    send(
        &mut stdin,
        &json!({"jsonrpc":"2.0","id":4,"method":"resources/templates/list","params":{}}),
    );
    assert_eq!(
        receive(&mut stdout)["result"],
        json!({"resourceTemplates":[]})
    );
    send(&mut stdin, &json!({"jsonrpc":"2.0","id":5,"method":"ping"}));
    let ping = receive(&mut stdout);
    assert_eq!(ping["id"], 5);
    assert_eq!(ping["result"], json!({}));
    send(
        &mut stdin,
        &json!({"jsonrpc":"2.0","id":"call","method":"tools/call","params":{"name":"missing","arguments":{}}}),
    );
    let call = receive(&mut stdout);
    assert_eq!(call["id"], "call");
    assert!(
        call["error"]["message"]
            .as_str()
            .unwrap()
            .contains("not running")
    );
    send(
        &mut stdin,
        &json!({"jsonrpc":"2.0","id":"read","method":"resources/read","params":{"uri":"wallet://docs/policy-authoring"}}),
    );
    let read = receive(&mut stdout);
    assert_eq!(read["id"], "read");
    assert!(
        read["error"]["message"]
            .as_str()
            .unwrap()
            .contains("not running")
    );
    std::thread::sleep(Duration::from_millis(50));
    assert!(child.try_wait().unwrap().is_none());
    drop(stdin);
    assert!(child.wait().unwrap().success());
}

#[test]
fn rejects_unknown_harness_without_writing_protocol_to_stdout() {
    let output = Command::new(env!("CARGO_BIN_EXE_ekubo-wallet-mcp-bridge"))
        .args(["--client", "unknown"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(
        String::from_utf8(output.stderr)
            .unwrap()
            .contains("unsupported")
    );
}

#[test]
fn accepts_grok_build_as_a_supported_harness() {
    let home = tempfile::tempdir().unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_ekubo-wallet-mcp-bridge"))
        .args(["--client", "grok-build"])
        .env("EKUBO_WALLET_HOME", home.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = BufReader::new(child.stdout.take().unwrap());
    send(
        &mut stdin,
        &json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}),
    );
    assert_eq!(receive(&mut stdout)["id"], 1);
    drop(stdin);
    assert!(child.wait().unwrap().success());
}

#[test]
fn malformed_json_returns_a_protocol_error_without_stopping() {
    let home = tempfile::tempdir().unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_ekubo-wallet-mcp-bridge"))
        .args(["--client", "cursor"])
        .env("EKUBO_WALLET_HOME", home.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = BufReader::new(child.stdout.take().unwrap());
    send(
        &mut stdin,
        &json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}),
    );
    assert_eq!(receive(&mut stdout)["id"], 1);
    stdin.write_all(b"{broken\n").unwrap();
    stdin.flush().unwrap();
    assert_eq!(receive(&mut stdout)["error"]["code"], -32700);
    send(
        &mut stdin,
        &json!({"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}),
    );
    assert_eq!(receive(&mut stdout)["result"], json!({"tools":[]}));
    drop(stdin);
    assert!(child.wait().unwrap().success());
}

#[test]
fn oversized_harness_frames_are_rejected_at_the_transport_ceiling() {
    let home = tempfile::tempdir().unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_ekubo-wallet-mcp-bridge"))
        .args(["--client", "gemini-cli"])
        .env("EKUBO_WALLET_HOME", home.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = BufReader::new(child.stdout.take().unwrap());
    send(
        &mut stdin,
        &json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}),
    );
    assert_eq!(receive(&mut stdout)["id"], 1);
    let oversized = vec![b' '; 24 * 1024 * 1024 + 1];
    let _ = stdin.write_all(&oversized);
    let _ = stdin.write_all(b"\n");
    drop(stdin);
    let output = child.wait_with_output().unwrap();
    assert!(!output.status.success());
    assert!(
        String::from_utf8(output.stderr)
            .unwrap()
            .contains("exceeds 24 MiB")
    );
}

#[cfg(unix)]
#[test]
fn connects_reconnects_and_preserves_bidirectional_protocol_messages() {
    use std::{
        fs,
        os::unix::fs::PermissionsExt as _,
        os::unix::net::{UnixListener, UnixStream},
        thread,
    };

    fn read(stream: &mut BufReader<UnixStream>) -> Value {
        let mut line = String::new();
        stream.read_line(&mut line).unwrap();
        serde_json::from_str(&line).unwrap()
    }
    fn write(stream: &mut UnixStream, value: &Value) {
        serde_json::to_writer(&mut *stream, &value).unwrap();
        stream.write_all(b"\n").unwrap();
        stream.flush().unwrap();
    }
    /// Answer one bridge connection the way the wallet does.
    ///
    /// `expect_initialized` distinguishes the two shapes a connection takes.
    /// The first happens while the harness is still waiting for its own
    /// `initialize` answer, so no `notifications/initialized` has been sent
    /// yet; a reconnect replays the one the bridge kept.
    fn handshake(
        stream: UnixStream,
        catalog: &Value,
        resources: &Value,
        expect_initialized: bool,
    ) -> (BufReader<UnixStream>, UnixStream) {
        let mut writer = stream.try_clone().unwrap();
        let mut reader = BufReader::new(stream);
        let hello = read(&mut reader);
        assert_eq!(hello["client"], "codex");
        let initialize = read(&mut reader);
        write(
            &mut writer,
            &json!({"jsonrpc":"2.0","id":initialize["id"],"result":{
                "protocolVersion":"2025-11-25",
                "capabilities":{"tools":{},"resources":{}},
                "serverInfo":{"name":"fake-wallet","version":BUILD_VERSION},
                "instructions":"Wallet instructions the agent must actually receive."
            }}),
        );
        if expect_initialized {
            assert_eq!(read(&mut reader)["method"], "notifications/initialized");
        }
        for _ in 0..2 {
            let list = read(&mut reader);
            let result = match list["method"].as_str().unwrap() {
                "tools/list" => catalog,
                "resources/list" => resources,
                other => panic!("unexpected catalog request {other}"),
            };
            write(
                &mut writer,
                &json!({"jsonrpc":"2.0","id":list["id"],"result":result}),
            );
        }
        (reader, writer)
    }

    let home = tempfile::tempdir().unwrap();
    fs::set_permissions(home.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let listener = UnixListener::bind(home.path().join("mcp.sock")).unwrap();
    let catalog = json!({"tools":[{"name":"wallet_test","description":"test","inputSchema":{"type":"object"}}]});
    let resources =
        json!({"resources":[{"uri":"wallet://docs/policy-authoring","name":"policy-authoring"}]});
    let (ready_tx, ready_rx) = mpsc::channel();
    let fake_catalog = catalog.clone();
    let fake_resources = resources.clone();
    let wallet = thread::spawn(move || {
        let (first, _) = listener.accept().unwrap();
        let (mut first_read, mut first_write) =
            handshake(first, &fake_catalog, &fake_resources, false);
        ready_tx.send(1).unwrap();

        // Forwarded once the harness answers the handshake the wallet just
        // supplied, rather than replayed by the bridge beforehand.
        assert_eq!(read(&mut first_read)["method"], "notifications/initialized");
        let list = read(&mut first_read);
        assert_eq!(list["id"], 10);
        write(
            &mut first_write,
            &json!({"jsonrpc":"2.0","id":10,"result":fake_catalog}),
        );
        let listed_resources = read(&mut first_read);
        assert_eq!(listed_resources["method"], "resources/list");
        write(
            &mut first_write,
            &json!({"jsonrpc":"2.0","id":listed_resources["id"],"result":fake_resources}),
        );
        write(
            &mut first_write,
            &json!({"jsonrpc":"2.0","method":"notifications/progress","params":{"progressToken":"p","progress":1}}),
        );
        write(
            &mut first_write,
            &json!({"jsonrpc":"2.0","id":99,"method":"sampling/createMessage","params":{"messages":[]}}),
        );
        assert_eq!(read(&mut first_read)["id"], 99);
        assert_eq!(read(&mut first_read)["method"], "notifications/cancelled");
        let call = read(&mut first_read);
        assert_eq!(call["id"], "interrupted");
        drop(first_read);
        drop(first_write);

        let (second, _) = listener.accept().unwrap();
        let (mut second_read, mut second_write) =
            handshake(second, &fake_catalog, &fake_resources, true);
        ready_tx.send(2).unwrap();
        let first_call = read(&mut second_read);
        let second_call = read(&mut second_read);
        assert_eq!(first_call["id"], "resumed-a");
        assert_eq!(second_call["id"], "resumed-b");
        write(
            &mut second_write,
            &json!({"jsonrpc":"2.0","id":"resumed-b","result":{"content":[{"type":"text","text":"second"}]}}),
        );
        write(
            &mut second_write,
            &json!({"jsonrpc":"2.0","id":"resumed-a","result":{"content":[{"type":"text","text":"first"}]}}),
        );
    });

    let mut child = Command::new(env!("CARGO_BIN_EXE_ekubo-wallet-mcp-bridge"))
        .args(["--client", "codex"])
        .env("EKUBO_WALLET_HOME", home.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = BufReader::new(child.stdout.take().unwrap());
    send(
        &mut stdin,
        &json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25"}}),
    );
    // The wallet describes itself: its instructions are the ones the model
    // reads, and the capabilities it declares are the ones the harness
    // records — with the change notifications the bridge, not the wallet,
    // is the one able to send.
    let initialized = receive(&mut stdout);
    assert_eq!(initialized["id"], 1);
    assert_eq!(initialized["result"]["serverInfo"]["name"], "fake-wallet");
    assert_eq!(
        initialized["result"]["instructions"],
        "Wallet instructions the agent must actually receive."
    );
    assert_eq!(
        initialized["result"]["capabilities"],
        json!({"tools":{"listChanged":true},"resources":{"listChanged":true}})
    );
    send(
        &mut stdin,
        &json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
    );
    ready_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    send(
        &mut stdin,
        &json!({"jsonrpc":"2.0","id":10,"method":"tools/list","params":{}}),
    );
    send(
        &mut stdin,
        &json!({"jsonrpc":"2.0","id":11,"method":"resources/list","params":{}}),
    );
    assert_eq!(receive(&mut stdout)["result"], catalog);
    assert_eq!(receive(&mut stdout)["result"], resources);
    assert_eq!(receive(&mut stdout)["method"], "notifications/progress");
    let server_request = receive(&mut stdout);
    assert_eq!(server_request["id"], 99);
    assert_eq!(server_request["method"], "sampling/createMessage");
    send(
        &mut stdin,
        &json!({"jsonrpc":"2.0","id":99,"result":{"model":"test","role":"assistant","content":{"type":"text","text":"ok"}}}),
    );
    send(
        &mut stdin,
        &json!({"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":"old","reason":"test"}}),
    );
    send(
        &mut stdin,
        &json!({"jsonrpc":"2.0","id":"interrupted","method":"tools/call","params":{"name":"wallet_test","arguments":{}}}),
    );
    let interrupted = receive(&mut stdout);
    assert_eq!(interrupted["id"], "interrupted");
    assert!(
        interrupted["error"]["message"]
            .as_str()
            .unwrap()
            .contains("stopped")
    );

    assert_eq!(ready_rx.recv_timeout(Duration::from_secs(8)).unwrap(), 2);
    send(
        &mut stdin,
        &json!({"jsonrpc":"2.0","id":"resumed-a","method":"tools/call","params":{"name":"wallet_test","arguments":{}}}),
    );
    send(
        &mut stdin,
        &json!({"jsonrpc":"2.0","id":"resumed-b","method":"tools/call","params":{"name":"wallet_test","arguments":{}}}),
    );
    let resumed_b = receive(&mut stdout);
    let resumed_a = receive(&mut stdout);
    assert_eq!(resumed_b["id"], "resumed-b");
    assert_eq!(resumed_b["result"]["content"][0]["text"], "second");
    assert_eq!(resumed_a["id"], "resumed-a");
    assert_eq!(resumed_a["result"]["content"][0]["text"], "first");
    drop(stdin);
    assert!(child.wait().unwrap().success());
    wallet.join().unwrap();
}

#[cfg(unix)]
#[test]
fn a_wallet_frame_split_across_writes_survives_a_racing_harness_frame() {
    use std::{
        fs,
        os::unix::fs::PermissionsExt as _,
        os::unix::net::{UnixListener, UnixStream},
        thread,
    };

    fn read(stream: &mut BufReader<UnixStream>) -> Value {
        let mut line = String::new();
        stream.read_line(&mut line).unwrap();
        serde_json::from_str(&line).unwrap()
    }
    fn write(stream: &mut UnixStream, value: &Value) {
        serde_json::to_writer(&mut *stream, &value).unwrap();
        stream.write_all(b"\n").unwrap();
        stream.flush().unwrap();
    }

    let home = tempfile::tempdir().unwrap();
    fs::set_permissions(home.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let listener = UnixListener::bind(home.path().join("mcp.sock")).unwrap();
    let (ready_tx, ready_rx) = mpsc::channel();

    let wallet = thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        let mut writer = stream.try_clone().unwrap();
        let mut reader = BufReader::new(stream);
        assert_eq!(read(&mut reader)["client"], "codex");
        let initialize = read(&mut reader);
        write(
            &mut writer,
            &json!({"jsonrpc":"2.0","id":initialize["id"],"result":{
                "protocolVersion":"2025-11-25",
                "capabilities":{"tools":{},"resources":{}},
                "serverInfo":{"name":"fake-wallet","version":BUILD_VERSION}
            }}),
        );
        for _ in 0..2 {
            let list = read(&mut reader);
            let result = match list["method"].as_str().unwrap() {
                "tools/list" => {
                    json!({"tools":[{"name":"wallet_test","description":"test","inputSchema":{"type":"object"}}]})
                }
                "resources/list" => json!({"resources":[]}),
                other => panic!("unexpected catalog request {other}"),
            };
            write(
                &mut writer,
                &json!({"jsonrpc":"2.0","id":list["id"],"result":result}),
            );
        }
        ready_tx.send(()).unwrap();

        assert_eq!(read(&mut reader)["method"], "notifications/initialized");
        assert_eq!(read(&mut reader)["id"], "split");

        // Deliver the answer in two writes with a gap between them. A real
        // wallet's JSON writer already emits a frame as several small writes,
        // so the bridge holding half of one is the ordinary case; this only
        // makes the timing of it something the test can rely on.
        let body = serde_json::to_vec(
            &json!({"jsonrpc":"2.0","id":"split","result":{"content":[{"type":"text","text":"whole"}]}}),
        )
        .unwrap();
        let (head, tail) = body.split_at(body.len() / 2);
        writer.write_all(head).unwrap();
        writer.flush().unwrap();
        thread::sleep(Duration::from_millis(400));
        writer.write_all(tail).unwrap();
        writer.write_all(b"\n").unwrap();
        writer.flush().unwrap();

        // The frame that raced the split one. Nothing has to answer it: its
        // whole job was to wake the other select! branch mid-frame.
        assert_eq!(read(&mut reader)["id"], "racer");
    });

    let mut child = Command::new(env!("CARGO_BIN_EXE_ekubo-wallet-mcp-bridge"))
        .args(["--client", "codex"])
        .env("EKUBO_WALLET_HOME", home.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = BufReader::new(child.stdout.take().unwrap());
    send(
        &mut stdin,
        &json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25"}}),
    );
    assert_eq!(receive(&mut stdout)["id"], 1);
    send(
        &mut stdin,
        &json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
    );
    ready_rx.recv_timeout(Duration::from_secs(5)).unwrap();

    send(
        &mut stdin,
        &json!({"jsonrpc":"2.0","id":"split","method":"tools/call","params":{"name":"wallet_test","arguments":{}}}),
    );
    // Land inside the wallet's gap, so the bridge is holding half a frame when
    // this arrives and abandons that read in order to forward it.
    thread::sleep(Duration::from_millis(150));
    send(
        &mut stdin,
        &json!({"jsonrpc":"2.0","id":"racer","method":"tools/call","params":{"name":"wallet_test","arguments":{}}}),
    );

    // Before the accumulator outlived the cancelled read, the bytes taken from
    // the socket went with it: the bridge resumed inside the JSON, called the
    // wallet's frame corrupt, and answered this id with an error instead.
    let answered = receive(&mut stdout);
    assert_eq!(answered["id"], "split", "{answered}");
    assert_eq!(
        answered["result"]["content"][0]["text"], "whole",
        "{answered}"
    );

    drop(stdin);
    assert!(child.wait().unwrap().success());
    wallet.join().unwrap();
}

#[cfg(unix)]
#[test]
fn standard_server_version_mismatch_terminates_the_bridge() {
    use std::{
        fs,
        os::unix::fs::PermissionsExt as _,
        os::unix::net::{UnixListener, UnixStream},
        thread,
    };

    fn read(stream: &mut BufReader<UnixStream>) -> Value {
        let mut line = String::new();
        stream.read_line(&mut line).unwrap();
        serde_json::from_str(&line).unwrap()
    }
    fn write(stream: &mut UnixStream, value: &Value) {
        serde_json::to_writer(&mut *stream, value).unwrap();
        stream.write_all(b"\n").unwrap();
        stream.flush().unwrap();
    }

    let home = tempfile::tempdir().unwrap();
    fs::set_permissions(home.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let listener = UnixListener::bind(home.path().join("mcp.sock")).unwrap();
    let wallet = thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        let mut writer = stream.try_clone().unwrap();
        let mut reader = BufReader::new(stream);
        let hello = read(&mut reader);
        assert_eq!(hello["client"], "codex");
        let initialize = read(&mut reader);
        write(
            &mut writer,
            &json!({"jsonrpc":"2.0","id":initialize["id"],"result":{
                "protocolVersion":"2025-11-25",
                "capabilities":{},
                "serverInfo":{"name":"newer-wallet","version":"999.0.0"}
            }}),
        );
        // Return immediately: after reading the standard serverInfo.version,
        // the bridge must not forward initialized, tools/list, or tool calls.
    });
    // The mismatch is found while answering `initialize`, so the harness is
    // told the session cannot start instead of recording a handshake from a
    // bridge that is about to stop.

    let mut child = Command::new(env!("CARGO_BIN_EXE_ekubo-wallet-mcp-bridge"))
        .args(["--client", "codex"])
        .env("EKUBO_WALLET_HOME", home.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let stdout = BufReader::new(child.stdout.take().unwrap());
    send(
        &mut stdin,
        &json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25"}}),
    );
    drop(stdin);
    drop(stdout);
    let output = child.wait_with_output().unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("Start a new agent session"), "{stderr}");
    assert!(stderr.contains("999.0.0"), "{stderr}");
    assert!(stderr.contains(BUILD_VERSION), "{stderr}");
    wallet.join().unwrap();
}

/// Shared fake wallet for the protocol tests: answers `initialize` with the
/// given build version and optional advertised protocol, then serves both
/// catalogs so a compatible bridge can finish its handshake.
#[cfg(unix)]
fn spawn_fake_wallet(
    home: &std::path::Path,
    version: &str,
    protocol: Option<u32>,
) -> std::thread::JoinHandle<()> {
    use std::os::unix::net::{UnixListener, UnixStream};

    fn read(stream: &mut BufReader<UnixStream>) -> Option<Value> {
        let mut line = String::new();
        stream.read_line(&mut line).ok()?;
        serde_json::from_str(&line).ok()
    }
    fn write(stream: &mut UnixStream, value: &Value) {
        serde_json::to_writer(&mut *stream, value).unwrap();
        stream.write_all(b"\n").unwrap();
        stream.flush().unwrap();
    }

    let listener = UnixListener::bind(home.join("mcp.sock")).unwrap();
    let version = version.to_owned();
    std::thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        let mut writer = stream.try_clone().unwrap();
        let mut reader = BufReader::new(stream);
        let _hello = read(&mut reader);
        let initialize = read(&mut reader).expect("initialize");
        let mut result = json!({
            "protocolVersion": "2025-11-25",
            "capabilities": {"tools": {}, "resources": {}},
            "serverInfo": {"name": "fake-wallet", "version": version},
        });
        if let Some(protocol) = protocol {
            result["_meta"] = json!({ BRIDGE_PROTOCOL_META_KEY: protocol });
        }
        write(
            &mut writer,
            &json!({"jsonrpc":"2.0","id":initialize["id"],"result":result}),
        );
        // An incompatible bridge stops here; a compatible one asks for both
        // catalogs, so answering them is what tells the two apart.
        for _ in 0..2 {
            let Some(request) = read(&mut reader) else {
                return;
            };
            let listed = match request["method"].as_str() {
                Some("tools/list") => json!({"tools": []}),
                Some("resources/list") => json!({"resources": []}),
                _ => continue,
            };
            write(
                &mut writer,
                &json!({"jsonrpc":"2.0","id":request["id"],"result":listed}),
            );
        }
    })
}

/// The point of versioning the contract rather than the build: a wallet that
/// updated underneath a running harness, or a helper left behind by another
/// build, stays usable as long as the shared contract did not move.
#[cfg(unix)]
#[test]
fn a_different_build_speaking_the_same_protocol_is_served() {
    use std::{fs, os::unix::fs::PermissionsExt as _};

    let home = tempfile::tempdir().unwrap();
    fs::set_permissions(home.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let wallet = spawn_fake_wallet(home.path(), "999.0.0", Some(BRIDGE_PROTOCOL_VERSION));

    let mut child = Command::new(env!("CARGO_BIN_EXE_ekubo-wallet-mcp-bridge"))
        .args(["--client", "codex"])
        .env("EKUBO_WALLET_HOME", home.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = BufReader::new(child.stdout.take().unwrap());
    send(
        &mut stdin,
        &json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25"}}),
    );
    let initialized = receive(&mut stdout);
    assert_eq!(initialized["id"], 1);
    // The wallet's own handshake reached the harness, so the bridge served
    // this wallet rather than answering offline on its behalf.
    assert_eq!(initialized["result"]["serverInfo"]["name"], "fake-wallet");
    assert_eq!(initialized["result"]["serverInfo"]["version"], "999.0.0");
    drop(stdin);
    assert!(child.wait().unwrap().success());
    wallet.join().unwrap();
}

/// A moved contract is still a hard stop, and still after exactly one attempt:
/// reconnecting would spin against a wallet that can never answer.
#[cfg(unix)]
#[test]
fn a_wallet_speaking_another_protocol_terminates_the_bridge() {
    use std::{fs, os::unix::fs::PermissionsExt as _};

    let home = tempfile::tempdir().unwrap();
    fs::set_permissions(home.path(), fs::Permissions::from_mode(0o700)).unwrap();
    // Identical build identity, so only the protocol can be what rejects it.
    let wallet = spawn_fake_wallet(
        home.path(),
        BUILD_VERSION,
        Some(BRIDGE_PROTOCOL_VERSION + 999),
    );

    let mut child = Command::new(env!("CARGO_BIN_EXE_ekubo-wallet-mcp-bridge"))
        .args(["--client", "codex"])
        .env("EKUBO_WALLET_HOME", home.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    send(
        &mut stdin,
        &json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25"}}),
    );
    drop(stdin);
    let output = child.wait_with_output().unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("bridge protocol"), "{stderr}");
    assert!(stderr.contains("Start a new agent session"), "{stderr}");
    wallet.join().unwrap();
}
