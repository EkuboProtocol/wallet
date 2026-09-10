//! Real stdio/socket regressions: no wallet database, keys or transactions.
#![cfg(unix)]

use serde_json::{Value, json};
use std::{
    io::{BufRead as _, BufReader, Read as _, Write as _},
    net::Shutdown,
    os::unix::net::{UnixListener, UnixStream},
    process::{Child, ChildStdin, Command, Stdio},
    sync::mpsc::{self, Receiver},
    thread,
    time::Duration,
};

const BUILD_VERSION: &str = env!("EKUBO_WALLET_BUILD_VERSION");

fn catalog() -> Value {
    json!({"tools":[{"name":"wallet_test","inputSchema":{"type":"object"}}]})
}

struct Harness {
    child: Child,
    stdin: Option<ChildStdin>,
    messages: Receiver<Value>,
}

impl Harness {
    fn start(home: &std::path::Path) -> Self {
        let mut child = Command::new(env!("CARGO_BIN_EXE_ekubo-wallet-mcp-bridge"))
            .args(["--client", "codex"])
            .env("EKUBO_WALLET_HOME", home)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let stdout = child.stdout.take().unwrap();
        let (tx, messages) = mpsc::channel();
        thread::spawn(move || {
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
        let stdin = child.stdin.take();
        let mut harness = Self {
            child,
            stdin,
            messages,
        };
        harness.send(&json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{
            "protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"test","version":"1"}
        }}));
        harness
    }

    fn send(&mut self, value: &Value) {
        let stdin = self.stdin.as_mut().unwrap();
        writeln!(stdin, "{value}").unwrap();
        stdin.flush().unwrap();
    }

    fn receive(&self) -> Value {
        self.messages
            .recv_timeout(Duration::from_secs(5))
            .expect("bridge did not respond")
    }

    fn initialized(&mut self) {
        self.send(&json!({"jsonrpc":"2.0","method":"notifications/initialized"}));
    }

    fn finish(&mut self) -> String {
        self.stdin.take();
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                assert!(status.success());
                let mut stderr = String::new();
                self.child
                    .stderr
                    .take()
                    .unwrap()
                    .read_to_string(&mut stderr)
                    .unwrap();
                return stderr;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "stdin EOF did not stop the bridge"
            );
            thread::sleep(Duration::from_millis(10));
        }
    }
}

impl Drop for Harness {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn read(reader: &mut BufReader<UnixStream>) -> Value {
    let mut line = String::new();
    reader.read_line(&mut line).unwrap();
    serde_json::from_str(&line).unwrap()
}

fn write(writer: &mut UnixStream, value: &Value) {
    writeln!(writer, "{value}").unwrap();
}

fn initialize(
    stream: UnixStream,
    delay: Duration,
    replayed: bool,
) -> (BufReader<UnixStream>, UnixStream) {
    stream
        .set_read_timeout(Some(Duration::from_secs(15)))
        .unwrap();
    let mut writer = stream.try_clone().unwrap();
    let mut reader = BufReader::new(stream);
    assert_eq!(read(&mut reader)["client"], "codex");
    let init = read(&mut reader);
    assert_eq!(init["method"], "initialize");
    thread::sleep(delay);
    write(
        &mut writer,
        &json!({"jsonrpc":"2.0","id":init["id"],"result":{
            "protocolVersion":"2025-11-25","capabilities":{"tools":{},"resources":{}},
            "serverInfo":{"name":"fake-wallet","version":BUILD_VERSION}
        }}),
    );
    if replayed {
        assert_eq!(read(&mut reader)["method"], "notifications/initialized");
    }
    for _ in 0..2 {
        let request = read(&mut reader);
        let result = match request["method"].as_str().unwrap() {
            "tools/list" => catalog(),
            "resources/list" => json!({"resources":[]}),
            method => panic!("unexpected handshake method: {method}"),
        };
        write(
            &mut writer,
            &json!({"jsonrpc":"2.0","id":request["id"],"result":result}),
        );
    }
    (reader, writer)
}

#[test]
fn slow_startup_keeps_the_same_handshake_and_announces_real_tools() {
    let home = tempfile::tempdir().unwrap();
    let listener = UnixListener::bind(home.path().join("mcp.sock")).unwrap();
    let wallet = thread::spawn(move || {
        // This exceeds the two-second startup deadline. Cancelling that
        // handshake used to discard its response and restart it forever.
        let (stream, _) = listener.accept().unwrap();
        let (mut reader, mut writer) = initialize(stream, Duration::from_secs(3), false);
        assert_eq!(read(&mut reader)["method"], "notifications/initialized");
        let request = read(&mut reader);
        assert_eq!(request["method"], "tools/list");
        write(
            &mut writer,
            &json!({"jsonrpc":"2.0","id":request["id"],"result":catalog()}),
        );
        let mut eof = String::new();
        assert_eq!(reader.read_line(&mut eof).unwrap(), 0);
    });
    let mut harness = Harness::start(home.path());
    assert_eq!(
        harness.receive()["result"]["serverInfo"]["name"],
        "ekubo-wallet-mcp-bridge"
    );
    harness.initialized();
    harness.send(&json!({"jsonrpc":"2.0","id":2,"method":"tools/list"}));
    let unavailable = harness.receive();
    assert_eq!(unavailable["error"]["code"], -32001);
    assert!(unavailable.get("result").is_none());
    harness.send(&json!({"jsonrpc":"2.0","id":3,"method":"ping"}));
    assert_eq!(harness.receive()["id"], 3);
    assert_eq!(
        harness.receive()["method"],
        "notifications/tools/list_changed"
    );
    assert_eq!(
        harness.receive()["method"],
        "notifications/resources/list_changed"
    );
    harness.send(&json!({"jsonrpc":"2.0","id":4,"method":"tools/list"}));
    assert_eq!(harness.receive()["result"], catalog());
    harness.finish();
    wallet.join().unwrap();
}

#[test]
fn transient_handshake_failure_recovers_within_startup_and_reports_the_cause() {
    let home = tempfile::tempdir().unwrap();
    let listener = UnixListener::bind(home.path().join("mcp.sock")).unwrap();
    let wallet = thread::spawn(move || {
        let (first, _) = listener.accept().unwrap();
        let mut first = BufReader::new(first);
        read(&mut first); // hello
        read(&mut first); // initialize
        drop(first);
        let (second, _) = listener.accept().unwrap();
        let (mut reader, _) = initialize(second, Duration::ZERO, false);
        let mut eof = String::new();
        assert_eq!(reader.read_line(&mut eof).unwrap(), 0);
    });
    let mut harness = Harness::start(home.path());
    assert_eq!(
        harness.receive()["result"]["serverInfo"]["name"],
        "fake-wallet"
    );
    let stderr = harness.finish();
    assert!(
        stderr.contains("wallet closed during MCP initialization"),
        "{stderr}"
    );
    assert!(stderr.contains("connection recovered"), "{stderr}");
    wallet.join().unwrap();
}

#[test]
fn hung_handshake_times_out_without_blocking_ping_or_stdin_eof() {
    let home = tempfile::tempdir().unwrap();
    let listener = UnixListener::bind(home.path().join("mcp.sock")).unwrap();
    let (ready_tx, ready_rx) = mpsc::channel();
    let wallet = thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(13)))
            .unwrap();
        let mut first = BufReader::new(stream);
        read(&mut first);
        read(&mut first);
        let mut eof = String::new();
        assert_eq!(
            first.read_line(&mut eof).unwrap(),
            0,
            "handshake deadline did not close the socket"
        );
        let (second, _) = listener.accept().unwrap();
        second
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        let mut second = BufReader::new(second);
        read(&mut second);
        read(&mut second);
        ready_tx.send(()).unwrap();
        assert_eq!(
            second.read_line(&mut eof).unwrap(),
            0,
            "stdin EOF did not cancel reconnect"
        );
    });
    let mut harness = Harness::start(home.path());
    harness.receive();
    harness.initialized();
    harness.send(&json!({"jsonrpc":"2.0","id":2,"method":"ping"}));
    assert_eq!(
        harness
            .messages
            .recv_timeout(Duration::from_secs(1))
            .unwrap()["id"],
        2
    );
    ready_rx
        .recv_timeout(Duration::from_secs(12))
        .expect("timed-out handshake was not retried");
    harness.send(&json!({"jsonrpc":"2.0","id":3,"method":"ping"}));
    assert_eq!(
        harness
            .messages
            .recv_timeout(Duration::from_secs(1))
            .unwrap()["id"],
        3
    );
    let stderr = harness.finish();
    assert!(stderr.contains("handshake timed out"), "{stderr}");
    wallet.join().unwrap();
}

#[test]
fn broken_write_fails_the_request_without_replay_and_reconnects() {
    let home = tempfile::tempdir().unwrap();
    let listener = UnixListener::bind(home.path().join("mcp.sock")).unwrap();
    let (ready_tx, ready_rx) = mpsc::channel();
    let wallet = thread::spawn(move || {
        let (first, _) = listener.accept().unwrap();
        let (mut reader, writer) = initialize(first, Duration::ZERO, false);
        assert_eq!(read(&mut reader)["method"], "notifications/initialized");
        // Keep the write half open so EOF cannot win the race: the bridge
        // must handle its own failed write instead of exiting through `?`.
        reader.get_ref().shutdown(Shutdown::Read).unwrap();
        ready_tx.send(()).unwrap();
        let (second, _) = listener.accept().unwrap();
        let (mut reader, mut writer2) = initialize(second, Duration::ZERO, true);
        // Finishing our handshake writes does not mean the bridge has polled
        // them yet. A tools/list probe can still be answered from its cache.
        // This upstream notification is forwarded only after it accepts the
        // reconnected session, providing a deterministic readiness barrier.
        write(
            &mut writer2,
            &json!({"jsonrpc":"2.0","method":"notifications/message","params":{
                "level":"info","data":"test reconnect ready"
            }}),
        );
        let request = read(&mut reader);
        assert_eq!(
            request["id"], "after-reconnect",
            "interrupted request was replayed"
        );
        write(
            &mut writer2,
            &json!({"jsonrpc":"2.0","id":request["id"],"result":catalog()}),
        );
        let mut eof = String::new();
        assert_eq!(reader.read_line(&mut eof).unwrap(), 0);
        drop(writer);
    });
    let mut harness = Harness::start(home.path());
    harness.receive();
    harness.initialized();
    ready_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    harness.send(&json!({"jsonrpc":"2.0","id":"interrupted","method":"tools/call","params":{"name":"wallet_test","arguments":{}}}));
    let failure = harness.receive();
    assert_eq!(failure["id"], "interrupted");
    assert!(
        failure["error"]["message"]
            .as_str()
            .unwrap()
            .contains("may have executed")
    );
    let ready = harness.receive();
    assert_eq!(ready["method"], "notifications/message");
    assert_eq!(ready["params"]["data"], "test reconnect ready");
    harness.send(&json!({"jsonrpc":"2.0","id":"after-reconnect","method":"tools/list"}));
    assert_eq!(harness.receive()["result"], catalog());
    harness.finish();
    wallet.join().unwrap();
}
