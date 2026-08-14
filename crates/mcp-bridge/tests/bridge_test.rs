use serde_json::{Value, json};
use std::{
    io::{BufRead as _, BufReader, Write as _},
    process::{Command, Stdio},
    sync::mpsc,
    time::Duration,
};

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
        initialized["result"]["capabilities"]["tools"]["listChanged"],
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
    fn handshake(stream: UnixStream, catalog: &Value) -> (BufReader<UnixStream>, UnixStream) {
        let mut writer = stream.try_clone().unwrap();
        let mut reader = BufReader::new(stream);
        assert_eq!(read(&mut reader)["client"], "codex");
        let initialize = read(&mut reader);
        write(
            &mut writer,
            &json!({"jsonrpc":"2.0","id":initialize["id"],"result":{"protocolVersion":"2025-11-25","capabilities":{},"serverInfo":{"name":"fake-wallet","version":"1"}}}),
        );
        assert_eq!(read(&mut reader)["method"], "notifications/initialized");
        let list = read(&mut reader);
        assert_eq!(list["method"], "tools/list");
        write(
            &mut writer,
            &json!({"jsonrpc":"2.0","id":list["id"],"result":catalog}),
        );
        (reader, writer)
    }

    let home = tempfile::tempdir().unwrap();
    fs::set_permissions(home.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let listener = UnixListener::bind(home.path().join("mcp.sock")).unwrap();
    let catalog = json!({"tools":[{"name":"wallet_test","description":"test","inputSchema":{"type":"object"}}]});
    let (ready_tx, ready_rx) = mpsc::channel();
    let fake_catalog = catalog.clone();
    let wallet = thread::spawn(move || {
        let (first, _) = listener.accept().unwrap();
        let (mut first_read, mut first_write) = handshake(first, &fake_catalog);
        ready_tx.send(1).unwrap();

        let list = read(&mut first_read);
        assert_eq!(list["id"], 10);
        write(
            &mut first_write,
            &json!({"jsonrpc":"2.0","id":10,"result":fake_catalog}),
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
        let (mut second_read, mut second_write) = handshake(second, &fake_catalog);
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
    assert_eq!(receive(&mut stdout)["id"], 1);
    send(
        &mut stdin,
        &json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
    );
    ready_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    assert_eq!(
        receive(&mut stdout)["method"],
        "notifications/tools/list_changed"
    );
    send(
        &mut stdin,
        &json!({"jsonrpc":"2.0","id":10,"method":"tools/list","params":{}}),
    );
    assert_eq!(receive(&mut stdout)["result"], catalog);
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
