use serde_json::{Value, json};
use std::{
    io::{BufRead as _, BufReader, Write as _},
    process::{Command, Stdio},
    time::Duration,
};

fn send(stdin: &mut std::process::ChildStdin, value: Value) {
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
        json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"test","version":"1"}}}),
    );
    let initialized = receive(&mut stdout);
    assert_eq!(initialized["id"], 1);
    assert_eq!(
        initialized["result"]["capabilities"]["tools"]["listChanged"],
        true
    );
    send(
        &mut stdin,
        json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
    );
    send(
        &mut stdin,
        json!({"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}),
    );
    let tools = receive(&mut stdout);
    assert_eq!(tools["result"], json!({"tools":[]}));
    send(
        &mut stdin,
        json!({"jsonrpc":"2.0","id":"call","method":"tools/call","params":{"name":"missing","arguments":{}}}),
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
