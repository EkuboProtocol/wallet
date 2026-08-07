//! Tests for [`super`].
//!
//! Out of line so the audit corpus is production code: V12 bills measured
//! bytes and excludes `*_test.rs` by default. A `#[path]` child module has
//! exactly the privacy access an inline one does, so nothing these can reach
//! changes, and the test paths are the ones they always were.

use super::*;
use alloy::primitives::U256;
use url::Url;

#[test]
fn parses_only_eip7702_delegation_designators() {
    let mut code = vec![0xef, 0x01, 0x00];
    code.extend([0x11; 20]);
    assert_eq!(
        delegated_implementation(&Bytes::from(code)),
        Some(Address::repeat_byte(0x11))
    );
    assert_eq!(delegated_implementation(&Bytes::from(vec![0xef, 1])), None);
}

/// The RPC URL is configuration, not a secret: a provider credential embedded
/// in it is read-only and easy to rotate, so errors name the exact endpoint
/// that failed rather than redacting it.
#[test]
fn rpc_errors_repeat_the_endpoint_verbatim() {
    let url = "https://user:secret@example.invalid/v3/PROJECTKEY";
    let message = rpc_error(&format_args!("request to {url} failed")).to_string();
    assert_eq!(
        message,
        format!("RPC request failed: request to {url} failed")
    );
}

#[test]
fn u256_balance_format_is_decimal() {
    assert_eq!(U256::from(123_u64).to_string(), "123");
}

/// A blocking stub JSON-RPC server, on a std thread rather than the test's
/// runtime, so the failover client under test is the only async thing here.
///
/// It answers exactly the two methods every read in this module opens with,
/// which is what makes it enough to prove where a request went: the chain ID
/// it reports identifies it.
fn stub_endpoint(chain_id: u64, block_number: u64) -> (Url, std::thread::JoinHandle<()>) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind a stub endpoint");
    let address = listener.local_addr().expect("stub endpoint address");
    let handle = std::thread::spawn(move || {
        use std::io::{Read as _, Write as _};
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { return };
            let mut buffer = [0_u8; 4096];
            let Ok(read) = stream.read(&mut buffer) else {
                continue;
            };
            let request = String::from_utf8_lossy(&buffer[..read]).to_string();
            let result = if request.contains("eth_chainId") {
                format!("\"{chain_id:#x}\"")
            } else {
                format!("\"{block_number:#x}\"")
            };
            let body = format!("{{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{result}}}");
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = stream.write_all(response.as_bytes());
        }
    });
    (
        format!("http://{address}/").parse().expect("stub URL"),
        handle,
    )
}

/// Port 1 on loopback: nothing listens there, so a connection is refused
/// immediately rather than after a timeout, which keeps these tests fast while
/// still exercising the "this endpoint did not answer" path.
fn dead_endpoint() -> Url {
    "http://127.0.0.1:1/".parse().expect("dead endpoint URL")
}

fn network_with(chain_id: u64, rpc_urls: Vec<Url>) -> NetworkConfig {
    NetworkConfig {
        name: "failovernet".into(),
        display_name: None,
        aliases: Vec::new(),
        chain_id,
        rpc_urls,
        max_gas_limit: None,
        native_currency: None,
        block_explorer_url: None,
        documentation_url: None,
    }
}

/// The property the whole feature exists for: one healthy endpoint anywhere in
/// the list is enough, however many dead ones precede it.
#[tokio::test]
async fn a_read_survives_every_endpoint_but_the_last() {
    let (healthy, _server) = stub_endpoint(7, 4242);
    let network = network_with(7, vec![dead_endpoint(), dead_endpoint(), healthy]);
    assert_eq!(
        latest_block_number(&network)
            .await
            .expect("the healthy endpoint answered"),
        4242
    );
}

/// An endpoint serving a different chain is disqualified, not obeyed. Reading
/// a balance from the wrong chain and reporting it under this network's name
/// is worse than reporting nothing.
#[tokio::test]
async fn an_endpoint_on_the_wrong_chain_is_skipped() {
    let (impostor, _wrong) = stub_endpoint(999, 1);
    let (honest, _right) = stub_endpoint(7, 5150);
    let network = network_with(7, vec![impostor, honest]);
    assert_eq!(
        latest_block_number(&network)
            .await
            .expect("the endpoint on the right chain answered"),
        5150
    );
}

/// When nothing answers, the error names every endpoint tried and what each
/// one said. A wallet that cannot reach a chain is a support question, and
/// "RPC request failed" about an unnamed member of a list of six does not
/// answer it.
#[tokio::test]
async fn the_failure_names_every_endpoint_it_tried() {
    let (impostor, _wrong) = stub_endpoint(999, 1);
    let dead = dead_endpoint();
    let network = network_with(7, vec![dead.clone(), impostor.clone()]);
    let error = format!(
        "{:#}",
        latest_block_number(&network)
            .await
            .expect_err("no endpoint could answer")
    );
    assert!(error.contains("all 2 RPC endpoints"), "unexpected: {error}");
    assert!(error.contains(dead.as_str()), "unexpected: {error}");
    assert!(error.contains(impostor.as_str()), "unexpected: {error}");
    // The reason each one failed, not merely its name: a wrong chain and a
    // refused connection call for different fixes.
    assert!(
        error.contains("RPC reports chain 999, not 7"),
        "unexpected: {error}"
    );
}

/// Failover stops at the first success. A later endpoint answering differently
/// must never be consulted, because two endpoints disagreeing is not something
/// a read can resolve by asking again.
#[tokio::test]
async fn a_successful_endpoint_ends_the_search() {
    let (first, _a) = stub_endpoint(7, 100);
    let (second, _b) = stub_endpoint(7, 200);
    let network = network_with(7, vec![first, second]);
    assert_eq!(latest_block_number(&network).await.unwrap(), 100);
}
