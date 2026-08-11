//! Tests for [`super`].
//!
//! Out of line so the audit corpus is production code: V12 bills measured
//! bytes and excludes `*_test.rs` by default. A `#[path]` child module has
//! exactly the privacy access an inline one does, so nothing these can reach
//! changes, and the test paths are the ones they always were.

use super::*;
use alloy::primitives::U256;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
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

/// Like [`stub_endpoint`], but never closes the connection and counts how
/// many distinct ones it accepts — proof, not assumption, that
/// [`super::provider_for`] pools a connection per endpoint instead of dialing
/// fresh on every call. Requests are answered one `read` at a time rather
/// than framed by `Content-Length`, matching [`stub_endpoint`]'s own
/// simplification: the `eth_chainId`/`eth_blockNumber` bodies this module
/// sends are a few dozen bytes, well inside one TCP segment on loopback, so
/// each `read` is one complete request in practice.
fn keep_alive_stub_endpoint(chain_id: u64, block_number: u64) -> (Url, Arc<AtomicUsize>) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind a stub endpoint");
    let address = listener.local_addr().expect("stub endpoint address");
    let connections = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&connections);
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(stream) = stream else { return };
            counter.fetch_add(1, Ordering::SeqCst);
            // A connection that is kept open must be served on its own
            // thread: a client that pools connections holds this one open
            // indefinitely between requests, and a single-threaded accept
            // loop would block here forever instead of accepting the next
            // connection a non-pooling client opens.
            std::thread::spawn(move || serve_keep_alive_connection(stream, chain_id, block_number));
        }
    });
    (
        format!("http://{address}/").parse().expect("stub URL"),
        connections,
    )
}

fn serve_keep_alive_connection(mut stream: std::net::TcpStream, chain_id: u64, block_number: u64) {
    use std::io::{Read as _, Write as _};
    let mut buffer = [0_u8; 4096];
    loop {
        let Ok(read) = stream.read(&mut buffer) else {
            return;
        };
        if read == 0 {
            return;
        }
        let request = String::from_utf8_lossy(&buffer[..read]).to_string();
        let result = if request.contains("eth_chainId") {
            format!("\"{chain_id:#x}\"")
        } else {
            format!("\"{block_number:#x}\"")
        };
        let body = format!("{{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{result}}}");
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        );
        if stream.write_all(response.as_bytes()).is_err() {
            return;
        }
    }
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
        rpc_strategy: crate::config::RpcStrategy::Ordered,
        max_gas_limit: None,
        max_fee_per_gas: None,
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

/// [`provider_for`] pools one provider per endpoint precisely so that
/// separate top-level reads — separate polls of
/// `wallet_wait_for_execution`'s once-a-second confirmation loop, in
/// production — reuse already-open connections instead of paying a fresh TCP
/// handshake each time. `latest_block_number` opens two connections on its
/// first call (`get_chain_id` and `get_block_number` run concurrently via
/// `tokio::try_join!`, both against a pool that starts empty), which is the
/// floor this test can prove against: without pooling, each of the five
/// calls below would open its own two, for ten in total — proven by running
/// this same assertion against the unpooled `provider_for` first and
/// watching it fail with `left: 10`. With pooling, the second call onward
/// finds both connections already idle in the pool, so the count stays at
/// two for all five reads instead of growing with every one of them.
#[tokio::test]
async fn repeated_reads_to_one_endpoint_reuse_the_same_two_pooled_connections() {
    let (endpoint, connections) = keep_alive_stub_endpoint(7, 4242);
    let network = network_with(7, vec![endpoint]);
    for _ in 0..5 {
        assert_eq!(
            latest_block_number(&network)
                .await
                .expect("the stub answered"),
            4242
        );
    }
    assert_eq!(
        connections.load(Ordering::SeqCst),
        2,
        "five reads to the same endpoint should reuse the same two pooled connections, not open ten"
    );
}

#[test]
fn a_receipt_the_lifecycle_cannot_store_is_the_endpoints_failure() {
    // Both fields arrive as u64 and land in signed INTEGER columns. The
    // conversion used to fail at the far end, inside `PendingStore::finalize`,
    // after this answer had already been accepted as the truth about the
    // chain: the row stayed `broadcast`, held the wallet's one in-flight slot
    // for that chain, and asking again reached the same endpoint.
    assert!(storable_receipt_fields(21_000_000, 21_000).is_ok());
    assert!(storable_receipt_fields(u64::MAX, 21_000).is_err());
    assert!(storable_receipt_fields(21_000_000, u64::MAX).is_err());

    // The boundary itself is storable; one past it is not.
    let highest = u64::try_from(i64::MAX).unwrap();
    assert!(storable_receipt_fields(highest, highest).is_ok());
    assert!(storable_receipt_fields(highest + 1, 0).is_err());
}

/// A stub endpoint that answers `eth_getTransactionReceipt` with a receipt for
/// whichever hash the caller chose, regardless of which one was asked about.
/// That mismatch is the whole point: the receipt lookup used to take the
/// endpoint's word that a response was an answer to the request.
fn receipt_stub(chain_id: u64, receipt_for: B256) -> (Url, std::thread::JoinHandle<()>) {
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
            let body = if request.contains("eth_chainId") {
                format!("{{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":\"{chain_id:#x}\"}}")
            } else {
                format!(
                    "{{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{{\
                       \"transactionHash\":\"{receipt_for:#x}\",\
                       \"transactionIndex\":\"0x0\",\
                       \"blockHash\":\"0x{}\",\
                       \"blockNumber\":\"0x64\",\
                       \"from\":\"0x1111111111111111111111111111111111111111\",\
                       \"to\":\"0x2222222222222222222222222222222222222222\",\
                       \"cumulativeGasUsed\":\"0x5208\",\
                       \"gasUsed\":\"0x5208\",\
                       \"effectiveGasPrice\":\"0x1\",\
                       \"logs\":[],\
                       \"logsBloom\":\"0x{}\",\
                       \"status\":\"0x1\",\
                       \"type\":\"0x2\"\
                     }}}}",
                    "22".repeat(32),
                    "00".repeat(256)
                )
            };
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

/// Every terminal settlement in the wallet runs through `transaction_receipt`,
/// and none of the states it produces is ever reconciled again -- reaching one
/// releases the wallet's in-flight slot for that chain. The request named a
/// hash and the response was taken as the answer to it on the endpoint's word
/// alone, so an endpoint returning an unrelated receipt could settle a
/// still-live envelope as confirmed, and the real one would go on to mine with
/// nothing watching it.
#[tokio::test]
async fn a_receipt_for_another_transaction_is_not_an_answer() {
    let asked_about = B256::repeat_byte(0xaa);
    let unrelated = B256::repeat_byte(0xbb);
    let (endpoint, _handle) = receipt_stub(7, unrelated);
    let network = network_with(7, vec![endpoint]);

    let error = format!(
        "{:#}",
        transaction_receipt(&network, &format!("{asked_about:#x}"))
            .await
            .expect_err("a receipt for a different transaction settles nothing")
    );
    assert!(error.contains("rather than the requested"), "{error}");

    // The honest case still works, so the check is not simply refusing.
    let (honest, _handle) = receipt_stub(7, asked_about);
    let network = network_with(7, vec![honest]);
    let receipt = transaction_receipt(&network, &format!("{asked_about:#x}"))
        .await
        .unwrap()
        .expect("the endpoint answered about the transaction that was asked about");
    assert!(receipt.succeeded);
    assert_eq!(receipt.block_number, 100);
}
