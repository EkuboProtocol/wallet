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

use crate::config::RpcStrategy;

fn strategy_network(strategy: RpcStrategy, rpc_urls: Vec<Url>) -> NetworkConfig {
    let mut network = network_with(7, rpc_urls);
    network.rpc_strategy = strategy;
    network
}

#[test]
fn the_median_fee_is_one_an_endpoint_returned() {
    // The lower middle for an even count, so the answer is always a value some
    // endpoint actually named rather than an average of two that nobody did.
    assert_eq!(median(&mut [7]), 7);
    assert_eq!(median(&mut [9, 1]), 1);
    assert_eq!(median(&mut [9, 1, 5]), 5);
    assert_eq!(median(&mut [1, 2, 3, 4]), 2);

    // The property that matters: with a majority honest, one endpoint naming
    // an absurd number cannot move the answer past what the honest ones said.
    assert_eq!(median(&mut [100, 110, u128::MAX]), 110);
    assert_eq!(median(&mut [100, 110, 0]), 100);
}

#[tokio::test]
async fn a_single_answer_strategy_pins_nothing() {
    // There is no quorum to protect: the endpoint that runs the simulation
    // reads its own head, and no other endpoint is held to it.
    let mut network = network_with(1, vec![dead_endpoint()]);
    network.rpc_strategy = crate::config::RpcStrategy::Ordered;
    assert_eq!(median_head(&network).await.unwrap(), None);
    network.rpc_strategy = crate::config::RpcStrategy::Random;
    assert_eq!(median_head(&network).await.unwrap(), None);

    // And a quorum whose endpoints cannot be reached fails rather than
    // falling back to one endpoint's word about the head.
    network.rpc_strategy = crate::config::RpcStrategy::MOfN { agree: 2 };
    assert!(median_head(&network).await.is_err());
}

/// The happy path `a_single_answer_strategy_pins_nothing` never reaches: real
/// endpoints answering with different heights, reduced to the height an
/// honest endpoint actually reported rather than an average nobody did.
#[tokio::test]
async fn median_head_pins_to_the_median_of_the_required_endpoints() {
    let (low, _a) = stub_endpoint(7, 100);
    let (high, _b) = stub_endpoint(7, 300);
    let network = strategy_network(RpcStrategy::MOfN { agree: 2 }, vec![low, high]);
    // Lower middle of an even count, same rule as the bare `median()` helper.
    assert_eq!(median_head(&network).await.unwrap(), Some(100));
}

/// An endpoint that never answers is a missing witness, not a zero: it must
/// neither enter the median nor stop the quorum from being reached by the
/// endpoints that did answer.
#[tokio::test]
async fn median_head_excludes_a_dead_endpoint_from_the_median() {
    let (low, _a) = stub_endpoint(7, 100);
    let (high, _b) = stub_endpoint(7, 300);
    let network = strategy_network(
        RpcStrategy::MOfN { agree: 2 },
        vec![dead_endpoint(), low, high],
    );
    assert_eq!(median_head(&network).await.unwrap(), Some(100));
}

/// A blocking stub `eth_feeHistory` responder, built the same way as
/// [`stub_endpoint`] and for the same reason. It answers `eth_chainId` too:
/// `median_fee_estimate` now refuses a witness that is not on the configured
/// chain, so a stub that stayed silent about its chain would be skipped.
///
/// `base_fee_per_gas` is repeated so [`alloy::providers::Provider::estimate_eip1559_fees`]'s
/// `latest_block_base_fee` (the second-to-last element) reads it back, and the
/// single reward bucket is what alloy's default estimator takes as this
/// endpoint's priority-fee vote.
fn fee_history_stub(base_fee_per_gas: u128, reward: u128) -> (Url, std::thread::JoinHandle<()>) {
    fee_history_stub_on_chain(7, base_fee_per_gas, reward)
}

/// The same stub, on a chain the caller picks, so a wrong-chain endpoint can
/// be put in front of `median_fee_estimate` and `median_head`.
fn fee_history_stub_on_chain(
    chain_id: u64,
    base_fee_per_gas: u128,
    reward: u128,
) -> (Url, std::thread::JoinHandle<()>) {
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
                    "{{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{{\"baseFeePerGas\":[\"{base_fee_per_gas:#x}\",\"{base_fee_per_gas:#x}\"],\"gasUsedRatio\":[0.5],\"oldestBlock\":\"0x1\",\"reward\":[[\"{reward:#x}\"]]}}}}"
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

/// Nothing exercised `median_fee_estimate`'s own loop before this: only its
/// `median()` helper had a test. Two endpoints reporting the same fee data
/// must both be counted before an `m_of_n` estimate is returned.
#[tokio::test]
async fn median_fee_estimate_requires_quorum_before_returning() {
    let (first, _a) = fee_history_stub(100, 20);
    let (second, _b) = fee_history_stub(100, 20);
    let network = strategy_network(RpcStrategy::MOfN { agree: 2 }, vec![first, second]);
    assert_eq!(
        median_fee_estimate(&network, 0, 0).await.unwrap(),
        (220, 20)
    );
}

/// One endpoint answering is one witness short under `agree: 2`.
#[tokio::test]
async fn median_fee_estimate_refuses_to_answer_on_one_witness() {
    let (only, _a) = fee_history_stub(100, 20);
    let network = strategy_network(RpcStrategy::MOfN { agree: 2 }, vec![only, dead_endpoint()]);
    let error = format!(
        "{:#}",
        median_fee_estimate(&network, 0, 0).await.unwrap_err()
    );
    assert!(
        error.contains("requires 2 endpoints to agree on the fee but only 1 answered"),
        "{error}"
    );
}

/// The property `m_of_n` fee estimation exists for: a dead endpoint is
/// skipped rather than counted or waited on, and the two fields are each the
/// median an honest endpoint actually reported — not the first answer, and
/// not an average nobody returned.
#[tokio::test]
async fn median_fee_estimate_excludes_a_dead_endpoint_and_takes_the_median() {
    let (low, _a) = fee_history_stub(10, 1); // max_fee 21, priority 1
    let (mid, _b) = fee_history_stub(20, 2); // max_fee 42, priority 2
    let (high, _c) = fee_history_stub(30, 3); // max_fee 63, priority 3
    let network = strategy_network(
        RpcStrategy::MOfN { agree: 3 },
        vec![dead_endpoint(), low, mid, high],
    );
    assert_eq!(median_fee_estimate(&network, 0, 0).await.unwrap(), (42, 2));
}

/// Under `ordered` and `random` there is no quorum to spend requests on: the
/// endpoint that answered the rest of preparation is trusted as-is, and this
/// function must return without ever asking the network. A network built from
/// only a dead endpoint proves it — any RPC attempt here would fail.
#[tokio::test]
async fn median_fee_estimate_is_a_no_op_without_m_of_n() {
    let network = strategy_network(RpcStrategy::Ordered, vec![dead_endpoint()]);
    assert_eq!(
        median_fee_estimate(&network, 500, 50).await.unwrap(),
        (500, 50)
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

/// The pin the whole quorum simulates against, chosen by one stale endpoint.
///
/// `median_head` stopped sampling at `required`, so with `m_of_n(2)` over
/// three endpoints the first two answers *were* the sample. One stale endpoint
/// answering alongside one current endpoint is half of it, the lower median
/// takes the stale height, and the honest third endpoint never contributes.
/// Every remaining endpoint is then held to that height and agrees honestly
/// about it -- a real quorum over the attacker's choice of state.
#[tokio::test]
async fn median_head_samples_every_endpoint_not_the_first_to_answer() {
    let (stale, _a) = stub_endpoint(7, 100);
    let (current, _b) = stub_endpoint(7, 300);
    let (also_current, _c) = stub_endpoint(7, 300);
    let network = strategy_network(
        RpcStrategy::MOfN { agree: 2 },
        vec![stale, current, also_current],
    );
    assert_eq!(
        median_head(&network).await.unwrap(),
        Some(300),
        "a single stale endpoint must not choose the height two honest ones disagree with"
    );
}

/// The same sampling bug on the fee path, where the number reaches the chain
/// rather than the screen: `gas_limit x max_fee_per_gas` is what an automatic
/// transaction can lose to an endpoint that answers dishonestly.
#[tokio::test]
async fn median_fee_estimate_samples_every_endpoint_not_the_first_to_answer() {
    // The liar answers low and answers first. `median` takes the lower of the
    // two middle values, so in a truncated two-endpoint sample the low answer
    // *is* the median -- and the honest third endpoint, which would have
    // carried it, was never asked. A fee estimate driven under the market
    // leaves an automatic transaction stuck in the mempool holding the
    // wallet's one in-flight slot for that chain.
    let (understated, _a) = fee_history_stub(10, 1); // max_fee 21, priority 1
    let (market, _b) = fee_history_stub(1_000, 100); // max_fee 2100, priority 100
    let (also_market, _c) = fee_history_stub(1_000, 100);
    let network = strategy_network(
        RpcStrategy::MOfN { agree: 2 },
        vec![understated, market, also_market],
    );
    assert_eq!(
        median_fee_estimate(&network, 0, 0).await.unwrap(),
        (2100, 100),
        "one endpoint answering below the market must not choose the fee two others disagree with"
    );
}

/// A vote cannot be taken back out of a median once it is in.
///
/// Nothing requires every configured endpoint to serve the configured chain --
/// `validate_network` checks the shape of the RPC list, not its identity -- and
/// an endpoint on another chain reports that chain's height. `median_head` took
/// it. `simulate_execution_through` does check the chain, but far too late: by
/// then the wrong-chain height is already the pin every honest endpoint is held
/// to, and disqualifying that endpoint from simulating does not unmake the pin
/// it chose.
#[tokio::test]
async fn median_head_refuses_a_witness_serving_another_chain() {
    let (impostor, _a) = stub_endpoint(999, 100);
    let (honest, _b) = stub_endpoint(7, 300);
    let (also_honest, _c) = stub_endpoint(7, 300);
    let network = strategy_network(
        RpcStrategy::MOfN { agree: 2 },
        vec![impostor, honest, also_honest],
    );
    assert_eq!(
        median_head(&network).await.unwrap(),
        Some(300),
        "a height from another chain must not enter the median"
    );

    // And it is not counted toward the quorum either: two endpoints, one of
    // them on the wrong chain, is one witness.
    let (impostor, _d) = stub_endpoint(999, 100);
    let (lonely, _e) = stub_endpoint(7, 300);
    let network = strategy_network(RpcStrategy::MOfN { agree: 2 }, vec![impostor, lonely]);
    let error = format!("{:#}", median_head(&network).await.unwrap_err());
    assert!(error.contains("only 1"), "{error}");
}

/// The same door, on the fee path.
#[tokio::test]
async fn median_fee_estimate_refuses_a_witness_serving_another_chain() {
    let (impostor, _a) = fee_history_stub_on_chain(999, 10, 1); // max_fee 21
    let (honest, _b) = fee_history_stub(1_000, 100); // max_fee 2100
    let (also_honest, _c) = fee_history_stub(1_000, 100);
    let network = strategy_network(
        RpcStrategy::MOfN { agree: 2 },
        vec![impostor, honest, also_honest],
    );
    assert_eq!(
        median_fee_estimate(&network, 0, 0).await.unwrap(),
        (2100, 100),
        "a fee from another chain must not enter the median"
    );
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
