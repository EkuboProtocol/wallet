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

use crate::config::RpcStrategy;

fn strategy_network(strategy: RpcStrategy, rpc_urls: Vec<Url>) -> NetworkConfig {
    let mut network = network_with(7, rpc_urls);
    network.rpc_strategy = strategy;
    network
}

/// `m_of_n` returns an answer only once the required number of endpoints have
/// returned the same one.
#[tokio::test]
async fn agreement_returns_the_answer_two_endpoints_share() {
    let (first, _a) = stub_endpoint(7, 500);
    let (second, _b) = stub_endpoint(7, 500);
    let network = strategy_network(RpcStrategy::MOfN { agree: 2 }, vec![first, second]);
    let block = crate::rpc::agree_across_endpoints(&network, |provider| async move {
        with_timeout(provider.get_block_number()).await
    })
    .await
    .expect("both endpoints said the same thing");
    assert_eq!(block, 500);
}

/// The property the strategy exists for: one endpoint's word is not enough,
/// and a contradiction is refused rather than resolved by picking a side.
#[tokio::test]
async fn agreement_refuses_a_contradiction_instead_of_choosing() {
    let (honest, _a) = stub_endpoint(7, 500);
    let (liar, _b) = stub_endpoint(7, 999_999);
    let network = strategy_network(RpcStrategy::MOfN { agree: 2 }, vec![honest, liar]);
    let error = format!(
        "{:#}",
        crate::rpc::agree_across_endpoints(&network, |provider| async move {
            with_timeout(provider.get_block_number()).await
        })
        .await
        .expect_err("a disagreement must not produce an answer")
    );
    assert!(error.contains("do not agree"), "unexpected: {error}");
    // Naming the endpoints on each side is what makes the report actionable.
    assert!(error.contains("2 distinct answers"), "unexpected: {error}");
}

/// An endpoint that fails is a missing witness, not a dissenting one: it must
/// neither count toward agreement nor be mistaken for a contradiction.
#[tokio::test]
async fn a_dead_endpoint_is_not_a_dissenting_vote() {
    let (first, _a) = stub_endpoint(7, 500);
    let (second, _b) = stub_endpoint(7, 500);
    let network = strategy_network(
        RpcStrategy::MOfN { agree: 2 },
        vec![dead_endpoint(), first, second],
    );
    assert_eq!(
        crate::rpc::agree_across_endpoints(&network, |provider| async move {
            with_timeout(provider.get_block_number()).await
        })
        .await
        .expect("two live endpoints agreed"),
        500
    );
}

/// Too few witnesses is reported as unavailability, not as a disagreement:
/// they are different problems and lead to different fixes.
#[tokio::test]
async fn too_few_answers_reads_as_unavailable() {
    let (only, _a) = stub_endpoint(7, 500);
    let network = strategy_network(RpcStrategy::MOfN { agree: 2 }, vec![only, dead_endpoint()]);
    let error = format!(
        "{:#}",
        crate::rpc::agree_across_endpoints(&network, |provider| async move {
            with_timeout(provider.get_block_number()).await
        })
        .await
        .expect_err("one witness is not two")
    );
    assert!(error.contains("requires 2 endpoints to agree"), "{error}");
    assert!(error.contains("only 1 answered"), "{error}");
}

/// Under `ordered` and `random` the agreement helper is plain failover: one
/// answer, from whoever answers first.
#[tokio::test]
async fn a_single_answer_is_enough_without_m_of_n() {
    for strategy in [RpcStrategy::Ordered, RpcStrategy::Random] {
        let (first, _a) = stub_endpoint(7, 500);
        let (second, _b) = stub_endpoint(7, 999_999);
        let network = strategy_network(strategy, vec![first, second]);
        let block = crate::rpc::agree_across_endpoints(&network, |provider| async move {
            with_timeout(provider.get_block_number()).await
        })
        .await
        .expect("one answer suffices");
        assert!(
            block == 500 || block == 999_999,
            "{strategy} took an answer"
        );
    }
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
/// [`stub_endpoint`] and for the same reason. `median_fee_estimate` never
/// checks `eth_chainId`, so this answers only the one method it calls.
///
/// `base_fee_per_gas` is repeated so [`alloy::providers::Provider::estimate_eip1559_fees`]'s
/// `latest_block_base_fee` (the second-to-last element) reads it back, and the
/// single reward bucket is what alloy's default estimator takes as this
/// endpoint's priority-fee vote.
fn fee_history_stub(base_fee_per_gas: u128, reward: u128) -> (Url, std::thread::JoinHandle<()>) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind a stub endpoint");
    let address = listener.local_addr().expect("stub endpoint address");
    let handle = std::thread::spawn(move || {
        use std::io::{Read as _, Write as _};
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { return };
            let mut buffer = [0_u8; 4096];
            let Ok(_read) = stream.read(&mut buffer) else {
                continue;
            };
            let body = format!(
                "{{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{{\"baseFeePerGas\":[\"{base_fee_per_gas:#x}\",\"{base_fee_per_gas:#x}\"],\"gasUsedRatio\":[0.5],\"oldestBlock\":\"0x1\",\"reward\":[[\"{reward:#x}\"]]}}}}"
            );
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

/// One endpoint answering is one witness short under `agree: 2`. Without this
/// the loop's own `required` bookkeeping — not just `agree_across_endpoints`'s,
/// which this function does not call — is what has to reject it.
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
