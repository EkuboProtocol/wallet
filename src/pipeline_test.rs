//! End-to-end pipeline tests over a local JSON-RPC stub.
//!
//! These pin the contract the signing orchestration must preserve across
//! refactors: the automatic path (policy allows → simulate → sign → persist →
//! broadcast → confirm) and the approval handoff (policy denies → queue →
//! human-side signing against the stored row → resubmit by request id). The
//! stub answers the exact RPC surface the pipeline touches and nothing more,
//! so any new upstream request fails loudly here.

use super::*;
use crate::{
    approval::{ApprovalDecision, ApprovalRequest, ReviewPresenter},
    config::{NetworkConfig, WalletMetadata, WalletSource},
    custody::{MemoryKeyStore, PrivateKeyMaterial},
    human_presence::TestHumanPresence,
    policy_store::DatabaseKey,
    simulation::SimulationResult,
};

/// A presenter that approves whatever it is shown: the handoff test's stand-in
/// for the terminal review.
struct ApproveEverything;

#[async_trait::async_trait]
impl ReviewPresenter for ApproveEverything {
    async fn review_transaction(
        &self,
        _request: &ApprovalRequest,
        _simulation: &SimulationResult,
    ) -> anyhow::Result<ApprovalDecision> {
        Ok(ApprovalDecision::Approved)
    }
}
use alloy::primitives::{Address, B256, keccak256};
use base64::Engine as _;
use std::{collections::HashSet, net::SocketAddr, sync::Mutex as StdMutex};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};

const CHAIN_ID: u64 = 31_337;
const PARENT_NUMBER: u64 = 100;
const BLOCK_GAS_LIMIT: u64 = 30_000_000;
const BASE_FEE: u64 = 1_000_000_000;

/// Every stub block's hash is its number repeated, so linkage is derivable.
fn hash_of(number: u64) -> B256 {
    B256::repeat_byte(u8::try_from(number & 0xff).unwrap())
}

/// The mutable chain the stub pretends to be: every raw transaction sent to
/// it is immediately mined successfully.
#[derive(Default)]
struct StubChain {
    mined: StdMutex<HashSet<B256>>,
}

fn zero_bloom() -> String {
    format!("0x{}", "00".repeat(256))
}

fn block_json(number: u64, parent: B256) -> serde_json::Value {
    serde_json::json!({
        "hash": hash_of(number),
        "parentHash": parent,
        "sha3Uncles": B256::ZERO,
        "miner": Address::ZERO,
        "stateRoot": B256::ZERO,
        "transactionsRoot": B256::ZERO,
        "receiptsRoot": B256::ZERO,
        "logsBloom": zero_bloom(),
        "difficulty": "0x0",
        "number": format!("{number:#x}"),
        "gasLimit": format!("{BLOCK_GAS_LIMIT:#x}"),
        "gasUsed": "0x0",
        "timestamp": "0x0",
        "extraData": "0x",
        "mixHash": B256::ZERO,
        "nonce": "0x0000000000000000",
        "baseFeePerGas": format!("{BASE_FEE:#x}"),
        "transactions": [],
        "uncles": []
    })
}

impl StubChain {
    fn dispatch(&self, method: &str, params: &serde_json::Value) -> serde_json::Value {
        match method {
            "eth_chainId" => serde_json::json!(format!("{CHAIN_ID:#x}")),
            "eth_getBlockByNumber" => block_json(PARENT_NUMBER, B256::repeat_byte(0xa9)),
            "eth_getCode" => serde_json::json!("0x"),
            "eth_getBalance" => serde_json::json!("0x21e19e0c9bab2400000"),
            "eth_getTransactionCount" => serde_json::json!("0x0"),
            "eth_feeHistory" => serde_json::json!({
                "oldestBlock": "0x60",
                "baseFeePerGas": vec![format!("{BASE_FEE:#x}"); 11],
                "gasUsedRatio": vec![0.5; 10],
                "reward": vec![vec![format!("{BASE_FEE:#x}")]; 10],
            }),
            "eth_simulateV1" => {
                let blocks = params[0]["blockStateCalls"]
                    .as_array()
                    .expect("simulate payload has blockStateCalls");
                let mut simulated = Vec::new();
                let mut parent = hash_of(PARENT_NUMBER);
                for (index, entry) in blocks.iter().enumerate() {
                    let number = PARENT_NUMBER + 1 + u64::try_from(index).unwrap();
                    let mut block = block_json(number, parent);
                    parent = serde_json::from_value(block["hash"].clone()).unwrap();
                    let calls = entry["calls"].as_array().map_or(0, Vec::len);
                    block["calls"] = serde_json::json!(
                        (0..calls)
                            .map(|_| serde_json::json!({
                                "returnData": "0x",
                                "logs": [],
                                "gasUsed": "0x5208",
                                "status": "0x1",
                            }))
                            .collect::<Vec<_>>()
                    );
                    simulated.push(block);
                }
                serde_json::Value::Array(simulated)
            }
            "eth_sendRawTransaction" => {
                let raw = params[0].as_str().expect("raw transaction is hex");
                let bytes = hex::decode(raw.trim_start_matches("0x")).expect("valid hex");
                let hash = keccak256(&bytes);
                self.mined.lock().unwrap().insert(hash);
                serde_json::json!(hash)
            }
            "eth_getTransactionByHash" => serde_json::Value::Null,
            "eth_getTransactionReceipt" => {
                let hash: B256 = serde_json::from_value(params[0].clone()).unwrap();
                if self.mined.lock().unwrap().contains(&hash) {
                    serde_json::json!({
                        "transactionHash": hash,
                        "transactionIndex": "0x0",
                        "blockHash": B256::repeat_byte(0xbb),
                        "blockNumber": format!("{:#x}", PARENT_NUMBER + 2),
                        "from": Address::ZERO,
                        "to": Address::ZERO,
                        "cumulativeGasUsed": "0x5208",
                        "gasUsed": "0x5208",
                        "contractAddress": null,
                        "logs": [],
                        "logsBloom": zero_bloom(),
                        "status": "0x1",
                        "type": "0x2",
                        "effectiveGasPrice": format!("{BASE_FEE:#x}"),
                    })
                } else {
                    serde_json::Value::Null
                }
            }
            other => panic!("stub RPC received unexpected method {other}"),
        }
    }
}

/// Serves the stub over real HTTP on an ephemeral port. Handles keep-alive
/// connections and one JSON-RPC request per HTTP request.
async fn start_stub() -> (SocketAddr, std::sync::Arc<StubChain>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let chain = std::sync::Arc::new(StubChain::default());
    let serve_chain = chain.clone();
    tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                return;
            };
            let chain = serve_chain.clone();
            tokio::spawn(async move {
                let mut buffer = Vec::new();
                loop {
                    // Read one HTTP request: headers, then Content-Length body.
                    let header_end = loop {
                        if let Some(position) =
                            buffer.windows(4).position(|window| window == b"\r\n\r\n")
                        {
                            break position + 4;
                        }
                        let mut chunk = [0_u8; 4096];
                        match socket.read(&mut chunk).await {
                            Ok(0) | Err(_) => return,
                            Ok(read) => buffer.extend_from_slice(&chunk[..read]),
                        }
                    };
                    let headers = String::from_utf8_lossy(&buffer[..header_end]).to_string();
                    let content_length: usize = headers
                        .lines()
                        .find_map(|line| {
                            let (name, value) = line.split_once(':')?;
                            name.eq_ignore_ascii_case("content-length")
                                .then(|| value.trim().parse().ok())?
                        })
                        .unwrap_or(0);
                    while buffer.len() < header_end + content_length {
                        let mut chunk = [0_u8; 4096];
                        match socket.read(&mut chunk).await {
                            Ok(0) | Err(_) => return,
                            Ok(read) => buffer.extend_from_slice(&chunk[..read]),
                        }
                    }
                    let body: serde_json::Value =
                        serde_json::from_slice(&buffer[header_end..header_end + content_length])
                            .expect("stub received invalid JSON");
                    buffer.drain(..header_end + content_length);
                    let respond = |request: &serde_json::Value| {
                        let method = request["method"].as_str().expect("method");
                        let params = &request["params"];
                        serde_json::json!({
                            "jsonrpc": "2.0",
                            "id": request["id"],
                            "result": chain.dispatch(method, params),
                        })
                    };
                    let response = if let Some(batch) = body.as_array() {
                        serde_json::json!(batch.iter().map(respond).collect::<Vec<_>>())
                    } else {
                        respond(&body)
                    };
                    let payload = response.to_string();
                    let reply = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{payload}",
                        payload.len()
                    );
                    if socket.write_all(reply.as_bytes()).await.is_err() {
                        return;
                    }
                }
            });
        }
    });
    (address, chain)
}

fn stub_network(address: SocketAddr) -> NetworkConfig {
    NetworkConfig {
        name: "stubnet".into(),
        display_name: Some("Stub Network".into()),
        aliases: Vec::new(),
        chain_id: CHAIN_ID,
        rpc_url: format!("http://{address}/").parse().unwrap(),
        max_gas_limit: Some(BLOCK_GAS_LIMIT.to_string()),
        native_currency: None,
        block_explorer_url: None,
        documentation_url: None,
    }
}

/// A wallet whose key lives in the in-memory store, a config naming only the
/// stub network, and a server wired to both.
fn pipeline_server(
    address: SocketAddr,
    policy: &WalletPolicy,
) -> (tempfile::TempDir, WalletMcpServer, WalletMetadata) {
    let directory = tempfile::tempdir().unwrap();
    let config = ConfigStore::new(directory.path());
    let keys = std::sync::Arc::new(MemoryKeyStore::default());
    let material = PrivateKeyMaterial::from_hex(
        "0x0000000000000000000000000000000000000000000000000000000000000007",
    )
    .unwrap();
    let wallet_address = material.signer().address();
    keys.insert_new("primary", &material).unwrap();
    let wallet = WalletMetadata {
        id: "primary".into(),
        address: wallet_address,
        created_at: Utc::now(),
        source: WalletSource::Created,
        exported_at: None,
    };
    config
        .update(|state| {
            state.wallets.push(wallet.clone());
            state.networks.push(stub_network(address));
            Ok(())
        })
        .unwrap();
    let open = || {
        PolicyStore::open(
            &directory.path().join("policies.db"),
            &DatabaseKey::new([9; 32]),
        )
        .unwrap()
    };
    let mut policies = open();
    policies.put("primary", policy, None).unwrap();
    let server = WalletMcpServer::new(
        config,
        policies,
        PendingStore::new(open()),
        TypedDataStore::new(open()),
        MessageStore::new(open()),
        LegalStore::new(open()),
        TokenStore::new(open()),
        AddressBookStore::new(open()),
        keys,
    )
    .unwrap();
    let legal = server.legal.lock().unwrap();
    legal
        .record_acceptance(
            LegalDocument::TermsOfService,
            &LegalDocument::TermsOfService.digest(),
        )
        .unwrap();
    legal
        .record_acceptance(
            LegalDocument::PrivacyPolicy,
            &LegalDocument::PrivacyPolicy.digest(),
        )
        .unwrap();
    drop(legal);
    (directory, server, wallet)
}

fn plan_reference(sender: Address) -> ekubo_wallet_core::plan_fetch::ArtifactReference {
    ekubo_wallet_core::plan_fetch::ArtifactReference {
        kind: "artifact_reference".into(),
        artifact_type: ekubo_wallet_core::plan_fetch::ArtifactType::ExecutionPlan,
        url: plan_data_uri(sender),
        integrity: None,
        bytes: None,
        instruction: None,
    }
}

fn plan_data_uri(sender: Address) -> String {
    let plan = serde_json::json!({
        "schema_version": "1",
        "chain_id": CHAIN_ID.to_string(),
        "caip2_chain_id": format!("eip155:{CHAIN_ID}"),
        "sender": format!("{sender:#x}"),
        "ordered_steps": [{
            "step": 1,
            "kind": "execution",
            "transaction": {
                "chain_id": CHAIN_ID.to_string(),
                "from": format!("{sender:#x}"),
                "to": "0x2222222222222222222222222222222222222222",
                "data": "0x",
                "value": "0"
            }
        }]
    });
    format!(
        "data:application/json;base64,{}",
        base64::engine::general_purpose::STANDARD.encode(plan.to_string())
    )
}

#[tokio::test(flavor = "multi_thread")]
async fn automatic_path_signs_broadcasts_and_confirms_through_the_stub() {
    let (address, chain) = start_stub().await;
    let (_directory, server, wallet) =
        pipeline_server(address, &WalletPolicy::allow_all_with_approval());

    let output = server
        .wallet_send_execution_plan(Parameters(SendExecutionPlanInput {
            wallet_id: "primary".into(),
            chain_id: CHAIN_ID.to_string(),
            reference: Some(plan_reference(wallet.address)),
            simulation_id: None,
            request_id: None,
            on_simulation_failure: OnSimulationFailure::RequestApproval,
        }))
        .await
        .expect("automatic send succeeds")
        .0;
    assert_eq!(output.status, ExecutionStatus::Submitted, "{output:?}");
    assert_eq!(chain.mined.lock().unwrap().len(), 1);

    // The exact signed bytes and hash were persisted, and the recorded hash
    // is the hash of those exact bytes.
    let record = server
        .pending
        .lock()
        .unwrap()
        .get(output.request_id)
        .unwrap();
    let serialized = record.serialized_transaction.expect("bytes persisted");
    let hash = record.signed_transaction_hash.expect("hash persisted");
    let bytes = hex::decode(serialized.trim_start_matches("0x")).unwrap();
    assert_eq!(format!("{:#x}", keccak256(&bytes)), hash);
    assert!(!record.approval_required, "automatic row needs no approval");
}

#[tokio::test(flavor = "multi_thread")]
async fn an_uncovered_call_queues_and_the_approved_row_broadcasts_by_request_id() {
    let (address, chain) = start_stub().await;
    let (directory, server, wallet) =
        pipeline_server(address, &WalletPolicy::require_approval_for_everything());

    // Agent leg: no rule covers this call, so it queues for a human instead
    // of signing. This is the question-nobody-answered path.
    let output = server
        .wallet_send_execution_plan(Parameters(SendExecutionPlanInput {
            wallet_id: "primary".into(),
            chain_id: CHAIN_ID.to_string(),
            reference: Some(plan_reference(wallet.address)),
            simulation_id: None,
            request_id: None,
            on_simulation_failure: OnSimulationFailure::RequestApproval,
        }))
        .await
        .expect("denied send queues")
        .0;
    assert_eq!(
        output.status,
        ExecutionStatus::ApprovalRequired,
        "{output:?}"
    );
    assert!(chain.mined.lock().unwrap().is_empty(), "nothing signed yet");
    let request_id = output.request_id;

    // Human leg: the real approval path — orchestrator::approve_transaction —
    // driven by a test presenter and test presence instead of a terminal and
    // the OS dialog. Fresh simulation, preparation, review document,
    // presence, the re-read ladder, signing, and the transaction-wrapped
    // store_signed all execute exactly as `ekubo-wallet review` runs them.
    let record = server.pending.lock().unwrap().get(request_id).unwrap();
    let read_policy = || -> anyhow::Result<crate::policy_store::StoredPolicy> {
        server
            .policies
            .lock()
            .unwrap()
            .get("primary")?
            .context("policy exists")
    };
    let outcome = crate::orchestrator::approve_transaction(
        &server.config,
        PendingStore::new(
            PolicyStore::open(
                &directory.path().join("policies.db"),
                &DatabaseKey::new([9; 32]),
            )
            .unwrap(),
        ),
        &TokenStore::new(
            PolicyStore::open(
                &directory.path().join("policies.db"),
                &DatabaseKey::new([9; 32]),
            )
            .unwrap(),
        ),
        &read_policy,
        record,
        crate::approval::InteractiveProof::for_tests(),
        &ApproveEverything,
        &TestHumanPresence { allow: true },
        &*server.keys,
    )
    .await
    .unwrap();
    let crate::orchestrator::ApprovalOutcome::Signed(signed_record) = outcome else {
        panic!("presenter approved, so the outcome must be Signed");
    };
    assert_eq!(signed_record.status, PendingStatus::Signed);
    assert!(signed_record.review_digest.is_some(), "review digest bound");

    // Agent leg again: resubmitting by request id broadcasts the exact stored
    // bytes and settles the record.
    let output = server
        .wallet_send_execution_plan(Parameters(SendExecutionPlanInput {
            wallet_id: "primary".into(),
            chain_id: CHAIN_ID.to_string(),
            reference: None,
            simulation_id: None,
            request_id: Some(request_id),
            on_simulation_failure: OnSimulationFailure::RequestApproval,
        }))
        .await
        .expect("approved resubmission succeeds")
        .0;
    assert_eq!(output.status, ExecutionStatus::Submitted, "{output:?}");
    assert_eq!(chain.mined.lock().unwrap().len(), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn an_explicit_deny_rule_is_refused_outright_and_never_queues() {
    // The other negative path. A `deny` rule is the owner having already
    // answered, so there is nothing to ask them: the send fails, and no
    // pending row exists for anyone to approve later.
    let (address, _chain) = start_stub().await;
    let policy = WalletPolicy::parse(serde_json::json!({
        "version": 1,
        "chains": { "*": {
            "native_value": "any_value",
            "rules": [
                { "effect": "allow", "label": "everything, in principle" },
                { "effect": "deny", "label": "except anything at all, in practice" },
            ],
        }},
    }))
    .expect("policy parses");
    let (directory, server, wallet) = pipeline_server(address, &policy);

    let error = server
        .wallet_send_execution_plan(Parameters(SendExecutionPlanInput {
            wallet_id: "primary".into(),
            chain_id: CHAIN_ID.to_string(),
            reference: Some(plan_reference(wallet.address)),
            simulation_id: None,
            request_id: None,
            on_simulation_failure: OnSimulationFailure::RequestApproval,
        }))
        .await
        .err()
        .expect("a deny rule refuses the send outright");
    let message = format!("{error:?}");
    assert!(
        message.contains("rejects this plan outright"),
        "the error must say it was refused rather than queued: {message}"
    );

    assert_eq!(
        server
            .pending
            .lock()
            .unwrap()
            .awaiting_approval(None)
            .unwrap()
            .len(),
        0,
        "a rejected plan must not leave a request for a human to approve"
    );
    drop(directory);
}

#[tokio::test(flavor = "multi_thread")]
async fn simulate_then_send_consumes_the_recorded_simulation() {
    let (address, _chain) = start_stub().await;
    let (_directory, server, wallet) =
        pipeline_server(address, &WalletPolicy::allow_all_with_approval());

    let simulated = server
        .wallet_simulate_execution_plan(Parameters(SimulateInput {
            wallet_id: "primary".into(),
            chain_id: CHAIN_ID.to_string(),
            reference: plan_reference(wallet.address),
            fork_id: None,
        }))
        .await
        .expect("simulation succeeds")
        .0;
    assert!(simulated.result.allowed, "{:?}", simulated.result);
    let simulation_id = simulated
        .result
        .simulation_id
        .expect("real-state simulation id");

    let output = server
        .wallet_send_execution_plan(Parameters(SendExecutionPlanInput {
            wallet_id: "primary".into(),
            chain_id: CHAIN_ID.to_string(),
            reference: None,
            simulation_id: Some(simulation_id),
            request_id: None,
            on_simulation_failure: OnSimulationFailure::RequestApproval,
        }))
        .await
        .expect("recorded send succeeds")
        .0;
    assert_eq!(output.status, ExecutionStatus::Submitted, "{output:?}");

    // The recorded simulation was consumed by the send.
    let error = server
        .wallet_send_execution_plan(Parameters(SendExecutionPlanInput {
            wallet_id: "primary".into(),
            chain_id: CHAIN_ID.to_string(),
            reference: None,
            simulation_id: Some(simulation_id),
            request_id: None,
            on_simulation_failure: OnSimulationFailure::RequestApproval,
        }))
        .await;
    let Err(error) = error else {
        panic!("a simulation must not authorize two sends");
    };
    assert!(error.message.contains("already sent"), "{}", error.message);
}
