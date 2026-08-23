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
    approval::{ApprovalDecision, ReviewDocument, ReviewPresenter},
    config::{NetworkConfig, WalletMetadata, WalletSource},
    custody::{KeyStore, MemoryKeyStore, PrivateKeyMaterial},
    human_presence::TestHumanPresence,
    policy_store::DatabaseKey,
    simulation::SimulationResult,
};

/// A presenter that keeps the document it was shown before approving, so a
/// test can read the sentence a human would have read.
#[derive(Default)]
struct CaptureThenApprove {
    documents: StdMutex<Vec<ReviewDocument>>,
}

#[async_trait::async_trait]
impl ReviewPresenter for CaptureThenApprove {
    async fn review_transaction(
        &self,
        document: &ReviewDocument,
        _simulation: &SimulationResult,
        _refresh: &dyn ekubo_wallet_core::approval::ReviewRefresh,
    ) -> anyhow::Result<ApprovalDecision> {
        self.documents.lock().unwrap().push(document.clone());
        Ok(ApprovalDecision::Approved)
    }
}

/// A presenter that approves whatever it is shown: the handoff test's stand-in
/// for the terminal review.
struct ApproveEverything;

#[async_trait::async_trait]
impl ReviewPresenter for ApproveEverything {
    async fn review_transaction(
        &self,
        _document: &ReviewDocument,
        _simulation: &SimulationResult,
        _refresh: &dyn ekubo_wallet_core::approval::ReviewRefresh,
    ) -> anyhow::Result<ApprovalDecision> {
        Ok(ApprovalDecision::Approved)
    }
}
/// A presenter that presses `r` once and then approves, standing in for a
/// reviewer who re-simulated before deciding.
///
/// It keeps both documents so the test can compare them: a refresh must be
/// able to change what the chain says about a plan, and must not be able to
/// change the plan.
#[derive(Default)]
struct RefreshThenApprove {
    documents: StdMutex<Vec<ReviewDocument>>,
}

#[async_trait::async_trait]
impl ReviewPresenter for RefreshThenApprove {
    async fn review_transaction(
        &self,
        document: &ReviewDocument,
        _simulation: &SimulationResult,
        refresh: &dyn ekubo_wallet_core::approval::ReviewRefresh,
    ) -> anyhow::Result<ApprovalDecision> {
        self.documents.lock().unwrap().push(document.clone());
        let refreshed = refresh.resimulate().await?;
        self.documents.lock().unwrap().push(refreshed.document);
        Ok(ApprovalDecision::Approved)
    }
}

/// A deliberately permissive presenter: it asks for fresh chain state, sees
/// that refresh fail, and nevertheless returns Approve. The signing kernel has
/// to reject this even when the UI adapter does not.
struct ApproveAfterFailedRefresh {
    chain: std::sync::Arc<StubChain>,
}

#[async_trait::async_trait]
impl ReviewPresenter for ApproveAfterFailedRefresh {
    async fn review_transaction(
        &self,
        _document: &ReviewDocument,
        _simulation: &SimulationResult,
        refresh: &dyn ekubo_wallet_core::approval::ReviewRefresh,
    ) -> anyhow::Result<ApprovalDecision> {
        self.chain.fail_all.store(true, Ordering::SeqCst);
        assert!(
            refresh.resimulate().await.is_err(),
            "the test endpoint was disabled before the refresh"
        );
        Ok(ApprovalDecision::Approved)
    }
}

use alloy::primitives::{Address, B256, keccak256};
use base64::Engine as _;
use std::{
    collections::HashSet,
    net::SocketAddr,
    sync::{
        Mutex as StdMutex,
        atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering},
    },
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};

const CHAIN_ID: u64 = 31_337;
/// Matches `OwnerApi::for_test`, which registers this key for its data
/// directory: both legs of an approval have to reach the same database.
const TEST_DATABASE_KEY: [u8; 32] = [0x43; 32];
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
    /// Make every subsequent RPC call fail, used to prove a failed refresh
    /// cannot fall back to an earlier authored transaction.
    fail_all: AtomicBool,
    /// Whether this node refuses `eth_sendRawTransaction`. A plan can simulate
    /// perfectly and still be an envelope no node will accept -- one that
    /// spends the whole native balance has nothing left to pay for itself.
    refuses_send: bool,
    /// Whether every simulated call comes back reverted. A plan that will not
    /// execute is a different failure from a policy that will not allow it,
    /// and the two have opposite answers.
    reverts_simulation: bool,
    hide_receipts: AtomicBool,
    receipt_succeeded: AtomicBool,
    receipt_block_hash_byte: AtomicU8,
    head_block_number: AtomicU64,
}

/// The lies a stub tells, if it tells any.
#[derive(Default)]
struct StubLie {
    refuses_send: bool,
    reverts_simulation: bool,
}

fn zero_bloom() -> String {
    format!("0x{}", "00".repeat(256))
}

fn block_json_limited(number: u64, parent: B256, gas_limit: u64) -> serde_json::Value {
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
        "gasLimit": format!("{gas_limit:#x}"),
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
            "eth_blockNumber" => serde_json::json!(format!(
                "{:#x}",
                self.head_block_number.load(Ordering::SeqCst)
            )),
            "eth_getBlockByNumber" => {
                block_json_limited(PARENT_NUMBER, B256::repeat_byte(0xa9), BLOCK_GAS_LIMIT)
            }
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
                    let mut block = block_json_limited(number, parent, BLOCK_GAS_LIMIT);
                    parent = serde_json::from_value(block["hash"].clone()).unwrap();
                    let calls = entry["calls"].as_array().map_or(0, Vec::len);
                    let (status, error) = if self.reverts_simulation {
                        (
                            "0x0",
                            serde_json::json!({ "code": 3, "message": "execution reverted" }),
                        )
                    } else {
                        ("0x1", serde_json::Value::Null)
                    };
                    block["calls"] = serde_json::json!(
                        (0..calls)
                            .map(|_| serde_json::json!({
                                "returnData": "0x",
                                "logs": [],
                                "gasUsed": "0x5208",
                                "status": status,
                                "error": error,
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
                if self.mined.lock().unwrap().contains(&hash)
                    && !self.hide_receipts.load(Ordering::SeqCst)
                {
                    serde_json::json!({
                        "transactionHash": hash,
                        "transactionIndex": "0x0",
                        "blockHash": B256::repeat_byte(self.receipt_block_hash_byte.load(Ordering::SeqCst)),
                        "blockNumber": format!("{:#x}", PARENT_NUMBER + 2),
                        "from": Address::ZERO,
                        "to": Address::ZERO,
                        "cumulativeGasUsed": "0x5208",
                        "gasUsed": "0x5208",
                        "contractAddress": null,
                        "logs": [],
                        "logsBloom": zero_bloom(),
                        "status": if self.receipt_succeeded.load(Ordering::SeqCst) { "0x1" } else { "0x0" },
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
    start_stub_lying(StubLie::default()).await
}

async fn start_stub_lying(lie: StubLie) -> (SocketAddr, std::sync::Arc<StubChain>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let chain = std::sync::Arc::new(StubChain {
        refuses_send: lie.refuses_send,
        reverts_simulation: lie.reverts_simulation,
        hide_receipts: AtomicBool::new(false),
        receipt_succeeded: AtomicBool::new(true),
        receipt_block_hash_byte: AtomicU8::new(0xbb),
        head_block_number: AtomicU64::new(PARENT_NUMBER + 2),
        ..StubChain::default()
    });
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
                        if chain.fail_all.load(Ordering::SeqCst) {
                            return serde_json::json!({
                                "jsonrpc": "2.0",
                                "id": request["id"],
                                "error": {
                                    "code": -32000,
                                    "message": "the test endpoint stopped answering",
                                },
                            });
                        }
                        if method == "eth_sendRawTransaction" && chain.refuses_send {
                            return serde_json::json!({
                                "jsonrpc": "2.0",
                                "id": request["id"],
                                "error": {
                                    "code": -32000,
                                    "message": "insufficient funds for gas * price + value",
                                },
                            });
                        }
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
        disabled: false,
        testnet: false,
        display_name: Some("Stub Network".into()),
        aliases: Vec::new(),
        chain_id: CHAIN_ID,
        rpc_urls: vec![format!("http://{address}/").parse().unwrap()],
        rpc_strategy: ekubo_wallet_core::config::RpcStrategy::Ordered,
        finality_confirmations: 2,
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
    let wallet_address = material.address();
    let instance_id = uuid::Uuid::new_v4();
    keys.insert_new(instance_id, &material).unwrap();
    let wallet = WalletMetadata {
        instance_id,
        id: "primary".into(),
        address: wallet_address,
        created_at: Utc::now(),
        source: WalletSource::Created,
        exported_at: None,
    };
    config
        .update_for_test(|state| {
            state.wallets.push(wallet.clone());
            state.networks.push(stub_network(address));
            Ok(())
        })
        .unwrap();
    // The same file and key `OwnerApi::for_test` opens, so a test can drive
    // the agent leg and the owner leg against one database.
    let open = || test_store(directory.path());
    let mut policies = open();
    policies.put_for_instance(&wallet, policy, None).unwrap();
    let policies = Arc::new(Mutex::new(policies));
    let execution_authority = AgentExecutionAuthority::over(keys, Arc::clone(&policies));
    let server = WalletMcpServer::new(
        config,
        policies,
        PendingStore::new(open()),
        TypedDataStore::new(open()),
        MessageStore::new(open()),
        LegalStore::new(open()),
        TokenStore::new(open()),
        AutomationStore::new(open()),
        execution_authority,
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

/// The wallet's own encrypted database, opened the way a test build opens it.
fn test_store(directory: &std::path::Path) -> PolicyStore {
    ekubo_wallet_core::policy_store::register_test_database_key(directory, TEST_DATABASE_KEY)
        .unwrap();
    PolicyStore::open(
        &directory.join(ekubo_wallet_core::policy_store::DATABASE_FILE),
        &DatabaseKey::new(TEST_DATABASE_KEY),
    )
    .unwrap()
}

fn legal_store(directory: &std::path::Path) -> LegalStore {
    LegalStore::new(test_store(directory))
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
    let (_directory, server, wallet) = pipeline_server(address, &WalletPolicy::allow_anything());

    let output = server
        .wallet_send_execution_plan(Parameters(SendExecutionPlanInput {
            wallet_id: "primary".into(),
            chain_id: CHAIN_ID.to_string(),
            reference: Some(plan_reference(wallet.address)),
            simulation_id: None,
            request_id: None,
            on_simulation_failure: OnSimulationFailure::RequestApproval,
            must_review: false,
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
async fn a_reorged_receipt_rolls_back_and_keeps_the_automatic_signing_slot() {
    let (address, chain) = start_stub().await;
    let (_directory, server, wallet) = pipeline_server(address, &WalletPolicy::allow_anything());
    let send = || SendExecutionPlanInput {
        wallet_id: "primary".into(),
        chain_id: CHAIN_ID.to_string(),
        reference: Some(plan_reference(wallet.address)),
        simulation_id: None,
        request_id: None,
        on_simulation_failure: OnSimulationFailure::RequestApproval,
        must_review: false,
    };
    let first = server
        .wallet_send_execution_plan(Parameters(send()))
        .await
        .unwrap()
        .0;
    let request = RequestInput {
        wallet_id: "primary".into(),
        chain_id: CHAIN_ID.to_string(),
        request_id: first.request_id,
    };
    let shallow = server
        .pending
        .lock()
        .unwrap()
        .get(first.request_id)
        .unwrap();
    assert_eq!(shallow.status, PendingStatus::Confirmed);
    assert!(shallow.finalized_at.is_none());
    assert!(
        server
            .pending
            .lock()
            .unwrap()
            .in_flight("primary", &CHAIN_ID.to_string())
            .unwrap()
            .is_some()
    );

    let blocked = server.wallet_send_execution_plan(Parameters(send())).await;
    assert!(blocked.is_err_and(|error| {
        error
            .message
            .contains("still holds this wallet and chain's signing slot")
    }));
    assert_eq!(chain.mined.lock().unwrap().len(), 1);

    // A different canonical block identity replaces the provisional one.
    chain.receipt_block_hash_byte.store(0xcc, Ordering::SeqCst);
    let moved = server.reconcile_pending(&request).await.unwrap();
    assert_eq!(moved.status, ExecutionStatus::Submitted);
    assert_eq!(
        moved.block_hash.as_deref(),
        Some(format!("{:#x}", B256::repeat_byte(0xcc)).as_str())
    );
    assert_eq!(moved.finalized, Some(false));

    // The receipt then disappears entirely: reconciliation restores the
    // broadcast lifecycle instead of preserving a false success.
    chain.hide_receipts.store(true, Ordering::SeqCst);
    let rolled_back = server.reconcile_pending(&request).await.unwrap();
    assert_eq!(rolled_back.status, ExecutionStatus::SubmissionPending);
    assert!(rolled_back.block_hash.is_none());

    // Once the replacement block is deep enough, the same receipt becomes
    // final and the signing slot is released.
    chain.hide_receipts.store(false, Ordering::SeqCst);
    chain
        .head_block_number
        .store(PARENT_NUMBER + 13, Ordering::SeqCst);
    let finalized = server.reconcile_pending(&request).await.unwrap();
    assert_eq!(finalized.status, ExecutionStatus::Submitted);
    assert_eq!(finalized.finalized, Some(true));
    assert!(
        server
            .pending
            .lock()
            .unwrap()
            .in_flight("primary", &CHAIN_ID.to_string())
            .unwrap()
            .is_none()
    );
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
            must_review: false,
        }))
        .await
        .expect("denied send queues")
        .0;
    assert_eq!(
        output.status,
        ExecutionStatus::ApprovalRequired,
        "{output:?}"
    );
    let instruction = output
        .instruction
        .as_deref()
        .expect("next step is explicit");
    assert!(instruction.contains("Approval itself attempts to submit"));
    assert!(!instruction.contains("On approved, submit with"));
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
        PendingStore::new(test_store(directory.path())),
        TokenStore::new(test_store(directory.path())),
        &legal_store(directory.path()),
        &read_policy,
        record,
        &ApproveEverything,
        &TestHumanPresence { allow: true },
        server.execution_authority.key_store_for_test(),
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
            must_review: false,
        }))
        .await
        .expect("approved resubmission succeeds")
        .0;
    assert_eq!(output.status, ExecutionStatus::Submitted, "{output:?}");
    assert_eq!(chain.mined.lock().unwrap().len(), 1);
}

/// The facts are what a reviewer reads first, and the sender is the one on
/// every transaction. It is always an account this wallet holds, so it is
/// always nameable -- and the name has to survive the whole authoring path,
/// not just the formatter that produces it.
#[tokio::test(flavor = "multi_thread")]
async fn the_document_a_reviewer_reads_names_the_account_it_sends_from() {
    let (address, chain) = start_stub().await;
    let _ = &chain;
    let (directory, server, wallet) =
        pipeline_server(address, &WalletPolicy::require_approval_for_everything());

    let output = server
        .wallet_send_execution_plan(Parameters(SendExecutionPlanInput {
            wallet_id: "primary".into(),
            chain_id: CHAIN_ID.to_string(),
            reference: Some(plan_reference(wallet.address)),
            simulation_id: None,
            request_id: None,
            on_simulation_failure: OnSimulationFailure::RequestApproval,
            must_review: false,
        }))
        .await
        .expect("an uncovered call queues")
        .0;
    let record = server
        .pending
        .lock()
        .unwrap()
        .get(output.request_id)
        .unwrap();
    let read_policy = || -> anyhow::Result<crate::policy_store::StoredPolicy> {
        server
            .policies
            .lock()
            .unwrap()
            .get("primary")?
            .context("policy exists")
    };
    let presenter = CaptureThenApprove::default();
    crate::orchestrator::approve_transaction(
        &server.config,
        PendingStore::new(test_store(directory.path())),
        TokenStore::new(test_store(directory.path())),
        &legal_store(directory.path()),
        &read_policy,
        record,
        &presenter,
        &TestHumanPresence { allow: true },
        server.execution_authority.key_store_for_test(),
    )
    .await
    .unwrap();

    let document = presenter
        .documents
        .lock()
        .unwrap()
        .first()
        .cloned()
        .expect("the presenter was shown a document");
    let sender = document
        .request
        .facts
        .iter()
        .chain(
            document
                .request
                .sections
                .iter()
                .flat_map(|section| &section.facts),
        )
        .find(|fact| fact.label == "Sender")
        .expect("every transaction document names its sender");
    let exact = format!("{:#x}", wallet.address);
    assert!(
        sender.value.contains(&exact),
        "the exact sending address must be on the document: {sender:?}"
    );
    assert!(
        sender.value.contains("your account primary"),
        "and be named as the owner's own: {sender:?}"
    );
}

/// Queue a plan the policy will not sign automatically, then approve it the
/// way the review window does, and return the signed row.
async fn queue_and_approve(
    directory: &tempfile::TempDir,
    server: &WalletMcpServer,
    wallet: &WalletMetadata,
) -> PendingTransaction {
    let output = server
        .wallet_send_execution_plan(Parameters(SendExecutionPlanInput {
            wallet_id: "primary".into(),
            chain_id: CHAIN_ID.to_string(),
            reference: Some(plan_reference(wallet.address)),
            simulation_id: None,
            request_id: None,
            on_simulation_failure: OnSimulationFailure::RequestApproval,
            must_review: false,
        }))
        .await
        .expect("an uncovered call queues")
        .0;
    assert_eq!(
        output.status,
        ExecutionStatus::ApprovalRequired,
        "{output:?}"
    );
    let record = server
        .pending
        .lock()
        .unwrap()
        .get(output.request_id)
        .unwrap();
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
        PendingStore::new(test_store(directory.path())),
        TokenStore::new(test_store(directory.path())),
        &legal_store(directory.path()),
        &read_policy,
        record,
        &ApproveEverything,
        &TestHumanPresence { allow: true },
        server.execution_authority.key_store_for_test(),
    )
    .await
    .unwrap();
    let crate::orchestrator::ApprovalOutcome::Signed(signed) = outcome else {
        panic!("presenter approved, so the outcome must be Signed");
    };
    assert_eq!(signed.status, PendingStatus::Signed);
    signed
}

#[tokio::test(flavor = "multi_thread")]
async fn approving_sends_the_signed_bytes_without_waiting_to_be_asked_again() {
    // The gap this closes: signing used to be the end of the owner's leg, and
    // the transaction waited for whatever queued it to come back and submit.
    // An agent whose approval wait timed out never does, so an approved
    // transaction sat unsent until the owner noticed and pressed "Send now".
    let (address, chain) = start_stub().await;
    let (directory, server, wallet) =
        pipeline_server(address, &WalletPolicy::require_approval_for_everything());
    let signed = Box::pin(queue_and_approve(&directory, &server, &wallet)).await;
    assert!(chain.mined.lock().unwrap().is_empty(), "nothing sent yet");

    let owner = crate::authority::OwnerApi::for_test(directory.path()).unwrap();
    let reviewed = owner.send_approved_transaction(signed).await.unwrap();

    assert!(reviewed.send_error.is_none(), "{:?}", reviewed.send_error);
    assert!(
        matches!(
            reviewed.record.status,
            PendingStatus::Broadcast | PendingStatus::Confirmed
        ),
        "approval put the exact bytes on the wire: {:?}",
        reviewed.record.status
    );
    assert_eq!(chain.mined.lock().unwrap().len(), 1);
    // And the agent that queued it, coming back later, is told the state
    // rather than sending anything a second time.
    let status = server
        .wallet_send_execution_plan(Parameters(SendExecutionPlanInput {
            wallet_id: "primary".into(),
            chain_id: CHAIN_ID.to_string(),
            reference: None,
            simulation_id: None,
            request_id: Some(reviewed.record.request_id),
            on_simulation_failure: OnSimulationFailure::RequestApproval,
            must_review: false,
        }))
        .await
        .expect("a sent request reports its state")
        .0;
    assert_eq!(status.status, ExecutionStatus::Submitted, "{status:?}");
    assert_eq!(chain.mined.lock().unwrap().len(), 1, "sent exactly once");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_submission_somebody_else_claimed_is_reported_rather_than_repeated() {
    // The desktop, the MCP server, and a WalletConnect session reach the same
    // database without sharing a lock, so the submission lease is what decides
    // between them. Losing it means the bytes are already going out, which is
    // the intended outcome and not a failure to show the reviewer.
    let (address, chain) = start_stub().await;
    let (directory, server, wallet) =
        pipeline_server(address, &WalletPolicy::require_approval_for_everything());
    let signed = Box::pin(queue_and_approve(&directory, &server, &wallet)).await;
    let claimed = server
        .pending
        .lock()
        .unwrap()
        .claim_for_submission(signed.request_id)
        .expect("another sender takes the lease first");
    assert_eq!(claimed.status, PendingStatus::Submitting);

    let owner = crate::authority::OwnerApi::for_test(directory.path()).unwrap();
    let reviewed = owner.send_approved_transaction(signed).await.unwrap();

    assert!(
        reviewed.send_error.is_none(),
        "losing the lease is not news"
    );
    assert_eq!(reviewed.record.status, PendingStatus::Submitting);
    assert!(
        chain.mined.lock().unwrap().is_empty(),
        "the lease holder sends, and nothing sends twice"
    );
    // The agent asking about it now gets the in-flight state, not an error.
    let status = server
        .wallet_send_execution_plan(Parameters(SendExecutionPlanInput {
            wallet_id: "primary".into(),
            chain_id: CHAIN_ID.to_string(),
            reference: None,
            simulation_id: None,
            request_id: Some(reviewed.record.request_id),
            on_simulation_failure: OnSimulationFailure::RequestApproval,
            must_review: false,
        }))
        .await
        .expect("a claimed request reports its state")
        .0;
    assert_eq!(
        status.status,
        ExecutionStatus::SubmissionPending,
        "{status:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn an_explicit_deny_rule_is_refused_outright_and_never_queues() {
    // The other negative path. A `deny` rule is the owner having already
    // answered, so there is nothing to ask them: the send fails, and no
    // pending row exists for anyone to approve later.
    let (address, _chain) = start_stub().await;
    let policy = WalletPolicy::parse(serde_json::json!({
        "version": 1,
        "rules": [
            { "effect": "deny", "label": "deny every transaction" }
        ]
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
            must_review: false,
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
async fn must_review_queues_a_plan_the_policy_would_have_signed() {
    // The same plan and the same allow-anything policy that
    // `automatic_path_signs_broadcasts_and_confirms_through_the_stub` sends
    // without asking anyone. The only difference is the caller's ask, and it
    // is enough: nothing signs, nothing broadcasts, and a row waits.
    let (address, chain) = start_stub().await;
    let (_directory, server, wallet) = pipeline_server(address, &WalletPolicy::allow_anything());

    let output = server
        .wallet_send_execution_plan(Parameters(SendExecutionPlanInput {
            wallet_id: "primary".into(),
            chain_id: CHAIN_ID.to_string(),
            reference: Some(plan_reference(wallet.address)),
            simulation_id: None,
            request_id: None,
            on_simulation_failure: OnSimulationFailure::RequestApproval,
            must_review: true,
        }))
        .await
        .expect("the send queues rather than failing")
        .0;
    assert_eq!(
        output.status,
        ExecutionStatus::ApprovalRequired,
        "{output:?}"
    );
    assert_eq!(
        chain.mined.lock().unwrap().len(),
        0,
        "a transaction awaiting review must not have been broadcast"
    );

    let record = server
        .pending
        .lock()
        .unwrap()
        .get(output.request_id)
        .unwrap();
    assert!(record.approval_required);
    assert!(
        record.serialized_transaction.is_none(),
        "nothing was signed"
    );
    // Persisted, because the review is authored fresh when the owner opens it
    // and by then the policy says this plan is perfectly allowed. Without the
    // row remembering, the reviewer would be shown a prompt with no reason.
    assert!(
        record.requested_review,
        "the row must remember that the review was asked for"
    );

    // And the caller is told why, in the same vocabulary as every other
    // reason a send does not sign itself.
    let simulation = output.simulation.expect("the send reports its simulation");
    assert_eq!(
        simulation.policy_outcome,
        ekubo_wallet_core::core::policy::PolicyOutcome::RequiresApproval
    );
    assert!(!simulation.allowed);
    assert!(
        simulation
            .policy_findings
            .iter()
            .any(|finding| finding.code
                == ekubo_wallet_core::core::policy::CALLER_REQUESTED_REVIEW_CODE),
        "{:?}",
        simulation.policy_findings
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_requested_review_tells_the_reviewer_why_they_are_being_asked() {
    // The document is authored fresh when the owner opens it, from a policy
    // that by then allows this plan outright. The usual sentence -- "outside
    // the wallet's automatic policy" -- would be false here, and a reviewer
    // acting on it would go looking for a rule that does not exist. Then the
    // ordinary approval path signs it, because asking for a second look is a
    // question, not a refusal.
    let (address, _chain) = start_stub().await;
    let (directory, server, wallet) = pipeline_server(address, &WalletPolicy::allow_anything());

    let output = server
        .wallet_send_execution_plan(Parameters(SendExecutionPlanInput {
            wallet_id: "primary".into(),
            chain_id: CHAIN_ID.to_string(),
            reference: Some(plan_reference(wallet.address)),
            simulation_id: None,
            request_id: None,
            on_simulation_failure: OnSimulationFailure::RequestApproval,
            must_review: true,
        }))
        .await
        .expect("the send queues")
        .0;
    let record = server
        .pending
        .lock()
        .unwrap()
        .get(output.request_id)
        .unwrap();

    let read_policy = || -> anyhow::Result<crate::policy_store::StoredPolicy> {
        server
            .policies
            .lock()
            .unwrap()
            .get("primary")?
            .context("policy exists")
    };
    let presenter = CaptureThenApprove::default();
    let outcome = Box::pin(crate::orchestrator::approve_transaction(
        &server.config,
        PendingStore::new(test_store(directory.path())),
        TokenStore::new(test_store(directory.path())),
        &legal_store(directory.path()),
        &read_policy,
        record,
        &presenter,
        &TestHumanPresence { allow: true },
        server.execution_authority.key_store_for_test(),
    ))
    .await
    .unwrap();

    let documents = presenter.documents.lock().unwrap();
    let summary = &documents
        .first()
        .expect("the reviewer was shown one")
        .request
        .summary;
    assert!(
        summary.contains("asked for you to review it"),
        "the reviewer must be told the real reason: {summary}"
    );
    assert!(
        !summary.contains("outside the wallet's automatic policy"),
        "the policy allows this plan, so saying otherwise is false: {summary}"
    );

    let crate::orchestrator::ApprovalOutcome::Signed(signed) = outcome else {
        panic!("presenter approved, so the outcome must be Signed");
    };
    assert_eq!(signed.status, PendingStatus::Signed);
}

#[tokio::test(flavor = "multi_thread")]
async fn must_review_cannot_rescue_a_plan_a_deny_rule_refused() {
    // Asking for review adds a human to a decision the owner has not made.
    // A `deny` rule is the owner having made it, and no caller-set flag turns
    // that back into a question — least of all one that would put the plan in
    // front of them with an Approve button on it.
    let (address, _chain) = start_stub().await;
    let policy = WalletPolicy::parse(serde_json::json!({
        "version": 1,
        "rules": [
            { "effect": "deny", "label": "deny every transaction" }
        ]
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
            must_review: true,
        }))
        .await
        .err()
        .expect("a deny rule refuses the send outright");
    let message = format!("{error:?}");
    assert!(
        message.contains("rejects this plan outright"),
        "asking for review must not turn a denial into a prompt: {message}"
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
        "a denied plan must not leave a request for a human to approve"
    );
    drop(directory);
}

#[tokio::test(flavor = "multi_thread")]
async fn must_review_and_a_failed_simulation_still_honors_fail() {
    // Two different asks that both end in "do not sign". `on_simulation_failure`
    // says not to spend the user's attention on a plan that cannot execute,
    // and asking for review does not contradict it: a review whose only
    // possible outcome is a reverting transaction is not the second look
    // anybody wanted. Nothing queues, so nothing has to be rejected later.
    let (address, _chain) = start_stub_lying(StubLie {
        reverts_simulation: true,
        ..StubLie::default()
    })
    .await;
    let (_directory, server, wallet) = pipeline_server(address, &WalletPolicy::allow_anything());

    let error = server
        .wallet_send_execution_plan(Parameters(SendExecutionPlanInput {
            wallet_id: "primary".into(),
            chain_id: CHAIN_ID.to_string(),
            reference: Some(plan_reference(wallet.address)),
            simulation_id: None,
            request_id: None,
            on_simulation_failure: OnSimulationFailure::Fail,
            must_review: true,
        }))
        .await
        .err()
        .expect("a failed simulation with \"fail\" is reported, not queued");
    assert!(
        format!("{error:?}").contains("nothing was queued or signed"),
        "{error:?}"
    );
    assert_eq!(
        server
            .pending
            .lock()
            .unwrap()
            .awaiting_approval(None)
            .unwrap()
            .len(),
        0
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn must_review_is_refused_on_a_request_that_is_already_signed() {
    // A `request_id` submits bytes a human already approved. There is no
    // decision left for a review to change, and quietly accepting the flag
    // would let an agent believe it had asked for one.
    let (address, _chain) = start_stub().await;
    let (_directory, server, _wallet) = pipeline_server(address, &WalletPolicy::allow_anything());

    let error = server
        .wallet_send_execution_plan(Parameters(SendExecutionPlanInput {
            wallet_id: "primary".into(),
            chain_id: CHAIN_ID.to_string(),
            reference: None,
            simulation_id: None,
            request_id: Some(uuid::Uuid::from_u128(9)),
            on_simulation_failure: OnSimulationFailure::RequestApproval,
            must_review: true,
        }))
        .await
        .err()
        .expect("must_review with request_id is refused");
    assert!(
        format!("{error:?}").contains("already reviewed and"),
        "{error:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn simulate_then_send_consumes_the_recorded_simulation() {
    let (address, _chain) = start_stub().await;
    let (_directory, server, wallet) = pipeline_server(address, &WalletPolicy::allow_anything());

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
            must_review: false,
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
            must_review: false,
        }))
        .await;
    let Err(error) = error else {
        panic!("a simulation must not authorize two sends");
    };
    assert!(error.message.contains("already sent"), "{}", error.message);
}

/// The reviewer re-simulates before deciding, and the approval still
/// completes end to end.
///
/// A queued transaction is often queued because its simulation failed for a
/// reason that has since passed — every endpoint was refusing requests, or a
/// prerequisite has now mined — so the review offers `r`. This drives that
/// path through the real orchestrator: the refresh re-runs simulation and
/// preparation, and the signature is built from what the refresh produced
/// rather than from the document the reviewer first saw.
///
/// That last property is structural rather than asserted here: the
/// orchestrator holds exactly one authored review, replaces it on every
/// refresh, and takes it after the presenter returns, so there is no earlier
/// simulation left in scope for signing to reach.
#[tokio::test(flavor = "multi_thread")]
async fn a_reviewer_can_re_simulate_before_approving() {
    let (address, chain) = start_stub().await;
    let (directory, server, wallet) =
        pipeline_server(address, &WalletPolicy::require_approval_for_everything());

    let output = server
        .wallet_send_execution_plan(Parameters(SendExecutionPlanInput {
            wallet_id: "primary".into(),
            chain_id: CHAIN_ID.to_string(),
            reference: Some(plan_reference(wallet.address)),
            simulation_id: None,
            request_id: None,
            on_simulation_failure: OnSimulationFailure::RequestApproval,
            must_review: false,
        }))
        .await
        .expect("send queues for approval")
        .0;
    assert_eq!(output.status, ExecutionStatus::ApprovalRequired);
    let request_id = output.request_id;

    let record = server.pending.lock().unwrap().get(request_id).unwrap();
    let read_policy = || -> anyhow::Result<crate::policy_store::StoredPolicy> {
        server
            .policies
            .lock()
            .unwrap()
            .get("primary")?
            .context("policy exists")
    };
    let presenter = RefreshThenApprove::default();
    let outcome = crate::orchestrator::approve_transaction(
        &server.config,
        PendingStore::new(test_store(directory.path())),
        TokenStore::new(test_store(directory.path())),
        &legal_store(directory.path()),
        &read_policy,
        record,
        &presenter,
        &TestHumanPresence { allow: true },
        server.execution_authority.key_store_for_test(),
    )
    .await
    .unwrap();

    let crate::orchestrator::ApprovalOutcome::Signed(signed_record) = outcome else {
        panic!("the presenter approved, so the outcome must be Signed");
    };
    assert_eq!(signed_record.status, PendingStatus::Signed);
    assert!(
        signed_record.review_digest.is_some(),
        "the signature is bound to a reviewed document"
    );

    let documents = presenter.documents.lock().unwrap().clone();
    assert_eq!(
        documents.len(),
        2,
        "one original and one refreshed document"
    );
    // Against an unchanged chain the refresh must produce the same review:
    // a refresh re-reads the chain, it does not re-decide what is being
    // approved. The plan digest above all must survive it.
    assert_eq!(
        documents[0].request.digest, documents[1].request.digest,
        "a refresh changed the digest under review"
    );
    assert_eq!(
        documents[0].request.facts, documents[1].request.facts,
        "a refresh changed the facts under review"
    );

    let output = server
        .wallet_send_execution_plan(Parameters(SendExecutionPlanInput {
            wallet_id: "primary".into(),
            chain_id: CHAIN_ID.to_string(),
            reference: None,
            simulation_id: None,
            request_id: Some(request_id),
            on_simulation_failure: OnSimulationFailure::RequestApproval,
            must_review: false,
        }))
        .await
        .expect("approved resubmission succeeds")
        .0;
    assert_eq!(output.status, ExecutionStatus::Submitted, "{output:?}");
    assert_eq!(chain.mined.lock().unwrap().len(), 1);
}

/// Finding 200861: a refresh error used to leave the prior `Authored` pair in
/// the review slot. A presenter could then approve and the orchestrator signed
/// the stale nonce, fees, and envelope the reviewer had explicitly asked to
/// replace. Failure now withdraws the prior pair before any RPC is awaited.
#[tokio::test(flavor = "multi_thread")]
async fn a_failed_refresh_cannot_approve_the_previous_transaction() {
    let (address, chain) = start_stub().await;
    let (directory, server, wallet) =
        pipeline_server(address, &WalletPolicy::require_approval_for_everything());

    let output = server
        .wallet_send_execution_plan(Parameters(SendExecutionPlanInput {
            wallet_id: "primary".into(),
            chain_id: CHAIN_ID.to_string(),
            reference: Some(plan_reference(wallet.address)),
            simulation_id: None,
            request_id: None,
            on_simulation_failure: OnSimulationFailure::RequestApproval,
            must_review: false,
        }))
        .await
        .expect("send queues for approval")
        .0;
    let request_id = output.request_id;
    let record = server.pending.lock().unwrap().get(request_id).unwrap();
    let read_policy = || -> anyhow::Result<crate::policy_store::StoredPolicy> {
        server
            .policies
            .lock()
            .unwrap()
            .get("primary")?
            .context("policy exists")
    };
    let presenter = ApproveAfterFailedRefresh {
        chain: chain.clone(),
    };
    let outcome = crate::orchestrator::approve_transaction(
        &server.config,
        PendingStore::new(test_store(directory.path())),
        TokenStore::new(test_store(directory.path())),
        &legal_store(directory.path()),
        &read_policy,
        record,
        &presenter,
        &TestHumanPresence { allow: true },
        server.execution_authority.key_store_for_test(),
    )
    .await;
    let Err(error) = outcome else {
        panic!("approval must not fall back to the pre-refresh transaction");
    };
    assert!(
        format!("{error:#}").contains("no current authored document"),
        "{error:#}"
    );
    assert!(
        chain.mined.lock().unwrap().is_empty(),
        "no envelope may be broadcast after the failed refresh"
    );
}

/// A plan that simulates and is then refused by every endpoint must not leave
/// the wallet frozen on that chain.
///
/// The row used to be recorded `broadcast` before anyone looked at
/// `broadcast_error`. `broadcast` cannot be discarded locally, holds the one
/// in-flight slot the partial unique index allows per wallet and chain, and --
/// since the nonce was never consumed -- reconciles as pending forever. A dapp
/// that could get one policy-allowed plan signed, and chose one that cannot pay
/// for itself, froze the account until someone intervened by hand.
#[tokio::test(flavor = "multi_thread")]
async fn a_send_no_endpoint_accepted_leaves_the_chain_usable() {
    let (address, chain) = start_stub_lying(StubLie {
        refuses_send: true,
        ..StubLie::default()
    })
    .await;
    let (_directory, server, wallet) = pipeline_server(address, &WalletPolicy::allow_anything());

    let output = server
        .wallet_send_execution_plan(Parameters(SendExecutionPlanInput {
            wallet_id: "primary".into(),
            chain_id: CHAIN_ID.to_string(),
            reference: Some(plan_reference(wallet.address)),
            simulation_id: None,
            request_id: None,
            on_simulation_failure: OnSimulationFailure::RequestApproval,
            must_review: false,
        }))
        .await
        .expect("a refused send is a reportable outcome, not a crash")
        .0;
    assert!(chain.mined.lock().unwrap().is_empty());

    // Approved, not SubmissionPending: the row is signed and never submitted,
    // which is what happened. The node's own reason travels with it.
    assert_eq!(output.status, ExecutionStatus::Approved, "{output:?}");
    assert!(
        output
            .broadcast_error
            .as_deref()
            .is_some_and(|error| error.contains("insufficient funds")),
        "{output:?}"
    );

    // And because it is signed rather than broadcast, it can be discarded --
    // which is what frees the wallet's one in-flight slot for this chain
    // without a nonce-consuming transaction on chain.
    let record = {
        let mut pending = server.pending.lock().unwrap();
        pending.discard_unsent(output.request_id).unwrap()
    };
    assert_eq!(record.status, PendingStatus::Cancelled, "{record:?}");
    let _ = wallet;
}
