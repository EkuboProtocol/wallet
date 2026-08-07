//! Tests for [`super`].
//!
//! Out of line so the audit corpus is production code: V12 bills measured
//! bytes and excludes `*_test.rs` by default. A `#[path]` child module has
//! exactly the privacy access an inline one does, so nothing these can reach
//! changes, and the test paths are the ones they always were.

use super::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn plan_json() -> String {
    serde_json::json!({
        "schema_version": "1",
        "chain_id": "1",
        "caip2_chain_id": "eip155:1",
        "sender": "0x1111111111111111111111111111111111111111",
        "ordered_steps": [{
            "step": 1,
            "kind": "execution",
            "transaction": {
                "chain_id": "1",
                "from": "0x1111111111111111111111111111111111111111",
                "to": "0x2222222222222222222222222222222222222222",
                "data": "0xd0e30db0",
                "value": "0",
            },
        }],
    })
    .to_string()
}

fn digest_of(body: &str) -> String {
    format!("0x{:x}", keccak256(body.as_bytes()))
}

fn reference_for(
    artifact_type: ArtifactType,
    url: impl Into<String>,
    body: Option<&str>,
) -> ArtifactReference {
    ArtifactReference {
        kind: "artifact_reference".into(),
        artifact_type,
        url: url.into(),
        integrity: body.map(|body| ArtifactIntegrity {
            algorithm: "keccak256".into(),
            value: digest_of(body),
        }),
        bytes: body.map(|body| body.len() as u64),
        instruction: None,
    }
}

fn data_uri_of(body: &str) -> String {
    format!(
        "data:application/json;base64,{}",
        base64::engine::general_purpose::STANDARD.encode(body)
    )
}

async fn resolve(
    reference: &ArtifactReference,
    policy: FetchPolicy,
) -> Result<(ExecutionPlan, ArtifactSource)> {
    resolve_execution_plan_reference(reference, policy).await
}

async fn serve_once(status_line: &'static str, body: String) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut request = [0_u8; 4096];
        let _ = stream.read(&mut request).await;
        let response = format!(
            "{status_line}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
            body.len(),
        );
        stream.write_all(response.as_bytes()).await.unwrap();
    });
    format!("http://{address}/plan/test")
}

#[tokio::test]
async fn resolves_a_base64_data_uri() {
    let body = plan_json();
    let reference = reference_for(ArtifactType::ExecutionPlan, data_uri_of(&body), Some(&body));
    let (plan, source) = resolve(&reference, FetchPolicy::production())
        .await
        .unwrap();
    assert_eq!(plan.chain_id.as_str(), "1");
    assert_eq!(source, ArtifactSource::InlineDataUri);
    assert_eq!(source.to_string(), "inline data URI");
}

#[tokio::test]
async fn a_data_uri_needs_no_integrity_block() {
    // The bytes are the reference: requiring an agent to compute
    // keccak256 over an inline plan would add friction with no security
    // gain. Integrity is still verified whenever it is supplied.
    let body = plan_json();
    let reference = reference_for(ArtifactType::ExecutionPlan, data_uri_of(&body), None);
    let (plan, _) = resolve(&reference, FetchPolicy::production())
        .await
        .unwrap();
    assert_eq!(plan.ordered_steps.len(), 1);
}

#[tokio::test]
async fn refuses_an_unsupported_integrity_algorithm() {
    let body = plan_json();
    let mut reference = reference_for(ArtifactType::ExecutionPlan, data_uri_of(&body), Some(&body));
    reference.integrity = Some(ArtifactIntegrity {
        algorithm: "sha256".into(),
        value: digest_of(&body),
    });
    let error = resolve(&reference, FetchPolicy::production())
        .await
        .unwrap_err();
    let message = error.to_string();
    assert!(message.contains("sha256"), "{message}");
    assert!(message.contains("keccak256"), "{message}");
}

#[tokio::test]
async fn refuses_a_byte_count_mismatch() {
    let body = plan_json();
    let mut reference = reference_for(ArtifactType::ExecutionPlan, data_uri_of(&body), Some(&body));
    reference.bytes = Some(body.len() as u64 + 1);
    let error = resolve(&reference, FetchPolicy::production())
        .await
        .unwrap_err();
    assert!(error.to_string().contains("altered or truncated"));
}

#[tokio::test]
async fn refuses_a_wrong_artifact_type_or_kind() {
    let body = plan_json();
    let reference = reference_for(ArtifactType::ReadCalls, data_uri_of(&body), Some(&body));
    let error = resolve(&reference, FetchPolicy::production())
        .await
        .unwrap_err();
    let message = error.to_string();
    assert!(message.contains("execution_plan"), "{message}");
    assert!(message.contains("read_calls"), "{message}");

    let mut reference = reference_for(ArtifactType::ExecutionPlan, data_uri_of(&body), Some(&body));
    reference.kind = "ekubo_execution_plan_reference".into();
    let error = resolve(&reference, FetchPolicy::production())
        .await
        .unwrap_err();
    assert!(error.to_string().contains("artifact_reference"));
}

#[tokio::test]
async fn tolerates_a_producer_summary_field() {
    // Producers that still emit the retired `summary` object stay accepted:
    // the envelope tolerates additive fields, and summary was never load-
    // bearing — the fetched body is the only source of truth.
    let body = plan_json();
    let envelope = serde_json::json!({
        "kind": "artifact_reference",
        "artifact_type": "execution_plan",
        "url": data_uri_of(&body),
        "summary": { "chain_id": "8453", "sender": "0x0", "step_count": 7 },
    });
    let reference: ArtifactReference = serde_json::from_value(envelope).unwrap();
    let (plan, _) = resolve(&reference, FetchPolicy::production())
        .await
        .unwrap();
    assert_eq!(plan.chain_id.as_str(), "1");
}

#[tokio::test]
async fn a_remote_reference_requires_integrity_and_byte_count() {
    let reference = reference_for(
        ArtifactType::ExecutionPlan,
        "https://mcp.ekubo.org/artifact/x",
        None,
    );
    let error = resolve(&reference, FetchPolicy::production())
        .await
        .unwrap_err();
    assert!(error.to_string().contains("integrity block"));
}

#[tokio::test]
async fn resolves_a_percent_encoded_data_uri() {
    let body = plan_json();
    let encoded: String =
        percent_encoding::utf8_percent_encode(&body, percent_encoding::NON_ALPHANUMERIC)
            .to_string();
    let reference = reference_for(
        ArtifactType::ExecutionPlan,
        format!("data:application/json,{encoded}"),
        Some(&body),
    );
    let (plan, _) = resolve(&reference, FetchPolicy::production())
        .await
        .unwrap();
    assert_eq!(plan.ordered_steps.len(), 1);
}

#[tokio::test]
async fn refuses_a_digest_mismatch() {
    let body = plan_json();
    let mut reference = reference_for(ArtifactType::ExecutionPlan, data_uri_of(&body), Some(&body));
    reference.integrity = Some(ArtifactIntegrity {
        algorithm: "keccak256".into(),
        value: format!("0x{}", "11".repeat(32)),
    });
    let error = resolve(&reference, FetchPolicy::production())
        .await
        .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("must not be simulated or signed")
    );
}

#[tokio::test]
async fn refuses_a_non_json_data_uri_media_type() {
    let reference = reference_for(
        ArtifactType::ExecutionPlan,
        "data:text/html;base64,PGI+PC9iPg==",
        None,
    );
    let error = resolve(&reference, FetchPolicy::production())
        .await
        .unwrap_err();
    assert!(error.to_string().contains("application/json"));
}

#[tokio::test]
async fn fetches_and_validates_a_remote_plan() {
    let body = plan_json();
    let url = serve_once("HTTP/1.1 200 OK", body.clone()).await;
    let reference = reference_for(ArtifactType::ExecutionPlan, url, Some(&body));
    let (plan, source) = resolve(&reference, FetchPolicy::insecure_for_tests())
        .await
        .unwrap();
    assert_eq!(plan.caip2_chain_id, "eip155:1");
    assert!(matches!(source, ArtifactSource::Https { host } if host == "127.0.0.1"));
}

#[tokio::test]
async fn a_trailing_dot_host_is_vetted_and_fetched_under_one_name() {
    // The admission checks trim the root label, so the name that was
    // vetted and pinned must also be the name the request carries. If the
    // two drift apart the address override stops binding and the fetch
    // resolves a second time, against nothing that was checked.
    let body = plan_json();
    let url = serve_once("HTTP/1.1 200 OK", body.clone())
        .await
        .replace("127.0.0.1", "localhost.");
    let reference = reference_for(ArtifactType::ExecutionPlan, url, Some(&body));
    let (plan, source) = resolve(&reference, FetchPolicy::insecure_for_tests())
        .await
        .unwrap();
    assert_eq!(plan.caip2_chain_id, "eip155:1");
    // The provenance host is the vetted, trailing-dot-normalized name.
    assert!(matches!(source, ArtifactSource::Https { host } if host == "localhost"));
}

#[tokio::test]
async fn reports_an_expired_reference_without_echoing_the_body() {
    let secret = "{\"error\":{\"secret\":\"internal detail\"}}";
    let url = serve_once("HTTP/1.1 404 Not Found", secret.to_owned()).await;
    let reference = reference_for(ArtifactType::ExecutionPlan, url, Some(secret));
    let error = resolve(&reference, FetchPolicy::insecure_for_tests())
        .await
        .unwrap_err();
    let message = error.to_string();
    assert!(message.contains("expired or never existed"));
    assert!(!message.contains("internal detail"));
}

#[tokio::test]
async fn read_call_bundle_errors_name_the_bundle_not_the_plan() {
    let secret = "{\"error\":{\"secret\":\"internal detail\"}}";
    let url = serve_once("HTTP/1.1 404 Not Found", secret.to_owned()).await;
    let reference = reference_for(ArtifactType::ReadCalls, url, Some(secret));
    let error = fetch_reference(
        &reference,
        ArtifactType::ReadCalls,
        FetchPolicy::insecure_for_tests(),
    )
    .await
    .unwrap_err();
    let message = error.to_string();
    assert!(message.contains("read-call bundle"));
    assert!(message.contains("expired or never existed"));
    assert!(!message.contains("internal detail"));

    let body = "{\"chain_id\":\"1\",\"calls\":[]}";
    let mut reference = reference_for(ArtifactType::ReadCalls, data_uri_of(body), Some(body));
    reference.integrity = Some(ArtifactIntegrity {
        algorithm: "keccak256".into(),
        value: format!("0x{}", "22".repeat(32)),
    });
    let mismatch = fetch_reference(
        &reference,
        ArtifactType::ReadCalls,
        FetchPolicy::production(),
    )
    .await
    .unwrap_err();
    assert!(
        mismatch
            .to_string()
            .contains("its calls must not be executed")
    );
}

#[tokio::test]
async fn refuses_redirects() {
    let url = serve_once("HTTP/1.1 302 Found", String::new()).await;
    let reference = reference_for(ArtifactType::ExecutionPlan, url, Some(""));
    let error = resolve(&reference, FetchPolicy::insecure_for_tests())
        .await
        .unwrap_err();
    assert!(error.to_string().contains("HTTP 302"));
}

#[tokio::test]
async fn production_policy_refuses_http_loopback_and_private_hosts() {
    for url in [
        "http://mcp.ekubo.org/plan/x",
        "https://127.0.0.1/plan/x",
        "https://10.0.0.1/plan/x",
        "https://169.254.169.254/plan/x",
        "https://100.64.0.1/plan/x",
        "https://[fd00::1]/plan/x",
        "https://localhost/plan/x",
        "https://intranet.local/plan/x",
        "https://mcp.ekubo.org:8443/plan/x",
        "https://user:secret@mcp.ekubo.org/plan/x",
        "https://mcp.ekubo.org/plan/x#fragment",
    ] {
        let reference = reference_for(ArtifactType::ExecutionPlan, url, Some("{}"));
        let error = resolve(&reference, FetchPolicy::production())
            .await
            .unwrap_err();
        let message = error.to_string();
        assert!(
            message.contains("execution plan"),
            "unexpected error for {url}: {message}"
        );
    }
}

#[tokio::test]
async fn refuses_an_oversized_data_uri() {
    let oversized = "a".repeat(MAX_SERIALIZED_PLAN_BYTES + 1);
    let reference = reference_for(
        ArtifactType::ExecutionPlan,
        format!("data:application/json,{oversized}"),
        None,
    );
    let error = resolve(&reference, FetchPolicy::production())
        .await
        .unwrap_err();
    assert!(error.to_string().contains("exceeds"));

    // The base64 arm had no coverage at all, and it is the one where the
    // encoded length and the decoded length differ.
    let oversized = "A".repeat(MAX_DATA_URI_PAYLOAD_BYTES + 4);
    let reference = reference_for(
        ArtifactType::ExecutionPlan,
        format!("data:application/json;base64,{oversized}"),
        None,
    );
    let error = resolve(&reference, FetchPolicy::production())
        .await
        .unwrap_err();
    assert!(error.to_string().contains("exceeds"), "{error}");
}

#[test]
fn public_ip_classification_covers_reserved_ranges() {
    for private in [
        "0.1.2.3",
        "10.1.2.3",
        "100.64.0.9",
        "127.0.0.1",
        "169.254.169.254",
        "172.16.0.1",
        "192.0.0.1",
        "192.168.1.1",
        "198.18.0.1",
        "255.255.255.255",
        "192.88.99.1",
        "::1",
        "fe80::1",
        "fd12::1",
        "::ffff:10.0.0.1",
        // Forms that carry an IPv4 destination inside a v6 literal.
        "::10.0.0.1",
        "64:ff9b::a00:1",
        "64:ff9b:1::a00:1",
        "2002:a00:1::",
        "2001:0:53aa:64c:c:c7f2:f5ff:fffe",
        "2001:20::1",
        "100::1",
    ] {
        assert!(
            !is_public_ip(private.parse().unwrap()),
            "{private} should be reserved"
        );
    }
    // Ordinary global addresses that the masks above must not swallow.
    for public in [
        "1.1.1.1",
        "104.16.0.1",
        "2606:4700::1111",
        "2001:4860:4860::8888",
        "2003::1",
    ] {
        assert!(
            is_public_ip(public.parse().unwrap()),
            "{public} should be public"
        );
    }
}

mod token_list_references {
    use super::*;

    fn list_json() -> String {
        serde_json::json!({
            "name": "Ekubo canonical list",
            "tokens": [{
                "chainId": 1,
                "address": "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
                "symbol": "USDC",
                "name": "USD Coin",
                "decimals": 6,
            }],
        })
        .to_string()
    }

    #[tokio::test]
    async fn resolves_a_token_list_from_an_inline_data_uri() {
        let body = list_json();
        let reference = reference_for(ArtifactType::TokenList, data_uri_of(&body), Some(&body));
        let (list, source) = resolve_token_list_reference(&reference, FetchPolicy::production())
            .await
            .unwrap();
        assert_eq!(list.declared_name.as_deref(), Some("Ekubo canonical list"));
        assert_eq!(list.tokens.len(), 1);
        assert_eq!(list.tokens[0].symbol, "USDC");
        assert_eq!(source, ArtifactSource::InlineDataUri);
    }

    /// The digest is what makes a fetched list the producer's list rather than
    /// whatever answered the URL, so altering a single byte must be refused
    /// exactly as it is for a plan.
    #[tokio::test]
    async fn a_tampered_token_list_is_refused() {
        let body = list_json();
        let tampered = body.replace("USDC", "USDT");
        assert_eq!(tampered.len(), body.len());
        let mut reference = reference_for(ArtifactType::TokenList, data_uri_of(&body), Some(&body));
        reference.url = data_uri_of(&tampered);
        let error = resolve_token_list_reference(&reference, FetchPolicy::production())
            .await
            .unwrap_err()
            .to_string();
        assert!(error.contains("token list"), "{error}");
    }

    /// Artifact types are not interchangeable: a plan handed to the token-list
    /// path must be refused by type before anything parses it.
    #[tokio::test]
    async fn an_execution_plan_reference_is_not_a_token_list() {
        let body = plan_json();
        let reference = reference_for(ArtifactType::ExecutionPlan, data_uri_of(&body), Some(&body));
        let error = resolve_token_list_reference(&reference, FetchPolicy::production())
            .await
            .unwrap_err()
            .to_string();
        assert!(error.contains("token_list"), "{error}");
        assert!(error.contains("execution_plan"), "{error}");
    }

    /// Errors name the artifact that failed, so an agent relaying three kinds
    /// of reference is told which one to re-request.
    #[tokio::test]
    async fn errors_name_the_token_list_not_the_plan() {
        let reference = reference_for(
            ArtifactType::TokenList,
            "data:application/json,not-json",
            None,
        );
        let error = resolve_token_list_reference(&reference, FetchPolicy::production())
            .await
            .unwrap_err()
            .to_string();
        assert!(!error.contains("execution plan"), "{error}");
    }
}
