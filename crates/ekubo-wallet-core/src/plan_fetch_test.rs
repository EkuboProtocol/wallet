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

mod file_references {
    use super::*;

    /// A file holding `body`, and the `file:` URL that names it. The
    /// directory is returned with the URL because dropping it deletes the
    /// file, which is exactly the failure the caller is not testing.
    fn written(body: &str) -> (tempfile::TempDir, std::path::PathBuf, String) {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("artifact.json");
        std::fs::write(&path, body).unwrap();
        let url = Url::from_file_path(&path).unwrap().to_string();
        (directory, path, url)
    }

    #[tokio::test]
    async fn resolves_a_plan_an_agent_left_on_disk() {
        let body = plan_json();
        let (_directory, _path, url) = written(&body);
        let reference = reference_for(ArtifactType::ExecutionPlan, url, Some(&body));
        let (plan, source) = resolve(&reference, FetchPolicy::production())
            .await
            .unwrap();
        assert_eq!(plan.ordered_steps.len(), 1);
        assert_eq!(source, ArtifactSource::LocalFile);
        // What the owner reads on the approval screen. It must not be
        // mistakable for the wallet having built the plan itself.
        assert_eq!(source.to_string(), "a file on this machine");
    }

    #[tokio::test]
    async fn a_file_reference_must_carry_integrity_and_a_byte_count() {
        // The digest is what ties the bytes read at send time to the ones
        // read at simulate time, and what stops a reference from naming a
        // file whose contents its author does not already have.
        let body = plan_json();
        let (_directory, _path, url) = written(&body);
        let reference = reference_for(ArtifactType::ExecutionPlan, url.clone(), None);
        let error = resolve(&reference, FetchPolicy::production())
            .await
            .unwrap_err()
            .to_string();
        assert!(error.contains("integrity block"), "{error}");
        assert!(error.contains("ekubo-wallet meta-reference"), "{error}");

        let mut without_count = reference_for(ArtifactType::ExecutionPlan, url, Some(&body));
        without_count.bytes = None;
        let error = resolve(&without_count, FetchPolicy::production())
            .await
            .unwrap_err()
            .to_string();
        assert!(error.contains("byte count"), "{error}");
    }

    #[tokio::test]
    async fn a_changed_file_is_refused_without_describing_what_it_holds() {
        let body = plan_json();
        let (_directory, path, url) = written(&body);
        let reference = reference_for(ArtifactType::ExecutionPlan, url, Some(&body));

        // Longer than the promise, so a message that named the file's real
        // size would be reporting a fact about a file the caller may never
        // have read.
        let replacement = format!("{}    ", plan_json());
        std::fs::write(&path, &replacement).unwrap();
        let error = resolve(&reference, FetchPolicy::production())
            .await
            .unwrap_err()
            .to_string();
        assert!(error.contains("rebuild the reference"), "{error}");
        assert!(
            !error.contains(&replacement.len().to_string()),
            "the size of a file the caller could not describe leaked: {error}"
        );

        // Same length, different bytes: the digest is the only thing that
        // catches it, and the digest it computed is the one thing the error
        // may not say.
        let replacement = plan_json().replace("0x2222", "0x3333");
        assert_eq!(replacement.len(), body.len());
        std::fs::write(&path, &replacement).unwrap();
        let error = resolve(&reference, FetchPolicy::production())
            .await
            .unwrap_err()
            .to_string();
        assert!(error.contains("must not be simulated or signed"), "{error}");
        assert!(
            !error.contains(digest_of(&replacement).trim_start_matches("0x")),
            "the digest of a file the caller could not describe leaked: {error}"
        );
    }

    #[tokio::test]
    async fn refuses_a_file_url_naming_another_host() {
        // This process speaks to no file server, so an authority is not a
        // fetch it declines to make — it is a path it refuses to invent. On
        // Windows the invented path is a real one: a host maps to the UNC
        // share `\\files.example\plans\one.json`, so a refusal that arrived
        // only as "could not be read" would mean the SMB read had already
        // been attempted.
        let body = plan_json();
        let reference = reference_for(
            ArtifactType::ExecutionPlan,
            "file://files.example/plans/one.json",
            Some(&body),
        );
        let error = resolve(&reference, FetchPolicy::production())
            .await
            .unwrap_err()
            .to_string();
        assert!(error.contains("absolute local path"), "{error}");
        assert!(error.contains("files.example"), "{error}");
        assert!(
            !error.contains("could not be read"),
            "the host was reached rather than refused: {error}"
        );
    }

    #[tokio::test]
    async fn refuses_a_file_url_naming_another_host_by_address() {
        // A literal address never looks like a normalized `localhost`, and
        // parses to a host of a different shape than a name does.
        let body = plan_json();
        for authority in ["10.0.0.5", "[::1]", "127.0.0.1"] {
            let reference = reference_for(
                ArtifactType::ExecutionPlan,
                format!("file://{authority}/plans/one.json"),
                Some(&body),
            );
            let error = resolve(&reference, FetchPolicy::production())
                .await
                .unwrap_err()
                .to_string();
            assert!(
                error.contains("absolute local path"),
                "{authority}: {error}"
            );
            assert!(
                !error.contains("could not be read"),
                "{authority} was reached rather than refused: {error}"
            );
        }
    }

    #[tokio::test]
    async fn reads_the_local_path_an_empty_or_localhost_authority_names() {
        // The two authorities that mean this machine. Both are folded to no
        // host by the parser, which is what the refusal above relies on, so
        // an accepted `file:` URL has to keep working through it.
        let body = plan_json();
        let (_directory, _path, url) = written(&body);
        assert!(url.starts_with("file:///"), "{url}");
        let localhost = url.replacen("file://", "file://localhost", 1);
        for candidate in [url, localhost] {
            let reference =
                reference_for(ArtifactType::ExecutionPlan, candidate.clone(), Some(&body));
            let (plan, source) = resolve(&reference, FetchPolicy::production())
                .await
                .unwrap_or_else(|error| panic!("{candidate}: {error}"));
            assert_eq!(plan.ordered_steps.len(), 1);
            assert_eq!(source, ArtifactSource::LocalFile);
        }
    }

    #[tokio::test]
    async fn refuses_anything_that_is_not_a_regular_file() {
        // A directory here, but the check is really about the FIFO and the
        // character device: both would hold the tool call open indefinitely.
        let body = plan_json();
        let directory = tempfile::tempdir().unwrap();
        let url = Url::from_directory_path(directory.path())
            .unwrap()
            .to_string();
        let reference = reference_for(ArtifactType::ExecutionPlan, url, Some(&body));
        let error = resolve(&reference, FetchPolicy::production())
            .await
            .unwrap_err()
            .to_string();
        assert!(error.contains("not a regular file"), "{error}");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn a_fifo_is_answered_rather_than_waited_on() {
        // What this asserts is mostly the timeout. A FIFO opened for reading
        // with no writer holds the open, not the read, so without
        // `O_NONBLOCK` the call never comes back and the regression is a
        // hung test rather than a wrong message. The message is checked too:
        // the refusal has to come from the handle's own type.
        let body = plan_json();
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("plan.json");
        // The shipped `mkfifo`, because `libc::mkfifo` is an `unsafe` call and
        // this workspace denies those outright.
        let made = std::process::Command::new("mkfifo")
            .arg(&path)
            .status()
            .expect("mkfifo");
        assert!(made.success(), "mkfifo {}", path.display());

        let url = Url::from_file_path(&path).unwrap().to_string();
        let reference = reference_for(ArtifactType::ExecutionPlan, url, Some(&body));
        let error = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            resolve(&reference, FetchPolicy::production()),
        )
        .await
        .expect("opening a FIFO must not block")
        .unwrap_err()
        .to_string();
        assert!(error.contains("not a regular file"), "{error}");
    }

    #[tokio::test]
    async fn a_missing_file_names_the_path_the_caller_gave() {
        let body = plan_json();
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("never-written.json");
        let url = Url::from_file_path(&path).unwrap().to_string();
        let reference = reference_for(ArtifactType::ExecutionPlan, url, Some(&body));
        let error = resolve(&reference, FetchPolicy::production())
            .await
            .unwrap_err()
            .to_string();
        assert!(error.contains("could not be read"), "{error}");
        assert!(error.contains("never-written.json"), "{error}");
    }

    #[tokio::test]
    async fn read_call_bundles_travel_the_same_way() {
        let body = serde_json::json!({
            "chain_id": "1",
            "calls": [{
                "to": "0x2222222222222222222222222222222222222222",
                "data": "0x18160ddd",
            }],
        })
        .to_string();
        let (_directory, _path, url) = written(&body);
        let reference = reference_for(ArtifactType::ReadCalls, url, Some(&body));
        let fetched = fetch_reference(
            &reference,
            ArtifactType::ReadCalls,
            FetchPolicy::production(),
        )
        .await
        .unwrap();
        assert_eq!(fetched.bytes, body.as_bytes());
        assert_eq!(fetched.source, ArtifactSource::LocalFile);
    }
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
        "2001:10::1",
        "100::1",
        // Site local: deprecated, which is not the same as unreachable.
        "fec0::1",
        "feff::1",
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

    /// The tokenlists.org distribution model: a bare published URL, no
    /// envelope and no digest, because the curator updates the list in place
    /// and nobody pointing a wallet at it holds a hash for what it says today.
    /// The host comes back with the entries because it is the one fact the
    /// caller could not choose.
    #[tokio::test]
    async fn imports_a_published_list_from_a_bare_url() {
        let url = serve_once("HTTP/1.1 200 OK", list_json()).await;
        let (list, host) = fetch_token_list_url(&url, &[], FetchPolicy::insecure_for_tests())
            .await
            .unwrap();
        assert_eq!(list.declared_name.as_deref(), Some("Ekubo canonical list"));
        assert_eq!(list.tokens.len(), 1);
        assert_eq!(list.tokens[0].symbol, "USDC");
        assert_eq!(host, "127.0.0.1");
    }

    /// Dropping the digest requirement drops nothing else. Admission is the
    /// containment on this path, so the production policy must still refuse
    /// the loopback host that the test policy above admits — otherwise a
    /// caller could aim the wallet at whatever this machine can reach and the
    /// missing digest would be the least of it.
    #[tokio::test]
    async fn a_bare_url_is_still_held_to_the_admission_policy() {
        for url in [
            "http://tokens.example.com/list.json",
            "https://127.0.0.1/list.json",
            "https://user:pass@tokens.example.com/list.json",
            "https://tokens.example.com:8443/list.json",
            "file:///tmp/list.json",
        ] {
            let error = fetch_token_list_url(url, &[], FetchPolicy::production())
                .await
                .unwrap_err()
                .to_string();
            assert!(error.contains("token list"), "{url}: {error}");
        }
    }

    /// A URL that answers with something else is a failed import, not a
    /// mystery: the error names the token list and never echoes the body it
    /// got back.
    #[tokio::test]
    async fn a_url_serving_something_other_than_a_list_is_refused() {
        let secret = "s3cret-intranet-contents";
        let url = serve_once("HTTP/1.1 200 OK", format!(r#"{{"page":"{secret}"}}"#)).await;
        let error = fetch_token_list_url(&url, &[], FetchPolicy::insecure_for_tests())
            .await
            .unwrap_err()
            .to_string();
        assert!(error.contains("not a token list"), "{error}");
        assert!(!error.contains(secret), "{error}");
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

#[test]
fn a_token_list_reference_gets_the_token_list_budget() {
    // The reference path used to apply the execution plan's cap to whatever it
    // fetched, so an identical list got four times the pre-parse budget purely
    // by arriving in an envelope -- and `parse_token_list`'s own check runs
    // after the whole body is already held.
    assert_eq!(
        ArtifactType::TokenList.max_body_bytes(),
        crate::token_list::MAX_TOKEN_LIST_BYTES
    );
    assert!(ArtifactType::TokenList.max_body_bytes() < MAX_SERIALIZED_PLAN_BYTES);
    assert_eq!(
        ArtifactType::ExecutionPlan.max_body_bytes(),
        MAX_SERIALIZED_PLAN_BYTES
    );
    assert_eq!(
        ArtifactType::ReadCalls.max_body_bytes(),
        MAX_SERIALIZED_PLAN_BYTES
    );

    // And a `data:` list is measured against the same number before it is
    // decoded, so nothing allocates a buffer for bytes the check would refuse.
    let oversized =
        "A".repeat(max_data_uri_payload_bytes(ArtifactType::TokenList.max_body_bytes()) + 4);
    let error = decode_data_uri(
        &format!("data:application/json;base64,{oversized}"),
        ArtifactType::TokenList,
    )
    .unwrap_err()
    .to_string();
    assert!(
        error.contains(&crate::token_list::MAX_TOKEN_LIST_BYTES.to_string()),
        "{error}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_local_read_does_not_run_on_a_runtime_worker() {
    // The read is bounded for a regular file on local storage and unbounded
    // for one on a mount that has stopped answering -- which the caller
    // chooses. Off the runtime's own threads, a stalled mount costs a blocking
    // thread rather than the ability to serve anything else.
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("plan.json");
    std::fs::write(&path, b"{}").unwrap();
    let url = format!("file://{}", path.display());

    let body = read_local_file(&url, ArtifactType::ExecutionPlan)
        .await
        .expect("an ordinary file still reads");
    assert_eq!(body, b"{}");

    // A directory is refused with the same sentence on every platform, which
    // is the case the non-blocking open exists to keep answering.
    let error = read_local_file(
        &format!("file://{}", directory.path().display()),
        ArtifactType::ExecutionPlan,
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(error.contains("not a regular file"), "{error}");
}
