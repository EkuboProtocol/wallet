//! Resolving referenced artifacts from a URL instead of inline tool arguments.
//!
//! Producers such as the Ekubo MCP server return references — a short-lived
//! `https` URL where a body is stored plus a keccak256 digest of its exact
//! bytes — so the agent between the producer and this wallet relays a line of
//! text instead of re-emitting kilobytes of calldata. Two artifact kinds
//! travel this way: execution plans (`execution_plan_reference`) and
//! read-call bundles (`read_calls_reference`, exact `wallet_batch_eth_call`
//! argument bodies). This wallet fetches the body itself, verifies the
//! digest, and then parses and validates it exactly as it would an inline
//! one; a fetched body earns no extra trust from having a URL, and an inline
//! body is still expressible as a `data:` URI that never touches the network.
//!
//! These fetches are this process's only outbound requests that are not a
//! configured chain RPC, so admission is deliberately narrow: `https` on the
//! default port to a public, resolvable host; no credentials, fragments,
//! redirects, or private/internal addresses; a hard response-size cap; and
//! errors that describe the failure without echoing a byte of the response
//! body.

use crate::core::execution_plan::{ExecutionPlan, MAX_SERIALIZED_PLAN_BYTES};
use alloy::primitives::keccak256;
use anyhow::{Context, Result, bail, ensure};
use base64::Engine as _;
use percent_encoding::percent_decode_str;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use url::{Host, Url};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const TOTAL_TIMEOUT: Duration = Duration::from_secs(15);

/// The longest `data:` payload worth decoding at all.
///
/// Base64 packs three bytes into four characters and percent-encoding never
/// contracts, so nothing longer than this can decode to a body within
/// `MAX_SERIALIZED_PLAN_BYTES`. Expressed against that limit rather than as
/// its own number, because it is the same limit — just measured before the
/// decode instead of after it.
const MAX_DATA_URI_PAYLOAD_BYTES: usize = MAX_SERIALIZED_PLAN_BYTES / 3 * 4 + 4;

/// How long name resolution may take before a reference fetch gives up.
///
/// `CONNECT_TIMEOUT` and `TOTAL_TIMEOUT` are configured on the HTTP client, so
/// neither starts until an address exists. Without a deadline of its own, a
/// caller who names a host served by a dead resolver holds the tool call open
/// for as long as the platform stub resolver cares to retry — tens of seconds
/// across several nameservers — and holds a blocking-pool thread with it.
const RESOLVE_TIMEOUT: Duration = Duration::from_secs(5);

/// What transports `resolve_execution_plan` will accept.
///
/// Production admits only public `https` and local `data:` URIs. Debug builds
/// may loosen that to plain `http` and loopback hosts for end-to-end testing
/// against a local plan producer; release builds never do.
#[derive(Clone, Copy, Debug)]
pub struct FetchPolicy {
    allow_insecure: bool,
}

impl FetchPolicy {
    #[must_use]
    pub fn production() -> Self {
        #[cfg(debug_assertions)]
        if std::env::var_os("EKUBO_WALLET_ALLOW_INSECURE_PLAN_URLS").is_some() {
            return Self {
                allow_insecure: true,
            };
        }
        Self {
            allow_insecure: false,
        }
    }

    #[cfg(test)]
    fn insecure_for_tests() -> Self {
        Self {
            allow_insecure: true,
        }
    }
}

/// Names the artifact being fetched in every admission and integrity error,
/// so a failed plan fetch and a failed read-bundle fetch stay as specific as
/// they were when plans were the only referenced artifact.
#[derive(Clone, Copy, Debug)]
pub struct FetchSubject {
    /// The artifact's noun in error messages: "execution plan URL is not…".
    pub noun: &'static str,
    /// What a 404 should tell the agent to do about the expired reference.
    pub refresh_hint: &'static str,
    /// The consequence clause of a digest mismatch.
    pub mismatch_consequence: &'static str,
}

pub const EXECUTION_PLAN_SUBJECT: FetchSubject = FetchSubject {
    noun: "execution plan",
    refresh_hint: "re-run the producer's preparation tool for a fresh plan and reference",
    mismatch_consequence: "it must not be simulated or signed",
};

pub const READ_CALLS_SUBJECT: FetchSubject = FetchSubject {
    noun: "read-call bundle",
    refresh_hint: "re-run the producer's tool for a fresh bundle and reference",
    mismatch_consequence: "its calls must not be executed",
};

/// Fetch, verify, parse, and validate one execution plan.
///
/// `expected_content_keccak256` is the digest published beside the URL by
/// whatever produced the plan. When present, it is recomputed over the exact
/// bytes obtained here and a mismatch is a hard failure: the plan the agent
/// saw prepared is then provably not the plan this wallet would execute.
pub async fn resolve_execution_plan(
    url: &str,
    expected_content_keccak256: Option<&str>,
    policy: FetchPolicy,
) -> Result<ExecutionPlan> {
    let bytes = fetch_verified_bytes(
        url,
        expected_content_keccak256,
        policy,
        EXECUTION_PLAN_SUBJECT,
    )
    .await?;
    let value: serde_json::Value =
        serde_json::from_slice(&bytes).context("execution plan body is not valid JSON")?;
    ExecutionPlan::parse(value)
}

/// Fetch one referenced body — remote `https` or local `data:` URI — and
/// verify it against the digest its producer published, without interpreting
/// the bytes. Callers parse and validate the result exactly as they would an
/// inline body.
pub async fn fetch_verified_bytes(
    url: &str,
    expected_content_keccak256: Option<&str>,
    policy: FetchPolicy,
    subject: FetchSubject,
) -> Result<Vec<u8>> {
    let bytes = if url.starts_with("data:") {
        decode_data_uri(url, subject)?
    } else {
        fetch_remote(url, policy, subject).await?
    };
    if let Some(expected) = expected_content_keccak256 {
        verify_digest(&bytes, expected, subject)?;
    }
    Ok(bytes)
}

/// Decode `data:application/json[;base64],…` without touching the network.
fn decode_data_uri(url: &str, subject: FetchSubject) -> Result<Vec<u8>> {
    let remainder = url
        .strip_prefix("data:")
        .expect("caller matched the data: prefix");
    let (media, payload) = remainder
        .split_once(',')
        .context("data: URI has no comma separating media type from payload")?;
    let mut base64_payload = false;
    for (index, part) in media.split(';').enumerate() {
        if index == 0 {
            ensure!(
                part.is_empty() || part.eq_ignore_ascii_case("application/json"),
                "data: URI media type must be application/json"
            );
        } else if part.eq_ignore_ascii_case("base64") {
            base64_payload = true;
        } else {
            ensure!(
                part.to_ascii_lowercase().starts_with("charset="),
                "unsupported data: URI parameter"
            );
        }
    }
    let noun = subject.noun;
    // Checked before the decode, not after it. Neither encoding can contract:
    // base64 packs three bytes into four characters and percent-encoding only
    // ever expands, so a payload longer than this cannot decode to anything
    // the check below would accept. Refusing on the encoded length keeps the
    // process from allocating a buffer for bytes the next statement throws
    // away.
    ensure!(
        payload.len() <= MAX_DATA_URI_PAYLOAD_BYTES,
        "{noun} body exceeds {MAX_SERIALIZED_PLAN_BYTES} bytes"
    );
    let bytes = if base64_payload {
        base64::engine::general_purpose::STANDARD
            .decode(payload)
            .context("data: URI payload is not valid standard base64")?
    } else {
        percent_decode_str(payload).collect()
    };
    ensure!(
        bytes.len() <= MAX_SERIALIZED_PLAN_BYTES,
        "{noun} body exceeds {MAX_SERIALIZED_PLAN_BYTES} bytes"
    );
    Ok(bytes)
}

// The suffix checks run on an already-lowercased copy of the hostname; the
// lint pattern-matches them as file-extension comparisons, which they are not.
#[allow(clippy::case_sensitive_file_extension_comparisons)]
async fn fetch_remote(url: &str, policy: FetchPolicy, subject: FetchSubject) -> Result<Vec<u8>> {
    let noun = subject.noun;
    let parsed = Url::parse(url).with_context(|| format!("{noun} URL is not a valid URL"))?;
    ensure!(
        parsed.scheme() == "https" || (policy.allow_insecure && parsed.scheme() == "http"),
        "{noun} URLs must use https"
    );
    ensure!(
        parsed.username().is_empty() && parsed.password().is_none(),
        "{noun} URLs must not carry credentials"
    );
    ensure!(
        parsed.fragment().is_none(),
        "{noun} URLs must not carry a fragment"
    );
    ensure!(
        policy.allow_insecure || parsed.port().is_none(),
        "{noun} URLs must use the default https port"
    );
    let mut parsed = parsed;
    let host = parsed
        .host()
        .with_context(|| format!("{noun} URL has no host"))?;
    let is_domain = matches!(&host, Host::Domain(_));
    let host_text = vetted_host(&host, policy.allow_insecure, noun)?;
    let port = parsed.port_or_known_default().unwrap_or(443);

    // Everything below — the lookup, the vetting, and the address override —
    // uses the trailing-dot-trimmed name, while the request would carry the
    // authority as written. reqwest keys its override on the request's
    // hostname, and `example.com.` is not the same key as `example.com`, so
    // the pin would silently fail to bind and the connection would resolve a
    // second time against nothing that was checked. The URL is normalized to
    // the name that was actually vetted, so there is one name throughout.
    if is_domain && parsed.host_str() != Some(host_text.as_str()) {
        parsed
            .set_host(Some(&host_text))
            .with_context(|| format!("{noun} URL has no valid host"))?;
    }

    // Resolve once, vet every address, and pin the connection to the vetted
    // set so a rebinding resolver cannot answer differently for the actual
    // connect. The admission decision and the connection use the same bytes.
    let resolved = resolve_with_deadline(&host_text, port, noun).await?;
    ensure!(
        policy.allow_insecure || resolved.iter().all(|address| is_public_ip(address.ip())),
        "{noun} host resolves to a private or reserved address"
    );

    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        // A proxy resolves the hostname itself and connects on this process's
        // behalf, so the override below would pin nothing and the addresses
        // vetted above would never be the ones dialled. Admission only means
        // something if this process makes the connection, so the ambient
        // HTTPS_PROXY/ALL_PROXY environment is ignored here. The chain RPC is
        // a different case: that endpoint is one the owner configured, and
        // reaching it through their proxy is their decision to make.
        .no_proxy()
        .connect_timeout(CONNECT_TIMEOUT)
        .timeout(TOTAL_TIMEOUT)
        .resolve_to_addrs(&host_text, &resolved)
        .build()
        .context("could not build the reference fetch client")?;
    let response = client
        .get(parsed)
        .header("accept", "application/json")
        .send()
        .await
        .with_context(|| format!("{noun} fetch failed"))?;
    let status = response.status();
    if status == reqwest::StatusCode::NOT_FOUND {
        bail!(
            "{noun} reference returned 404: it has expired or never existed; {}",
            subject.refresh_hint
        );
    }
    ensure!(status.is_success(), "{noun} fetch returned HTTP {status}");
    if let Some(length) = response.content_length() {
        ensure!(
            length <= MAX_SERIALIZED_PLAN_BYTES as u64,
            "{noun} body exceeds {MAX_SERIALIZED_PLAN_BYTES} bytes"
        );
    }
    let mut body = Vec::new();
    let mut response = response;
    while let Some(chunk) = response
        .chunk()
        .await
        .with_context(|| format!("{noun} fetch failed mid-body"))?
    {
        ensure!(
            body.len() + chunk.len() <= MAX_SERIALIZED_PLAN_BYTES,
            "{noun} body exceeds {MAX_SERIALIZED_PLAN_BYTES} bytes"
        );
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

fn verify_digest(bytes: &[u8], expected: &str, subject: FetchSubject) -> Result<()> {
    let normalized = expected.strip_prefix("0x").unwrap_or(expected);
    ensure!(
        normalized.len() == 64 && normalized.bytes().all(|byte| byte.is_ascii_hexdigit()),
        "expected_content_keccak256 must be a 32-byte hex digest"
    );
    let actual = format!("{:x}", keccak256(bytes));
    ensure!(
        actual == normalized.to_ascii_lowercase(),
        "fetched {} bytes hash to 0x{actual} but the reference promised 0x{}; \
         the body was altered or the reference is stale, so {}",
        subject.noun,
        normalized.to_ascii_lowercase(),
        subject.mismatch_consequence
    );
    Ok(())
}

/// The hostname to resolve and pin, once the host itself has been admitted.
///
/// Shared by the reference fetch and by [`ensure_public_endpoint`] so the two
/// cannot drift: an endpoint an MCP caller names is admitted by exactly the
/// rules a referenced plan URL is.
// The suffix checks run on an already-lowercased copy of the hostname; the
// lint pattern-matches them as file-extension comparisons, which they are not.
#[allow(clippy::case_sensitive_file_extension_comparisons)]
fn vetted_host(host: &Host<&str>, allow_insecure: bool, noun: &str) -> Result<String> {
    Ok(match host {
        Host::Domain(domain) => {
            let domain = domain.trim_end_matches('.');
            let lowered = domain.to_ascii_lowercase();
            ensure!(
                allow_insecure
                    || (domain.contains('.')
                        && !lowered.ends_with(".local")
                        && !lowered.ends_with(".internal")
                        && !lowered.ends_with(".localhost")
                        && !lowered.ends_with(".onion")
                        && !lowered.ends_with(".home.arpa")),
                "{noun} must name a public host"
            );
            domain.to_owned()
        }
        Host::Ipv4(address) => {
            ensure!(
                allow_insecure || is_public_ip(IpAddr::V4(*address)),
                "{noun} must not target private or reserved addresses"
            );
            address.to_string()
        }
        Host::Ipv6(address) => {
            ensure!(
                allow_insecure || is_public_ip(IpAddr::V6(*address)),
                "{noun} must not target private or reserved addresses"
            );
            address.to_string()
        }
    })
}

async fn resolve_with_deadline(host: &str, port: u16, noun: &str) -> Result<Vec<SocketAddr>> {
    let resolved: Vec<SocketAddr> =
        tokio::time::timeout(RESOLVE_TIMEOUT, tokio::net::lookup_host((host, port)))
            .await
            .with_context(|| format!("{noun} host did not resolve within {RESOLVE_TIMEOUT:?}"))?
            .with_context(|| format!("{noun} host did not resolve"))?
            .collect();
    ensure!(!resolved.is_empty(), "{noun} host did not resolve");
    Ok(resolved)
}

/// Whether an endpoint a caller named over MCP may be contacted at all.
///
/// `validate_network` deliberately admits `http` and loopback, because an
/// owner configuring a local devnet from their own terminal is naming a
/// machine they already control. An MCP caller is not that owner. An endpoint
/// it proposes therefore passes the same admission a referenced plan URL does
/// — public `https`, no credentials, no private or reserved address — before
/// this process sends it a single byte.
///
/// This cannot be as tight as the reference fetch: the URL is stored and used
/// later, so there is no connection to pin the vetted addresses to, and a
/// resolver that answers differently afterwards is not caught here. What backs
/// it up is that the stored endpoint is visible to the owner in `network list`.
pub async fn ensure_public_endpoint(url: &Url, noun: &str) -> Result<()> {
    ensure!(url.scheme() == "https", "{noun} must use https");
    ensure!(
        url.username().is_empty() && url.password().is_none(),
        "{noun} must not carry credentials in the URL"
    );
    let host = url.host().with_context(|| format!("{noun} has no host"))?;
    let host_text = vetted_host(&host, false, noun)?;
    let port = url.port_or_known_default().unwrap_or(443);
    let resolved = resolve_with_deadline(&host_text, port, noun).await?;
    ensure!(
        resolved.iter().all(|address| is_public_ip(address.ip())),
        "{noun} resolves to a private or reserved address"
    );
    Ok(())
}

/// Whether an address is plausibly globally routable. `IpAddr::is_global` is
/// unstable, so the reserved ranges are spelled out.
fn is_public_ip(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(v4) => {
            let octets = v4.octets();
            !(v4.is_unspecified()
                || v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_multicast()
                || v4.is_documentation()
                // 0.0.0.0/8 "this network"
                || octets[0] == 0
                // 100.64.0.0/10 carrier-grade NAT
                || (octets[0] == 100 && (octets[1] & 0b1100_0000) == 64)
                // 192.0.0.0/24 IETF protocol assignments
                || (octets[0] == 192 && octets[1] == 0 && octets[2] == 0)
                // 192.88.99.0/24 deprecated 6to4 relay anycast
                || (octets[0] == 192 && octets[1] == 88 && octets[2] == 99)
                // 198.18.0.0/15 benchmarking
                || (octets[0] == 198 && (octets[1] & 0b1111_1110) == 18)
                // 240.0.0.0/4 reserved
                || octets[0] >= 240)
        }
        IpAddr::V6(v6) => {
            // `to_ipv4` covers the IPv4-mapped `::ffff:a.b.c.d` form and the
            // deprecated IPv4-compatible `::a.b.c.d` form alike. Both carry an
            // IPv4 address that is exactly as reachable as the literal would
            // be, so both are judged as that address rather than as an opaque
            // v6 one. `::1` and `::` fall out of this as 0.0.0.1 and 0.0.0.0,
            // which the v4 arm already refuses.
            if let Some(v4) = v6.to_ipv4() {
                return is_public_ip(IpAddr::V4(v4));
            }
            let segments = v6.segments();
            !(v6.is_unspecified()
                || v6.is_loopback()
                || v6.is_multicast()
                // fc00::/7 unique local
                || (segments[0] & 0xfe00) == 0xfc00
                // fe80::/10 link local
                || (segments[0] & 0xffc0) == 0xfe80
                // 100::/64 discard-only
                || (segments[0] == 0x0100
                    && segments[1] == 0
                    && segments[2] == 0
                    && segments[3] == 0)
                // 64:ff9b::/96 and 64:ff9b:1::/48 NAT64. A translator on the
                // path turns the embedded IPv4 into a v4 packet this vetting
                // never saw, so the prefix is refused outright: a translator
                // that is not there costs nothing, and one that is would carry
                // a v6 literal straight to 10.0.0.1.
                || (segments[0] == 0x0064 && segments[1] == 0xff9b)
                // 2001::/32 Teredo, which tunnels to an arbitrary IPv4 host
                || (segments[0] == 0x2001 && segments[1] == 0x0000)
                // 2001:20::/28 ORCHIDv2
                || (segments[0] == 0x2001 && (segments[1] & 0xfff0) == 0x0020)
                // 2002::/16 6to4, whose next 32 bits are an embedded IPv4
                || segments[0] == 0x2002
                // 2001:db8::/32 documentation
                || (segments[0] == 0x2001 && segments[1] == 0x0db8))
        }
    }
}

#[cfg(test)]
mod tests {
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
                "submit_condition": "always",
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
        let encoded = base64::engine::general_purpose::STANDARD.encode(&body);
        let url = format!("data:application/json;base64,{encoded}");
        let plan = resolve_execution_plan(&url, Some(&digest_of(&body)), FetchPolicy::production())
            .await
            .unwrap();
        assert_eq!(plan.chain_id.as_str(), "1");
    }

    #[tokio::test]
    async fn resolves_a_percent_encoded_data_uri() {
        let body = plan_json();
        let encoded: String =
            percent_encoding::utf8_percent_encode(&body, percent_encoding::NON_ALPHANUMERIC)
                .to_string();
        let url = format!("data:application/json,{encoded}");
        let plan = resolve_execution_plan(&url, Some(&digest_of(&body)), FetchPolicy::production())
            .await
            .unwrap();
        assert_eq!(plan.ordered_steps.len(), 1);
    }

    #[tokio::test]
    async fn refuses_a_digest_mismatch() {
        let body = plan_json();
        let encoded = base64::engine::general_purpose::STANDARD.encode(&body);
        let url = format!("data:application/json;base64,{encoded}");
        let wrong = format!("0x{}", "11".repeat(32));
        let error = resolve_execution_plan(&url, Some(&wrong), FetchPolicy::production())
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
        let error = resolve_execution_plan(
            "data:text/html;base64,PGI+PC9iPg==",
            None,
            FetchPolicy::production(),
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("application/json"));
    }

    #[tokio::test]
    async fn fetches_and_validates_a_remote_plan() {
        let body = plan_json();
        let digest = digest_of(&body);
        let url = serve_once("HTTP/1.1 200 OK", body).await;
        let plan = resolve_execution_plan(&url, Some(&digest), FetchPolicy::insecure_for_tests())
            .await
            .unwrap();
        assert_eq!(plan.caip2_chain_id, "eip155:1");
    }

    #[tokio::test]
    async fn a_trailing_dot_host_is_vetted_and_fetched_under_one_name() {
        // The admission checks trim the root label, so the name that was
        // vetted and pinned must also be the name the request carries. If the
        // two drift apart the address override stops binding and the fetch
        // resolves a second time, against nothing that was checked.
        let body = plan_json();
        let digest = digest_of(&body);
        let url = serve_once("HTTP/1.1 200 OK", body)
            .await
            .replace("127.0.0.1", "localhost.");
        let plan = resolve_execution_plan(&url, Some(&digest), FetchPolicy::insecure_for_tests())
            .await
            .unwrap();
        assert_eq!(plan.caip2_chain_id, "eip155:1");
    }

    #[tokio::test]
    async fn reports_an_expired_reference_without_echoing_the_body() {
        let url = serve_once(
            "HTTP/1.1 404 Not Found",
            "{\"error\":{\"secret\":\"internal detail\"}}".to_owned(),
        )
        .await;
        let error = resolve_execution_plan(&url, None, FetchPolicy::insecure_for_tests())
            .await
            .unwrap_err();
        let message = error.to_string();
        assert!(message.contains("expired or never existed"));
        assert!(!message.contains("internal detail"));
    }

    #[tokio::test]
    async fn read_call_bundle_errors_name_the_bundle_not_the_plan() {
        let url = serve_once(
            "HTTP/1.1 404 Not Found",
            "{\"error\":{\"secret\":\"internal detail\"}}".to_owned(),
        )
        .await;
        let error = fetch_verified_bytes(
            &url,
            None,
            FetchPolicy::insecure_for_tests(),
            READ_CALLS_SUBJECT,
        )
        .await
        .unwrap_err();
        let message = error.to_string();
        assert!(message.contains("read-call bundle"));
        assert!(message.contains("expired or never existed"));
        assert!(!message.contains("internal detail"));

        let body = "{\"chain_id\":\"1\",\"calls\":[]}";
        let encoded = base64::engine::general_purpose::STANDARD.encode(body);
        let data_url = format!("data:application/json;base64,{encoded}");
        let wrong = format!("0x{}", "22".repeat(32));
        let mismatch = fetch_verified_bytes(
            &data_url,
            Some(&wrong),
            FetchPolicy::production(),
            READ_CALLS_SUBJECT,
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
        let error = resolve_execution_plan(&url, None, FetchPolicy::insecure_for_tests())
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
            let error = resolve_execution_plan(url, None, FetchPolicy::production())
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
        let url = format!("data:application/json,{oversized}");
        let error = resolve_execution_plan(&url, None, FetchPolicy::production())
            .await
            .unwrap_err();
        assert!(error.to_string().contains("exceeds"));

        // The base64 arm had no coverage at all, and it is the one where the
        // encoded length and the decoded length differ.
        let oversized = "A".repeat(MAX_DATA_URI_PAYLOAD_BYTES + 4);
        let url = format!("data:application/json;base64,{oversized}");
        let error = resolve_execution_plan(&url, None, FetchPolicy::production())
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
}
