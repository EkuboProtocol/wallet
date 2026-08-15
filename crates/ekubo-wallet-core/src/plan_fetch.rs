//! Resolving referenced artifacts from producer envelopes instead of inline
//! tool arguments.
//!
//! Producers such as the Ekubo MCP server return one `artifact_reference`
//! envelope per stored wallet payload: the `https` URL where the body is
//! stored and an integrity block (keccak256 of its exact bytes plus their
//! count). The agent between the producer
//! and this wallet relays the envelope verbatim as a single `reference`
//! argument instead of re-emitting kilobytes of calldata. Three artifact
//! kinds travel this way: execution plans, read-call bundles (exact
//! `wallet_batch_eth_call` argument bodies), and curated token lists. This
//! wallet fetches the body
//! itself, transparently decompresses standard HTTP content encodings,
//! verifies the digest and byte count over the resulting canonical JSON, and
//! then parses and validates it exactly as it would an inline one; a fetched body earns no extra trust
//! from having a URL, and an inline body is still expressible as a `data:`
//! URI that never touches the network — there the bytes are the reference,
//! so integrity is verified only when supplied.
//!
//! The `https` fetches are this process's only outbound requests that are not
//! a configured chain RPC, so admission is deliberately narrow: `https` on the
//! default port to a public, resolvable host; no credentials, fragments,
//! redirects, or private/internal addresses; a hard response-size cap; and
//! errors that describe the failure without echoing a byte of the response
//! body.
//!
//! One transport takes no envelope at all: [`fetch_token_list_url`] imports a
//! curated token list from the bare `https` URL its curator publishes it at,
//! which is how tokenlists.org lists are distributed and the only way an owner
//! can set up a list nobody wrapped for them. It is the single exception to
//! the digest rule, it is confined to token lists, and it runs through the
//! identical admission policy — the reasoning for why a list can afford it,
//! and what it does and does not widen, is on that function.

use crate::core::execution_plan::{ExecutionPlan, MAX_SERIALIZED_PLAN_BYTES};
use alloy::primitives::keccak256;
use anyhow::{Context, Result, anyhow, bail, ensure};
use base64::Engine as _;
use percent_encoding::percent_decode_str;
use schemars::JsonSchema;
use serde::Deserialize;
use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::sync::LazyLock;
use std::time::Duration;
use url::{Host, Url};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const TOTAL_TIMEOUT: Duration = Duration::from_secs(15);

/// Caller-named outbound fetches this process performs at once.
///
/// Every one of them resolves a name, opens a TLS connection, waits through
/// multi-second timeouts, and accumulates up to the artifact's body cap. An
/// MCP client that could start them without limit would have a wallet-shaped
/// outbound request amplifier, and would exhaust this process's tasks,
/// sockets, and resolver workers on the way.
///
/// Attached to the fetch itself rather than to a tool. `wallet_propose_network`
/// has had its own one-at-a-time limiter since it was the only tool that sent
/// a request to a URL its caller named; a token-list URL and every reference
/// body are the same thing, and putting the limit on the primitive is what
/// keeps the next one from being added without it.
///
/// Two rather than one: unlike a network probe, a person waits on these
/// several at a time — importing a couple of lists — and neither number is
/// parallelism worth having for a sweep.
const MAX_CONCURRENT_FETCHES: usize = 2;

static FETCH_SLOTS: LazyLock<tokio::sync::Semaphore> =
    LazyLock::new(|| tokio::sync::Semaphore::new(MAX_CONCURRENT_FETCHES));

/// The longest `data:` payload that could decode to a body of `max_body`.
///
/// Base64 packs three bytes into four characters and percent-encoding never
/// contracts, so nothing longer than this can decode to something the
/// after-the-decode check would accept. The same limit, measured before the
/// decode instead of after it, so no buffer is allocated for bytes the next
/// statement throws away.
const fn max_data_uri_payload_bytes(max_body: usize) -> usize {
    max_body / 3 * 4 + 4
}

/// The largest of those, for the longest artifact this wallet fetches.
const MAX_DATA_URI_PAYLOAD_BYTES: usize = max_data_uri_payload_bytes(MAX_SERIALIZED_PLAN_BYTES);

/// The longest a reference locator may be, checked before it is parsed.
///
/// A `data:` URI carrying a maximum-size body is the largest legitimate one;
/// the allowance on top covers the scheme, media type, and `;base64`. An
/// `https` URL is orders of magnitude below this.
const MAX_REFERENCE_URL_BYTES: usize = MAX_DATA_URI_PAYLOAD_BYTES + 256;

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
/// Production admits only public `https` and bounded `data:` URIs. Debug
/// builds may loosen that to plain `http` and loopback hosts for end-to-end
/// testing against a local plan producer; release builds never do.
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
}

/// Which artifact a reference names. Drives every admission and integrity
/// error's noun and refresh guidance, so a failed plan fetch and a failed
/// read-bundle fetch stay as specific as they were when plans were the only
/// referenced artifact.
#[derive(Clone, Copy, Debug, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactType {
    ExecutionPlan,
    ReadCalls,
    TokenList,
}

impl ArtifactType {
    fn noun(self) -> &'static str {
        match self {
            Self::ExecutionPlan => "execution plan",
            Self::ReadCalls => "read-call bundle",
            Self::TokenList => "token list",
        }
    }

    /// The largest body worth holding for this kind of artifact.
    ///
    /// Per type, because the reference path used to apply the execution
    /// plan's cap to everything it fetched. A token list carries its own,
    /// four times smaller, and the plain-URL import already passed it — so
    /// the identical list got a fourfold larger pre-parse budget purely by
    /// arriving in an envelope, and the parser's own check came after the
    /// whole body was already held.
    const fn max_body_bytes(self) -> usize {
        match self {
            Self::ExecutionPlan | Self::ReadCalls => MAX_SERIALIZED_PLAN_BYTES,
            Self::TokenList => crate::token_list::MAX_TOKEN_LIST_BYTES,
        }
    }

    fn wire_name(self) -> &'static str {
        match self {
            Self::ExecutionPlan => "execution_plan",
            Self::ReadCalls => "read_calls",
            Self::TokenList => "token_list",
        }
    }

    fn refresh_hint(self) -> &'static str {
        match self {
            Self::ExecutionPlan => {
                "re-run the producer's preparation tool for a fresh plan and reference"
            }
            Self::ReadCalls => "re-run the producer's tool for a fresh bundle and reference",
            Self::TokenList => "re-run the producer's tool for a fresh list and reference",
        }
    }

    fn mismatch_consequence(self) -> &'static str {
        match self {
            Self::ExecutionPlan => "it must not be simulated or signed",
            Self::ReadCalls => "its calls must not be executed",
            // A token list only ever becomes a suggestion the owner still has
            // to confirm, so the consequence is about what they would be
            // shown, not about anything that could be signed.
            Self::TokenList => "none of its names may be suggested",
        }
    }
}

/// The integrity block of a reference. Strict: an integrity object carrying
/// fields this wallet does not understand is an integrity object it cannot
/// claim to have verified.
#[derive(Clone, Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ArtifactIntegrity {
    /// Digest algorithm over the exact stored bytes. Kept a string rather
    /// than an enum so a rejection can name both what was sent and the
    /// supported set; only "keccak256" is accepted today.
    pub algorithm: String,
    /// 0x-prefixed 64-hex digest of the exact bytes served.
    pub value: String,
}

/// Producer-supplied facts about the referenced body, for sanity checks
/// before and after fetching. Additive-tolerant: fields present are
/// cross-checked, absent or unknown ones are ignored.
/// One producer `artifact_reference` envelope, accepted VERBATIM as a tool
/// argument.
///
/// The envelope itself tolerates additive fields (future producers may
/// enrich it without stranding deployed wallets) while `integrity` stays
/// strict. `integrity` and `bytes` are required whenever the body travels
/// over the network; a `data:` URI carries its bytes in the reference
/// itself, so there they are verified only when supplied.
#[derive(Clone, Debug, Deserialize, JsonSchema)]
pub struct ArtifactReference {
    /// Must be `artifact_reference`.
    pub kind: String,
    pub artifact_type: ArtifactType,
    /// Public `https` URL of the stored body or a bounded
    /// `data:application/json[;base64]` URI carrying it inline.
    pub url: String,
    #[serde(default)]
    pub integrity: Option<ArtifactIntegrity>,
    /// Exact byte length of the stored body; a fetched body of any other
    /// length is refused.
    #[serde(default)]
    pub bytes: Option<u64>,
    #[serde(default)]
    pub instruction: Option<String>,
}

/// Emit the artifact envelope inline at MCP argument sites.
///
/// Schemars normally replaces a reused struct with a bare `$ref`. Although
/// valid JSON Schema, clients that classify tool arguments without resolving
/// references can then treat this field as untyped. A schema callback on each
/// public `reference` field uses this function so the field itself says
/// `type: object` and carries the exact envelope properties.
#[must_use]
pub fn artifact_reference_object_schema(
    generator: &mut schemars::SchemaGenerator,
) -> schemars::Schema {
    ArtifactReference::json_schema(generator)
}

/// Where verified bytes came from, for provenance display at approval time.
/// The `https` host is the vetted, pinned name admission checked, so showing
/// it to the user is showing a TLS-verified fact.
///
/// Local files are deliberately absent: a path is caller-chosen text, not
/// publisher provenance, and desktop MCP clients have no filesystem transport.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ArtifactSource {
    Https { host: String },
    InlineDataUri,
}

impl fmt::Display for ArtifactSource {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Https { host } => formatter.write_str(host),
            Self::InlineDataUri => formatter.write_str("inline data URI"),
        }
    }
}

#[derive(Debug)]
pub struct FetchedArtifact {
    pub bytes: Vec<u8>,
    pub source: ArtifactSource,
}

/// Fetch, verify, parse, and validate one referenced execution plan, and
/// report where its bytes came from.
pub async fn resolve_execution_plan_reference(
    reference: &ArtifactReference,
    policy: FetchPolicy,
) -> Result<(ExecutionPlan, ArtifactSource)> {
    let fetched = fetch_reference(reference, ArtifactType::ExecutionPlan, policy).await?;
    let value: serde_json::Value =
        serde_json::from_slice(&fetched.bytes).context("execution plan body is not valid JSON")?;
    let plan = ExecutionPlan::parse(value)?;
    Ok((plan, fetched.source))
}

/// Fetch, verify, and parse one referenced token list, and report where its
/// bytes came from.
///
/// A token list earns no trust from having been fetched rather than typed:
/// what comes back is a set of suggestions the owner still confirms one list
/// at a time in the desktop Tokens review screen. Verifying the digest only
/// establishes that the bytes are the ones the producer published, which is
/// the same thing it establishes for a plan.
pub async fn resolve_token_list_reference(
    reference: &ArtifactReference,
    policy: FetchPolicy,
) -> Result<(crate::token_list::ParsedTokenList, ArtifactSource)> {
    let fetched = fetch_reference(reference, ArtifactType::TokenList, policy).await?;
    let list = crate::token_list::parse_token_list(&fetched.bytes)?;
    Ok((list, fetched.source))
}

/// Fetch and parse a curated token list published at a plain `https` URL, and
/// report the host that served it.
///
/// This is how tokenlists.org lists are actually distributed: a list lives at
/// a well-known URL its curator updates in place — `https://tokens.uniswap.org`
/// is the canonical example — and whoever points a wallet at one holds no
/// digest for what it says today. Requiring an envelope here would mean the
/// only importable lists are the ones some producer had already wrapped, which
/// is precisely the set an owner setting up their own lists is not choosing
/// from. So this is the one artifact fetched without an integrity block, and
/// it is confined to token lists.
///
/// What makes the missing digest affordable is what a token list can do. A
/// plan reference names bytes that get simulated and signed, so its digest is
/// the only thing tying what the owner reviewed to what executes. A list names
/// nothing: every entry becomes a suggestion that waits for the owner in
/// the desktop Tokens review screen, and their review is the check the digest would
/// otherwise stand in for. A digest would also be answering the wrong
/// question — it proves the bytes are the ones the *caller* described, while
/// what the owner is deciding is whether the curator is worth trusting, which
/// no hash can tell them.
///
/// The host is returned with the entries because it is the only fact about
/// the list that was proved rather than asserted. TLS establishes it, the
/// caller cannot choose it without controlling the name, and it is what the
/// owner is shown at review time in place of a label the agent picked.
///
/// The exposure this does add is that a caller can make this process fetch a
/// public URL it chose and hear back what parsed. Admission is unchanged and
/// does the containing: `https` only, default port, no credentials, no
/// redirects, and no host resolving to a private or reserved address — so what
/// is reachable this way is reachable from anywhere on the internet, and the
/// wallet's network position buys the caller nothing. The reply is entry
/// counts and token rows, never the response body.
/// Only the entries on `chain_ids` are kept, or every entry when it is empty.
/// The filter belongs here rather than at the call site because a published
/// multi-chain list is routinely larger than the review budget for any one
/// import of it, and selecting before that budget is charged is what lets an
/// owner take the part of such a list they actually wanted.
pub async fn fetch_token_list_url(
    url: &str,
    chain_ids: &[u64],
    policy: FetchPolicy,
) -> Result<(crate::token_list::ParsedTokenList, String)> {
    let (body, host) = fetch_remote(
        url,
        policy,
        ArtifactType::TokenList,
        crate::token_list::MAX_TOKEN_LIST_BYTES,
    )
    .await?;
    let list = crate::token_list::parse_token_list_for_chains(&body, chain_ids)?;
    Ok((list, host))
}

/// Fetch one referenced body — remote `https` or local `data:` URI — and
/// verify it against the digest and byte count its producer published,
/// without interpreting the bytes. HTTP content encoding is a transport
/// detail: reqwest decompresses it first, the body cap is enforced on those
/// decompressed bytes, and both integrity fields describe those same bytes.
/// Callers parse and validate the result exactly as they would an inline body.
pub async fn fetch_reference(
    reference: &ArtifactReference,
    expected_type: ArtifactType,
    policy: FetchPolicy,
) -> Result<FetchedArtifact> {
    let noun = expected_type.noun();
    ensure!(
        reference.kind == "artifact_reference",
        "the reference's kind is {:?}, not \"artifact_reference\"",
        reference.kind
    );
    // Bound the locator before anything looks at it. The largest legitimate
    // one is a `data:` URI carrying a maximum-size body, and a short prefix
    // covers the scheme and media type; an `https` URL is far below that. The
    // decoder's own limit is downstream of splitting and base64-decoding the
    // string, so it bounded the body rather than the reference.
    ensure!(
        reference.url.len() <= MAX_REFERENCE_URL_BYTES,
        "{noun} reference URL exceeds {MAX_REFERENCE_URL_BYTES} bytes"
    );
    ensure!(
        reference.artifact_type == expected_type,
        "this tool takes an artifact_type \"{}\" reference, but this reference is \"{}\"",
        expected_type.wire_name(),
        reference.artifact_type.wire_name(),
    );
    if let Some(integrity) = &reference.integrity {
        ensure!(
            integrity.algorithm == "keccak256",
            "integrity algorithm {:?} is not supported; this wallet verifies keccak256",
            integrity.algorithm
        );
    }
    let max_bytes = expected_type.max_body_bytes();
    if let Some(bytes) = reference.bytes {
        // Refuse before allocating or fetching anything oversized.
        ensure!(
            bytes <= max_bytes as u64,
            "{noun} reference promises a body over {max_bytes} bytes"
        );
    }

    let (body, source) = if reference.url.starts_with("data:") {
        (
            decode_data_uri(&reference.url, expected_type)?,
            ArtifactSource::InlineDataUri,
        )
    } else {
        // A body that travels over the network must be verifiable: the
        // silent skip-verification path of the old optional digest is gone.
        require_verifiable(reference, noun, "fetched over the network", "")?;
        let (bytes, host) = fetch_remote(&reference.url, policy, expected_type, max_bytes).await?;
        (bytes, ArtifactSource::Https { host })
    };

    if let Some(expected_bytes) = reference.bytes {
        ensure!(
            body.len() as u64 == expected_bytes,
            "the reference promised {expected_bytes} bytes but the {noun} body is {} bytes; \
             the artifact was altered or truncated",
            body.len()
        );
    }
    if let Some(integrity) = &reference.integrity {
        verify_digest(&body, &integrity.value, expected_type)?;
    }
    Ok(FetchedArtifact {
        bytes: body,
        source,
    })
}

/// Both facts a body living outside its own reference must come with before
/// it is worth reading: what it should hash to, and how long it should be.
fn require_verifiable(
    reference: &ArtifactReference,
    noun: &str,
    how: &str,
    hint: &str,
) -> Result<()> {
    ensure!(
        reference.integrity.is_some(),
        "{noun} references {how} must carry an integrity block{hint}"
    );
    ensure!(
        reference.bytes.is_some(),
        "{noun} references {how} must carry their exact byte count{hint}"
    );
    Ok(())
}

/// Decode `data:application/json[;base64],…` without touching the network.
fn decode_data_uri(url: &str, artifact_type: ArtifactType) -> Result<Vec<u8>> {
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
    let noun = artifact_type.noun();
    let max_bytes = artifact_type.max_body_bytes();
    // Checked before the decode, not after it. Neither encoding can contract:
    // base64 packs three bytes into four characters and percent-encoding only
    // ever expands, so a payload longer than this cannot decode to anything
    // the check below would accept. Refusing on the encoded length keeps the
    // process from allocating a buffer for bytes the next statement throws
    // away.
    ensure!(
        payload.len() <= max_data_uri_payload_bytes(max_bytes),
        "{noun} body exceeds {max_bytes} bytes"
    );
    let bytes = if base64_payload {
        base64::engine::general_purpose::STANDARD
            .decode(payload)
            .context("data: URI payload is not valid standard base64")?
    } else {
        percent_decode_str(payload).collect()
    };
    ensure!(
        bytes.len() <= max_bytes,
        "{noun} body exceeds {max_bytes} bytes"
    );
    Ok(bytes)
}

// The suffix checks run on an already-lowercased copy of the hostname; the
// lint pattern-matches them as file-extension comparisons, which they are not.
#[allow(clippy::case_sensitive_file_extension_comparisons)]
async fn fetch_remote(
    url: &str,
    policy: FetchPolicy,
    artifact_type: ArtifactType,
    max_bytes: usize,
) -> Result<(Vec<u8>, String)> {
    let noun = artifact_type.noun();
    // Held for the whole fetch: the resolve, the connect, and the read are all
    // work a caller can ask for, and none of them is bounded by anything else.
    let _permit = FETCH_SLOTS
        .acquire()
        .await
        .context("the outbound fetch limiter was closed")?;
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

    let mut sorted_addrs = resolved;
    sorted_addrs.sort_unstable();
    let client = pinned_client(PinnedKey {
        host: host_text.clone(),
        port,
        addrs: sorted_addrs,
    })?;
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
            artifact_type.refresh_hint()
        );
    }
    ensure!(status.is_success(), "{noun} fetch returned HTTP {status}");
    if let Some(length) = response.content_length() {
        ensure!(
            length <= max_bytes as u64,
            "{noun} body exceeds {max_bytes} bytes"
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
            body.len() + chunk.len() <= max_bytes,
            "{noun} body exceeds {max_bytes} bytes"
        );
        body.extend_from_slice(&chunk);
    }
    Ok((body, host_text.to_ascii_lowercase()))
}

/// A vetted connection identity: the admission decision and the pooled
/// client are keyed on the same bytes, so a resolver answering differently
/// later produces a different key rather than reusing a stale pin.
#[derive(Clone, PartialEq, Eq)]
struct PinnedKey {
    host: String,
    port: u16,
    addrs: Vec<SocketAddr>,
}

/// Clients pooled per vetted (host, port, resolved-addrs) identity.
/// Simulate-then-send fetches the same reference seconds apart; reusing the
/// pooled TLS connection avoids paying connector construction and a fresh
/// handshake twice. Bounded so a hostile sequence of hosts cannot grow
/// memory; eviction is oldest-first. Resolution and vetting still run on
/// every fetch — only the vetted result is reused.
static PINNED_CLIENTS: std::sync::OnceLock<std::sync::Mutex<Vec<(PinnedKey, reqwest::Client)>>> =
    std::sync::OnceLock::new();
const MAX_PINNED_CLIENTS: usize = 8;

fn pinned_client(key: PinnedKey) -> Result<reqwest::Client> {
    let pool = PINNED_CLIENTS.get_or_init(|| std::sync::Mutex::new(Vec::new()));
    let mut entries = pool.lock().expect("pinned-client pool lock");
    if let Some(position) = entries.iter().position(|(existing, _)| *existing == key) {
        return Ok(entries[position].1.clone());
    }
    let client = reqwest::Client::builder()
        // Reference integrity is over canonical JSON, not its wire encoding.
        // Advertising and decoding the standard encodings here means every
        // downstream size and digest check sees that canonical representation.
        .gzip(true)
        .brotli(true)
        .zstd(true)
        .deflate(true)
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
        .resolve_to_addrs(&key.host, &key.addrs)
        .build()
        .context("could not build the reference fetch client")?;
    if entries.len() >= MAX_PINNED_CLIENTS {
        entries.remove(0);
    }
    entries.push((key, client.clone()));
    Ok(client)
}

/// Check a caller-supplied or remotely hosted body against its promised
/// digest, naming both sides when they differ. Local files use
/// [`digest_check`] and the combined, non-disclosing verification above.
fn verify_digest(bytes: &[u8], expected: &str, artifact_type: ArtifactType) -> Result<()> {
    let (matched, actual, normalized) = digest_check(bytes, expected)?;
    ensure!(
        matched,
        "fetched {} bytes hash to 0x{actual} but the reference promised 0x{normalized}; \
         the body was altered or the reference is stale, so {}",
        artifact_type.noun(),
        artifact_type.mismatch_consequence()
    );
    Ok(())
}

/// Validate one promised digest and compare it without deciding how much of
/// the answer its caller may disclose.
fn digest_check(bytes: &[u8], expected: &str) -> Result<(bool, String, String)> {
    let normalized = expected.strip_prefix("0x").unwrap_or(expected);
    ensure!(
        normalized.len() == 64 && normalized.bytes().all(|byte| byte.is_ascii_hexdigit()),
        "integrity.value must be a 32-byte hex keccak256 digest"
    );
    let actual = format!("{:x}", keccak256(bytes));
    let normalized = normalized.to_ascii_lowercase();
    Ok((actual == normalized, actual, normalized))
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

/// How many name resolutions may be outstanding at once.
///
/// `RESOLVE_TIMEOUT` bounds how long a *caller* waits. It does not bound the
/// resolution: `lookup_host` does its work on the blocking pool, and cancelling
/// the future that awaits it does not stop the platform stub resolver from
/// retrying across its nameservers. So a caller who names a host served by a
/// dead resolver used to be released after five seconds -- returning its
/// admission slot to the next caller -- while the thread it started stayed
/// stuck for tens of seconds. Repeat that and the admission limit is
/// satisfied at every moment while the blocking pool fills with work nobody
/// is waiting for.
///
/// This bounds the thing that actually accumulates. A permit is held by the
/// resolution rather than by the caller, so it comes back when the resolver
/// finishes, not when the caller gives up.
const MAX_CONCURRENT_RESOLUTIONS: usize = 16;

static RESOLVER_SLOTS: LazyLock<std::sync::Arc<tokio::sync::Semaphore>> =
    LazyLock::new(|| std::sync::Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_RESOLUTIONS)));

async fn resolve_with_deadline(host: &str, port: u16, noun: &str) -> Result<Vec<SocketAddr>> {
    let permit = RESOLVER_SLOTS
        .clone()
        .acquire_owned()
        .await
        .map_err(|_| anyhow!("the resolver slot pool was closed"))?;
    let host = host.to_owned();
    // Spawned, and its handle deliberately dropped on timeout. A dropped
    // `JoinHandle` detaches rather than aborting, so the task -- and the permit
    // it holds -- outlives the caller's patience by exactly as long as the
    // resolver takes. That is the point: the slot is returned when the work
    // ends.
    let lookup = tokio::spawn(async move {
        let _permit = permit;
        tokio::net::lookup_host((host.as_str(), port))
            .await
            .map(std::iter::Iterator::collect::<Vec<SocketAddr>>)
    });
    let resolved: Vec<SocketAddr> = tokio::time::timeout(RESOLVE_TIMEOUT, lookup)
        .await
        .with_context(|| format!("{noun} host did not resolve within {RESOLVE_TIMEOUT:?}"))?
        .with_context(|| format!("{noun} host resolution did not complete"))?
        .with_context(|| format!("{noun} host did not resolve"))?;
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
    let _ = public_endpoint_addresses(url, noun).await?;
    Ok(())
}

/// Resolve a domain-backed endpoint once and return only the addresses it is
/// safe to pin into an HTTP client. Keeping the addresses is what closes the
/// gap between admission-time DNS and the later connection.
pub(crate) async fn public_endpoint_addresses(url: &Url, noun: &str) -> Result<Vec<SocketAddr>> {
    let host = url.host().with_context(|| format!("{noun} has no host"))?;
    let host_text = vetted_host(&host, false, noun)?;
    let port = url.port_or_known_default().unwrap_or(443);
    let resolved = resolve_with_deadline(&host_text, port, noun).await?;
    ensure!(
        resolved.iter().all(|address| is_public_ip(address.ip())),
        "{noun} resolves to a private or reserved address"
    );
    Ok(resolved)
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
                // fec0::/10 site local. Deprecated by RFC 3879 and replaced by
                // the unique-local range above, but deprecation is not
                // unreachability: a stack still routes it, and a network
                // numbered before 2004 still answers on it.
                || (segments[0] & 0xffc0) == 0xfec0
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
                // 2001:10::/28 ORCHID and 2001:20::/28 ORCHIDv2. Adjacent but
                // not one aligned block, so they are two masks rather than a
                // wider one that would also swallow 2001:0::/28.
                || (segments[0] == 0x2001
                    && ((segments[1] & 0xfff0) == 0x0010 || (segments[1] & 0xfff0) == 0x0020))
                // 2002::/16 6to4, whose next 32 bits are an embedded IPv4
                || segments[0] == 0x2002
                // 2001:db8::/32 documentation
                || (segments[0] == 0x2001 && segments[1] == 0x0db8))
        }
    }
}

#[cfg(test)]
#[path = "plan_fetch_test.rs"]
mod tests;
