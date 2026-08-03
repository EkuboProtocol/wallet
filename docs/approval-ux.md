# Approval UX architecture

Approval is a security protocol with multiple presentations, not a boolean
supplied by an MCP client. Terminal, local-browser, and MCP Apps experiences all
review the same server-authored immutable request.

## User experience goals

- Make the default path easy to understand without teaching users wallet or MCP
  internals.
- Show what will happen, not just what method will be called.
- Keep model-readable results useful when a client cannot render custom UI.
- Default to rejection and make cancellation harmless.
- Never mix interactive decoration with JSON or secret output on stdout.
- Preserve a final OS-controlled human-presence step for consequential
  exceptions, policy changes, key export, and removal.

## Shared approval request

The core owns a versioned `ApprovalRequest` containing:

- random request ID and expiry;
- operation kind;
- wallet and derived address;
- chain ID and network name;
- server-normalized execution plan;
- transaction fields and complete digest;
- decoded calls, native value, token transfers, and approvals;
- fee and nonce bounds;
- simulation block, material state changes, and warnings;
- active policy revision/digest and findings; and
- the exact reservation made against policy limits.

The presenter cannot replace those fields. Approval submits only the pending ID,
the expected digest, and a one-time capability. The core reloads the immutable
record, verifies authenticated policy state, consumes the capability atomically,
performs OS human presence when required, and only then signs.

## State machine

```text
requested
   │ parse, normalize, simulate, evaluate, reserve
   ▼
pending_review ── timeout/reject ──▶ rejected_or_expired
   │ exact digest + one-time capability
   ▼
owner_presence ── deny/fail ───────▶ rejected
   │
   ▼
approved ── consume once ──▶ signing ──▶ broadcast_or_recorded_failure
```

No transition returns to `pending_review`, and an approval cannot be reused for
a reconstructed transaction. A changed nonce, fee, calldata, recipient, value,
simulation, or policy revision creates a new request and digest.

## Direct CLI

`clap` remains the argument parser and stable scripting interface. `cliclack`
provides passwords, confirmation, notes, warnings, progress, cancellation, and
theme support for interactive commands.

The terminal presenter:

- requires real stdin, stdout, and stderr terminals;
- writes prompts and status to stderr;
- sanitizes control characters before rendering untrusted labels or metadata;
- selects **No** by default;
- clearly distinguishes policy approval from OS owner authentication; and
- leaves raw exported key material as the only stdout payload of export.

An exact typed phrase is not the primary security boundary. A clear default-no
review followed by native owner authentication gives a better experience while
preserving the actual human-presence control.

## Ephemeral loopback browser

For MCP hosts without component UI, the core may start a review server for one
request and open the system browser.

Required controls:

1. Bind only an explicit loopback address and an OS-assigned random port. Never
   bind `0.0.0.0` or a LAN interface.
2. Generate at least 256 random bits for a single-use capability. Put it in the
   URL fragment so it is not sent in the initial HTTP request, logs, or referrer;
   page JavaScript sends it only in the approval POST body or authorization
   header.
3. Serve a self-contained page with no third-party scripts, fonts, analytics,
   images, or network requests.
4. Set a strict CSP, `Referrer-Policy: no-referrer`, `Cache-Control: no-store`,
   `X-Content-Type-Options: nosniff`, and frame denial.
5. Validate `Host`, reject unexpected `Origin`/fetch metadata, mutate only on
   POST, compare capabilities in constant time, and rate limit failures.
6. Escape every rendered field. The server supplies transaction data; the URL
   and browser never supply HTML.
7. Expire quickly, accept one decision, close all listeners immediately, and
   treat browser closure as rejection after timeout.
8. After the click, invoke OS human presence in the core. Possession of a
   loopback capability alone never authorizes a required exception.

The loopback server improves presentation; it does not turn a browser session
into a trusted identity.

## ChatGPT and MCP Apps

Current OpenAI plugin guidance uses the open MCP Apps standard for optional UI.
The review component is returned as a `text/html;profile=mcp-app` resource and
linked with `_meta.ui.resourceUri`.

The model-visible prepare tool returns useful structured facts and an inline
review component. A distinct approval tool is marked with
`_meta.ui.visibility: ["app"]`, so it is callable by the component but not
advertised to the model. The one-time approval capability is returned in tool
result `_meta`, which the host delivers to the component but hides from the
model. OS human presence remains the final authority.

The component has an empty network allowlist unless a reviewed requirement is
added. It renders authoritative server results, treats all text as untrusted,
does not use browser storage as durable state, and remains usable through a
concise model-readable fallback.

Relevant primary documentation:

- [OpenAI: Add UI to your MCP server](https://developers.openai.com/plugins/build/chatgpt-ui)
- [OpenAI plugin reference](https://developers.openai.com/plugins/reference)
- [OpenAI security and privacy](https://developers.openai.com/plugins/guides/security-privacy)
- [OpenAI Secure MCP Tunnel](https://developers.openai.com/api/docs/guides/secure-mcp-tunnels)

For a private local wallet, Secure MCP Tunnel can connect ChatGPT developer
mode to the stdio server without public inbound access. Public plugin submission
requires a stable public HTTPS MCP endpoint and is not equivalent to this local
custody design. A public product would need a separately threat-modeled broker
or pairing architecture; it must not silently expose the local signer.

## Presentation order

The preferred transaction review order is:

1. Plain-language action and severity.
2. Wallet, chain, recipient/contract, and full address.
3. Assets leaving and minimum assets expected back.
4. New or changed token approvals.
5. Fees, nonce, expiry, and slippage/deadline bounds.
6. Simulation result and material state changes.
7. Policy revision, limits consumed, exceptions, and warnings.
8. Advanced raw calldata, selector, complete digest, and request ID.

Addresses are never shown only in truncated form. Human-friendly labels are
supplemental and cannot replace canonical identifiers.

## Failure behavior

- Unsupported UI: return the pending ID and direct CLI review instructions.
- Presenter crash or disconnect: keep the request pending only until its short
  expiry, then release its reservation through an authenticated event.
- OS presence denial: reject and consume the approval capability.
- Policy or simulation changes while pending: invalidate the request and require
  a new review.
- Browser or component reports different transaction facts: ignore them and
  reject a digest mismatch.
