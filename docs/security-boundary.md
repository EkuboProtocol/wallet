# Security boundary

The MCP client, model output, configured RPC, and local files are treated as
untrusted. Before normal signing, the process resolves the plan from the
caller-named URL, validates it, simulates its exact target/value/calldata,
evaluates the active encrypted policy, resolves nonce/fees, loads the key,
signs locally, validates the recovered sender and complete envelope, and
durably stores the bytes and hash before broadcasting.

Resolving a plan by URL is the one outbound request that is neither a
configured chain RPC nor a fixed endpoint compiled into the release — the
WalletConnect relay and the release check in `release_check` are the fixed
ones, and neither takes a URL from a caller — and this URL is
caller-controlled, so its admission is narrow:
`https` on the default port to a public host; no credentials, fragments, or
redirects; every resolved address must be globally routable and the connection
is pinned to the vetted set, so a rebinding resolver cannot swap targets
between the check and the connect; responses are capped at 16 MiB; and error
paths report status and size without echoing a byte of the body, so this
wallet cannot be used to exfiltrate what an internal endpoint returns. The
fetched bytes are checked against the caller-supplied keccak256 digest when
one is given, and the result is parsed and validated identically to an inline
plan — a URL grants no trust. `data:` URIs decode locally and touch no
network. `file:` URLs read this machine's disk, for bodies an agent assembled
rather than received; there the digest and byte count are mandatory, and
because naming a body requires already holding its bytes — and because a
mismatch reports neither the file's real length nor its computed digest — the
read tells its caller nothing about a file it did not write beyond whether
the path could be opened.

Exceptional signing has an additional boundary: the CLI re-simulates, prepares
the exact nonce/gas/fees/delegation without loading the key, shows those fields,
authenticates the owner against the OS, rechecks configuration and policy, and
signs the prepared object without another RPC lookup.

EIP-712 typed data never reaches the policy at all. Every payload, including a
recognized permit, queues in the encrypted database for CLI review, which
displays the complete payload, requires terminal approval plus OS owner
authentication, and only then signs. Recognized permits (ERC-2612, DAI, and
canonical Permit2, matched by their complete type encodings) are still decoded
into the token approvals signing would grant, but only so the reviewer can read
them.

A policy cannot bound a signature the way it bounds a transaction. A permit is
consumed once, so a rule that authorizes one permit under a limit authorizes an
unbounded series of them under that same limit, each individually within
policy, and the spender chooses when to redeem each one. There is no
per-transaction ceiling to apply, and the wallet holds no counters to apply one
with. That is why signing has no automatic path.

EIP-191 `personal_sign` messages queue the same way, for the additional reason
that no policy could even score what a message signature authorizes. The CLI
prints the exact bytes as hex beside their text, escapes control characters,
terminal escape sequences, and Unicode bidirectional overrides so the message
cannot repaint or reorder the screen reviewing it, and parses recognized
ERC-4361 sign-in messages into labeled fields with warnings for an unconfigured
or disagreeing chain, an expired or post-dated login, a domain that disagrees
with its own URI, and any listed resources. A sign-in message naming an account
other than the signing wallet is refused outright, and legacy raw `eth_sign`
over a bare 32-byte digest is refused because no approval screen can describe
it honestly. A message signature binds no chain, so a `chain_id` sent with one
is displayed as the requester's claim.

## Why keys live in the credential store, and why nothing guards them

Private keys are the one secret that never enters the encrypted database. They
are stored as individual OS credential-store entries under
`org.ekubo.wallet.private-key.v1`, keyed by wallet ID, and the database's own
key is a separate entry. Two secrets rather than one buys something specific:
the data directory stops being key-bearing. It gets into backups, synced
folders, snapshots, and bug reports, and none of those copies can yield a key
no matter what else leaks — which matters because the database key is fetched
by nearly every command, while a private key is read only to sign. The
credential store also applies per-item access control the operating system
enforces, which a SQLCipher page cannot: once its key is in memory, the file's
protection is over.

What this does not do is stop an attacker already running code as you. Both
secrets sit in the same credential store behind the same login, so anything
that can read one can generally read the other. The protection is against
secrets at rest leaving the machine, not against a compromised session.

The obvious hardening — marking the key entry as requiring biometric or
passcode presence, so the OS refuses to release it without a live human — is
deliberately not applied, and will not be. This wallet exists so an agent can
pursue long-running goals unattended, including in loops; a key that cannot be
read without a fingerprint is a key that cannot sign at 3am. Presence
enforcement would make exactly the automatic path impossible. `wallet_send_execution_plan`
therefore performs no presence check at all on the automatic path.

So the boundary that actually contains an autonomous agent is the policy, not
key custody. What bounds a compromised or misled agent is what the policy
permits — the targets, the values, the call shapes — because once the policy
allows an action, nothing further stands between the request and a signature.
Owner authentication guards the exceptional path, where a human is present by
definition, along with key export, wallet removal — and policy replacement,
precisely because the policy is that boundary: rewriting it changes what an
agent can sign unattended, so it is authenticated like signing even though it
reads no key material.

It is also asked for before stored metadata changes — address-book aliases and
token names — which grant no signing authority at all. That looks like an
exception to the rule and is really the rule read properly: those rows are what
the owner reads when they decide, and an attacker who cannot widen the policy
can still change the sentence being decided on. An alias turns an address into
a familiar name; a token row turns base units into an amount. Both are supplied
by an untrusted agent as a *proposal*, and both take a terminal confirmation
and an OS presence check to become a name. Rejecting takes neither, so nobody
is trained to authenticate their way past a prompt.

Network profiles work the same way and matter most: the RPC endpoint in one is
the wallet's entire view of its chain, so accepting a profile is a statement
about who is trusted to describe reality. `wallet_propose_network` queues it;
`ekubo-wallet review` shows which endpoint would be replaced, verifies
the chain ID, and takes the presence check before writing.

Owner authentication is in any case an application-level check in the CLI, not
an operating-system gate on the key. Choose a wallet's policy on that basis,
and keep autonomous wallets funded accordingly.

## What the crate split enforces in-process

Because that check is application-level, it is worth being precise about what
holds it up. The workspace is two crates: `ekubo-wallet-core` is the security
kernel, and the `ekubo-wallet` binary above it is presentation — CLI, TUI, MCP
server, WalletConnect. The split is not a naming convention. Four things about
it are enforced by the compiler:

- **No signer leaves the kernel.** `PrivateKeyMaterial::signer`, `expose_hex`,
  and `load_matching_signer` are `pub(crate)`. Presentation code can hold a
  `PrivateKeyMaterial` and learn its `address`, and that is all: a signer signs
  any 32 bytes with no policy and no authentication, so obtaining one is
  obtaining the wallet. Every signature in the process is therefore minted by
  a function in `orchestrator`.
- **No presence backend is supplied from outside.** `HumanPresence` is sealed
  by a kernel-private marker trait. Presentation code passes one *in*, so
  without the seal it could pass an implementation whose `confirm` returns
  `Ok(())` — not a weak owner check but the absence of every owner check in the
  process, since each one is a single `confirm` call. `KeyStore` is sealed the
  same way.
- **No arbitrary SQL.** `PolicyStore`'s connection is `pub(crate)`, the
  database key loader is private, and the binary crate does not depend on
  `rusqlite` at all — so storage is reachable only through the kernel's typed
  methods, and not by accident even in principle.
- **No raw transaction construction.** `sign_prepared` is private, so a
  transaction cannot be signed around the policy and simulation ladder.

Two further layers catch erosion rather than attack. Clippy's
`disallowed_methods` and `disallowed_types` — denied, not warned, in
`Cargo.toml` and configured in `clippy.toml` — fail the build if presentation
code names a custody symbol, so widening one of those `pub(crate)`s to `pub`
stops being a silent one-word change. `tests/boundary.rs` pins the
declarations, the bans, and the seals themselves.

What none of this does is defend against someone who can change the code:
they can edit the kernel as easily as the presentation layer. The guarantee is
narrower and still worth having — that no reviewer, refactor, or new MCP tool
reaches key material *by accident*, and that an auditor establishes what can
sign by reading one crate. Every MCP tool body, for instance, holds an
`Arc<dyn KeyStore>`; what stops it exfiltrating a key is that there is no
method it can call to read one.

SQLCipher protects confidentiality and page integrity, but there is no external
anti-rollback anchor. Restoring an older valid encrypted database can restore
an older policy or an already-signed pending record. See
[the threat model](threat-model.md) and
[architecture](architecture.md) for the precise guarantees and residual
risks, and [approval UX](approval-ux.md) for the actual approval flow.
