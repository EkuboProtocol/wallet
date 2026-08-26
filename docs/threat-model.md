# Desktop wallet threat model

This document describes the current desktop wallet. `docs/security-boundary.md`
provides the companion code-oriented boundary map.

## Assets and trust boundaries

Protected assets include private keys, signed transactions and messages, owner
policy, network and token metadata, installed automation definitions and run
history, update authority, and privacy-sensitive settings. Wallet authority and
persistent executable intent live in SQLCipher or the OS credential store;
plaintext configuration files are not wallet authority.

`ekubo-wallet-core` is the security kernel. GPUI, MCP agents, dapps, RPC
servers, relays, token lists, update hosting, clipboard contents, imported
files, automation bytecode and configuration, and the harness-reported client
kind are untrusted. Agent input is assumed prompt-injected and hostile. OS
human-presence services, release signing keys, and pinned dependencies are
trusted within their documented purposes. Platform credential storage is
trusted for at-rest encryption and ordinary availability, but not uniformly
for application isolation from another process running as the desktop user.

An unlocked-window attacker may automate GPUI but cannot satisfy a fresh OS
human-presence challenge. A same-user process using public filesystem, IPC, or
credential-store APIs is in scope; it can access the local MCP IPC by design
and can deny service. Debugger/injection access, a compromised loaded
dependency or OS, and control of the wallet process are out of scope.

## Critical Windows and Linux credential-store limitation

The current `keyring` crate's default `v1` feature persists both the SQLCipher
database key and raw account private keys in the macOS User keychain, Windows
generic Credential Manager, or the Linux Secret Service default collection.
The service and account strings are lookup identifiers, not application
authorization.

On Windows, Microsoft documents that
[generic credentials can be read and written by user processes](https://learn.microsoft.com/en-us/windows/win32/secauthn/kinds-of-credentials).
The [Secret Service specification](https://specifications.freedesktop.org/secret-service/latest/ch10.html)
does not mandate access control, and GNOME states that
[any application with the same user's privileges can read secrets in an unlocked keyring](https://wiki.gnome.org/Projects%282f%29GnomeKeyring%282f%29SecurityFAQ.html).
Ekubo Wallet does not establish or verify a stronger application-specific
control on either platform.

Consequently, same-user malware on Windows or Linux can query the credential
service for the database key and raw account keys without owner presence. A
prompt-injected agent or harness with permission to execute shell commands or
programs as the desktop user has the same capability. This attack does not use
the wallet MCP API: it bypasses the wallet process entirely, creates an
external signer, and defeats wallet policy, native review, and wallet audit
records. Closing Ekubo Wallet does not remove the persistent credentials.
SQLCipher continues to protect a copied database when its unwrap key is
unavailable, and the credential services protect against other OS users and
offline disk access; neither is a same-user application-isolation boundary.

The current macOS backend uses Keychain item access controls. Apple documents
that the [creating application is automatically trusted and item access is
tracked by its code-signing requirement](https://developer.apple.com/library/archive/documentation/Security/Conceptual/CodeSigningGuide/AboutCS/AboutCS.html).
That is a materially stronger application boundary, but it does not protect a
compromised wallet process, signing identity, authenticated owner session, or
operating system.

This Windows and Linux behavior is an open critical boundary failure, not an
accepted custody guarantee; [issue #112](https://github.com/EkuboProtocol/wallet/issues/112)
tracks the required redesign. Until it is fixed, valuable Windows and Linux
accounts depend on preventing untrusted code from running as the wallet user.

## Owner authorization

Mutations that widen signing authority, add or replace trusted inputs, reveal
protected material, or reduce privacy terminate in core through narrow typed
operations. A visible dialog is not authorization. Core requests human
presence, issues a short-lived scope-bound capability, re-reads protected state
after authentication, and commits atomically. Dapp approval binds the exact
review and account. Update authorization binds publisher, version, platform,
format, canonical URL, and verified digest.

Three owner-UI operations are deliberate fail-safe reductions and do not ask
for a fresh OS challenge: a policy transition that core proves only tightens
the active policy, disabling the exact network profile that was displayed, and
removing the exact trusted-token row that was displayed. Core re-reads or
exact-matches current protected state and commits each reduction atomically.
Agents cannot invoke them. Re-enabling a network, widening or ambiguously
changing policy, and adding or replacing token metadata require owner
authentication.

On Linux the owner-authentication backend is polkit, which reads action
definitions only from root-owned `/usr/share/polkit-1/actions`. The `.deb`
installs `com.ekubo.wallet.policy` there itself. The AppImage cannot, so until
the definition is present every owner operation fails closed with one message,
and Settings → Owner authentication offers to install it: the wallet runs
`pkexec install` on the bundled copy under polkit's own always-present
`org.freedesktop.policykit.exec` action, which is `auth_admin` and prompts
through the session's authentication agent. The wallet process holds no
privilege before, during, or after; it compares the bundled file's bytes to the
copy compiled into the build before asking, and the only thing that runs as
root is coreutils `install(1)` on that file. A same-user attacker who can
already replace the AppImage or ptrace the process gains nothing new from this
path that they could not get by running `pkexec` themselves, which is the
boundary the
[credential-store limitation](#critical-windows-and-linux-credential-store-limitation)
already describes. When no agent can prompt, the pane shows the equivalent
`sudo install` command instead of falling back to weaker authorization.

## Local MCP IPC

Harnesses spawn a minimal stdio bridge which survives wallet downtime and
connects to the singleton through same-user local IPC. Unix uses a `0600`
socket in the wallet's `0700` data directory and rejects a foreign UID. Windows
uses a current-user-only named-pipe DACL and rejects a foreign peer SID. Native
package signatures establish distribution integrity and do not authorize IPC.

Each bridge connection creates a fresh restricted MCP server and session UUID.
Only `AgentApi`, not `OwnerApi`, crosses the IPC boundary. It constructs a
server with typed SQLCipher-backed stores and a narrow core execution authority
so tools can persist requests and request only guarded automatic execution or
exact cancellation. The MCP server never receives a directly callable
`KeyStore`, arbitrary signature operation, owner authorization, raw key export,
native-review decisions, unrestricted storage, or owner-only mutation
capabilities; the core authority privately owns the key-store dependency behind
its two guarded methods.

Harness kind is the `--client` argument the bridge passed. It drives activity
attribution and, since the plan source matcher, a policy rule may also name it
through `source.agent.client`. It remains untrusted: a same-user process is in
scope and can pass any harness name, so such a rule separates one honest
harness from another rather than excluding a hostile one. Because naming a
source only ever shrinks what a rule matches, a harness claim can restrict a
permission and can never create one. Attribution cannot fail the request it
describes: it is written after the request is stored, and for an automatic
send after signing, so a storage refusal leaves the row unlabelled rather
than reporting completed work as an error. The local stack has no HTTP or
OAuth surface.
Managed configurations contain only the installed helper command with a fixed
`--client` argument and, where that file format supports remote MCP, the
independent hosted companion URL. Claude Desktop keeps the remote companion in
its account-level custom connectors instead of `claude_desktop_config.json`.

## WalletConnect and dapps

Pairing URIs and relay traffic are untrusted. Pairing and session keys are
separate; a settled session accepts only approved accounts, chains, and
methods. Approval authenticates the exact proposal-derived review and account,
then re-reads account, network, and review state. Sessions have a fixed
seven-day deadline; incoming extension requests cannot move it.

WalletConnect transaction requests enter the same account policy engine as
local MCP requests and scheduled automations. Policy rules match calls, the
prepared transaction envelope, and the channel that delivered the plan. A rule
with no `source` matcher signs and submits the same transaction automatically
whichever connected dapp requests it.

A rule may name `walletconnect` and constrain the dapp's claimed domain, but
that domain is the URL the dapp typed about itself in its session proposal and
is attested by nothing; a dapp serving from anywhere may name any domain, so a
domain-gated rule is only as strong as the owner's care at the pairing screen.
Adding a source matcher can only shrink what a rule matches, so a claim never
widens authority. `plan_source` remains display and audit context only and is
never matched: it is a line assembled for a person and half-authored by the
requester, kept deliberately apart from the closed `request_source` structure
core builds and rules read. A dapp cannot force an
otherwise allowed transaction into review or override a deny. Personal-message
and typed-data requests always require native review. The WalletConnect adapter
receives only `DappApi`, not `OwnerApi` or a `KeyStore`; that capability can
re-read session state, queue review-only signatures, and delegate the exact
simulated plan into core's guarded execution authority.

## RPC, transactions, and policy

RPC responses, simulations, fee data, receipts, and broadcasts are untrusted.
Signing uses a server-authored review identity which changes with displayed
content. Account replacement, digests, policy, simulation, nonce, and fee
assumptions are revalidated at signing. Policy resolves each call by its first
matching allow, review, or deny rule and can authorize an all-allow prepared
transaction to use the OS-held key without a prompt. Deny dominates the
transaction, followed by review or an unmatched call. Prepared-envelope fields
come from the wallet's exact transaction preparation. A simulation ID grants
nothing: send always freshly simulates, prepares, and evaluates current policy.
Policy cannot reveal raw key
material or grant exports, settings mutation, review decisions, owner
authorization, or other owner capabilities.

An MCP sender may request native review for one transaction that policy would
otherwise allow automatically. This only adds a review: it cannot approve a
request, remove a policy-required review, or make a denied transaction
sendable. It does let a hostile local client create owner interruptions, just
as it can already do by submitting unmatched or review-matched plans. After the
owner authenticates an approved transaction, core signs and submits those exact
bytes before closing the review; if every endpoint refuses them, the durable
row remains signed for an explicit retry rather than silently treating the
approval as completed.

RPC-reported balance changes and simulation success are not policy inputs, but
the native review displays them as expected effects to help a person decide.
They are advisory rather than authenticated chain state: a dishonest configured
endpoint can fabricate favorable effects or conceal unfavorable ones. The
exact target, calldata summary and payload, native value, transaction type,
nonce, gas and fee ceiling remain the authoritative reviewed fields, with local
clear-signing interpretations where available. Owner authentication of an RPC
profile controls who may select that input; it does not make the endpoint's
later answers truthful.

Fee liability on the automatic path is a policy question and only a policy
question. `gas_limit`, `max_fee_per_gas`, and `max_priority_fee_per_gas` are
prepared-envelope matchers, so a rule bounds `gas_limit × max_fee_per_gas`
behind a revision and an owner approval. Network profiles carry no fee or gas
ceiling: a duplicate bound in unreviewed configuration was deleted by routine
profile edits, said nothing about what an owner's transactions are worth, and
is not a property of a chain. The wallet still refuses an envelope a block
could not accept or one below intrinsic gas, which are facts rather than
preferences.

An automatic-allow rule that omits the fee matchers therefore accepts the fee
fields the selected endpoint prepared, and no bound is mandatory before signing.
That residual is accepted deliberately: it requires an endpoint the owner
configured to be dishonest and to name fees that pass simulation, which is both
unlikely and awkward to arrange, and a mandatory ceiling would refuse ordinary
transactions on every chain whose fee scale it was not written for. Owners
running automatic policies against a single public endpoint should carry the
bound as a rule; `docs/policy-authoring.md` spells it.

Atomic batches hardcode Calibur's non-upgradeable v1.1.0 implementation address
and runtime hash. Before simulation, core requires the configured endpoint to
report exactly those runtime bytes at that address, and a delegation
authorization can name only that address. This is still an RPC assertion, not
authenticated chain state: the wallet has no local consensus or `eth_getProof`
path, and it does not restrict batches to Calibur's published deployment chains.
On an owner-added network, safety therefore also depends on the real chain
having the canonical implementation at that address. A dishonest endpoint could
conceal different or absent code; different code at the delegated address could
exercise the account's durable EIP-7702 authority. Owners must independently
verify the deployment before enabling batches or automatic policy on a custom
network.

Policy limits are evaluated per call and per prepared transaction. They are not
cumulative spend budgets or rate limits. A hostile agent or installed
automation can repeat an otherwise permitted action whenever the wallet and
chain signing slot becomes free. Owners who need a lifetime or time-window
budget must encode one in on-chain state or avoid granting that action automatic
authority; a numeric matcher on one call does not cap the sum of later calls.

## Scheduled automations

An MCP agent may install, replace, or disable an automation without owner
authentication. The stored bytecode, configuration, name, key, and schedule are
hostile executable intent, not authority: each non-empty output is synthesized
into an ordinary execution plan, freshly simulated and prepared, and passed to
the same current-policy automatic execution path as an inline agent plan. The
scheduler holds `AgentExecutionAuthority`, not `OwnerApi` or an arbitrary
signing operation.

Automations are bound to the wallet instance, network, and policy revision they
name at installation. A policy revision change moves an enabled automation to
`awaiting_relink`; that stored definition cannot silently start operating under
a later policy. The owner can start it again from the desktop, and an MCP agent
can install a replacement under the same key while naming the active revision.
That does not give a live hostile agent new authority: it could already submit
the replacement's calls directly, and both routes remain bounded by the current
policy. Revision binding protects against dormant executable intent inheriting
a later policy, not against an active agent using that policy. The scheduler
re-reads wallets and enabled networks each pass, serializes sends through the
wallet-and-chain in-flight slot, skips missed ticks, bounds bytecode,
configuration, returned calls, calldata, and installed-job counts, and stops
after repeated poll failures or a failed sent transaction.

The automation poll and its RPC response grant nothing. The code runs only in
an `eth_simulateV1` state override and the returned calls are untrusted input to
the ordinary policy path. A review or unmatched result queues one diagnostic
request and disables the automation; an explicit policy deny is rejected before
any request or signature is created. The current scheduler reports that deny as
a failed pass without a run-history row and leaves the automation enabled. It
can therefore repeat RPC work and prevent later due jobs for the same wallet and
network from running in that pass. This is an availability and RPC-load
residual, not a signing bypass.

There is no application-level wallet lock state. Ticks run only while the
wallet process is running; an automatic signature also depends on the platform
credential store allowing the key to be read. Closing the process or suspending
the machine skips ticks rather than replaying them later.

## Updates and release supply chain

Update metadata and hosting are untrusted. `latest.json` and artifacts are
Minisign-verified; core checks the bundled version marker and repeats checks
immediately before installation. Platform signing precedes final updater
signing when configured. Unsigned artifacts may be built from any requested
reference. The arbitrary-source build jobs receive neither OIDC nor release
credentials; an isolated job that executes no candidate source attests the
resulting bytes. Before any credential-bearing job, every byte must have a
GitHub attestation from the exact trusted build workflow revision on `main`, and
the manifested artifact SHA and release tag must resolve to protected `main`
history. CI results are deliberately not release authority. A protected release variable
selects the Windows Authenticode mode, and the workflow proves the installer
matches the selected state before publication: a valid signature when signing is
enabled, no signature at all when it is disabled, and a failed release when the
variable says neither. The detached updater signature is required either way. Apple and enabled Windows signing services and release keys remain
trust dependencies whose compromise requires publication halt, key rotation
through a trusted channel, and an audit of released bytes and workflow logs.

The signed native package covers the separately bundled MCP helper during
distribution. The wallet atomically installs a copy at a fixed path in its
private per-user directory (`0700` on Unix), replacing it by rename on each launch whose
bytes differ, and collects the superseded images. It does not treat the
helper's hash or code signature as
authorization: any process already running as the same user can connect to the
local MCP IPC listener directly.

## Local platform and lifecycle

The platform credential-store consequences are described in
[Critical Windows and Linux credential-store limitation](#critical-windows-and-linux-credential-store-limitation).
On those platforms, closing the process stops scheduled execution but does not
remove the persistent SQLCipher or account-key credentials.

Transaction notifications default to detailed previews: their titles disclose
lifecycle state and their bodies name the local account and configured network.
They contain no request identifier or approval action. The encrypted preview
preference is security-sensitive, and changing it requires owner
authentication. Explicit Quit disconnects WalletConnect, stops local MCP IPC,
and installs only an already verified, exactly authorized update. Hiding or
closing windows does not mutate protected state.

SQLCipher authenticates pages at rest but does not provide freshness. A
same-user process able to replace the database may roll it back to an earlier
valid state. Backups therefore remain sensitive; rollback can restore old
settings or erase local audit history.

## Residual risks and response

The wallet cannot make a compromised OS, injected process, dependency,
authenticated owner session, release key, or platform signing service
trustworthy. Physical attackers able to satisfy OS authentication,
administrators controlling OS facilities, denial of service, traffic analysis,
and recovery from total host compromise are out of scope. Suspected local
compromise calls for disconnecting dapps, rotating affected wallet keys, and
rebuilding from pinned source.

Security regressions are guarded by adjacent Rust tests, IPC capability and
schema-boundary tests, action-pin checks, updater fixtures, and release
signature verification. Trust-boundary changes must update this document and
their tests together.
