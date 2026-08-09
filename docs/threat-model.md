# Threat model

Status: implemented release candidate. The listed automated checks pass in CI;
this statement is not a claim of independent security audit.

## Objective and trust boundary

An MCP client may propose a structured transaction but cannot obtain arbitrary
signatures or weaken policy. The process that reads the signing key must parse,
simulate, evaluate policy, sign, validate, persist, and broadcast the exact
transaction.

The MCP client, model-generated input, configured RPC, and filesystem are
untrusted. The wallet process and loaded code, OS credential/authentication
APIs, and explicit human input are trusted. Administrator, kernel, debugger,
malicious dependency, and arbitrary in-process code execution are out of scope.

The supported server is one `ekubo-wallet server` stdio process. There is no
privileged daemon or custom IPC. CLI management commands are local, interactive
processes and expose no generic signing primitive.

Execution plans arrive by caller-named URL, which adds one outbound request
that is not a configured chain RPC and the only SSRF-shaped surface here: the
other non-RPC requests, the WalletConnect relay and the release check, go to
endpoints compiled into the release that no caller can influence. The fetch
admits only public `https` on the default port — no credentials, fragments,
redirects, or private/reserved addresses, with every resolved address vetted
and pinned for the connection — caps the response at 16 MiB, verifies the
caller-supplied keccak256 digest over the exact fetched bytes when given, and
never echoes response bytes in an error. The fetched plan then passes the same
parse, validation, simulation, and policy path as any inline plan, so the URL
transport grants no authority; `data:` URIs decode locally with no network.

A `file:` URL is the third form, for a plan the agent assembled rather than
received, and it is a read of this machine rather than a request off it. The
caller already has that read — the transport is stdio, so it runs as the
owner — and what it does not get is the wallet reading a file on its behalf
and reporting back: the digest and byte count are mandatory, so naming a body
means already holding its bytes, the path must be a regular file so a FIFO
cannot hold the call open, and a mismatch reports neither the file's real
length nor its computed digest. The residual disclosure is whether a path
exists and opens. This assumes the transport stays stdio; a network-reachable
transport would make the caller someone other than the owner, and `file:`
would have to be reconsidered along with everything else that assumption
carries.

### Key custody, and the presence check that is deliberately absent

Private keys are individual OS credential-store entries keyed by wallet ID,
never SQLCipher rows, and the database key is a separate entry. The split is
what keeps the data directory free of key material: copies of it — backups,
syncs, snapshots, bug reports — cannot yield a key whatever else leaks, and the
database key is handled far more often than any private key, since almost every
command opens the database while only signing reads a key. It also puts the key
behind per-item access control the OS enforces, which an encrypted page cannot
once its key is resident. It does not defend against code already running as
the user: both secrets share one credential store and one login, which is why
in-process code execution is out of scope above.

The credential-store backend can mark an entry as requiring biometric or
passcode presence before release. This wallet does not use that, by design, and
the omission is load-bearing rather than pending. The product's purpose is
unattended agent operation against long-running goals, including loops; an
entry the OS will not release without a live human cannot be read at 3am, so
presence enforcement and the automatic signing path are mutually exclusive.
`wallet_send_execution_plan` accordingly performs no presence check.

The consequence is explicit: **for the automatic path, the policy is the
security boundary, and key custody is not.** Anything the policy permits is
reachable by a compromised or misled agent without a further gate, so a
wallet's exposure is bounded by what its policy allows and by what it holds.
Owner authentication (`human_presence`) covers the exceptional review path,
where a human is present by definition, and configuration mutations. It is an
application-level check in the CLI process, not an OS gate on key release, and
it is not a control against in-process execution.

## Signing invariants

1. Private keys never appear in MCP inputs/results, policies, logs, config, or
   SQLCipher rows.
2. Signing accepts a validated structured plan, never an arbitrary digest or
   caller-supplied serialized transaction. Off-chain signatures are equally
   structured: EIP-712 typed data is parsed and re-hashed locally, and EIP-191
   messages are hashed from their exact stored bytes under the `0x19` prefix.
   Legacy raw `eth_sign` over a bare unprefixed 32-byte digest is refused,
   because that digest is indistinguishable from a transaction, permit, or
   EIP-7702 authorization hash and no approval screen can describe it
   truthfully.
   No signature has an automatic path at all. A message signature has no
   readable on-chain effect for the policy language to score, and a typed-data
   signature has one the language cannot bound: a permit is redeemed by its
   holder whenever it likes, so a per-transaction limit that admits one permit
   admits an unbounded series of them, and this wallet keeps no counters to
   notice. Every message and every payload therefore queues for human review;
   that review escapes control characters, terminal escape sequences, and
   Unicode bidirectional overrides, because the body is attacker-controlled
   text rendered into the approver's terminal.
3. The signed sender, chain, target, value, calldata, transaction type, nonce,
   gas, fees, and EIP-7702 authorization are constructed locally and validated
   after signing.
4. Automatic signing uses the policy revision evaluated for the simulation and
   atomically verifies that revision — the store's final write is one SQLCipher
   transaction that re-reads revision and status before the signed bytes can
   enter the submission queue.

   Policy governs signing, and the submission claim is where that authority
   stops. `claim_for_submission` re-checks the revision and takes the lease in
   one transaction, so a policy replacement either commits first — cancelling
   the `signed` row, which then fails the claim — or commits after, and finds
   a `submitting` row it deliberately does not touch. That is not a gap being
   left open. The bytes are signed and durably stored by then, the holder may
   already have handed them to an RPC, and a row cancelled underneath a live
   submitter produces a broadcast reported as failed for a transaction that
   succeeded, which invites a replacement for something that already executed.
   Revoking a policy cannot unsign what is signed; the remedy for an envelope
   already on its way is on-chain cancellation.
   The one exception to "only policy-checked plans reach signing" is
   owner-requested cancellation (`wallet_attempt_cancel`): it consults no
   policy because its envelope shape is fixed and derived entirely from the
   stored record and the chain — a 0-value self-send with empty calldata and
   no authorization list at the exact nonce of an envelope this wallet already
   signed and submitted — so like an exact-byte rebroadcast it cannot expand
   what was authorized, only consume the in-flight nonce at the cost of gas.
5. Exceptional review binds the exact prepared transaction fields. After OS
   authentication, mutable local configuration and policy are reloaded and no
   further RPC lookup occurs before signing.
6. Every use of key material requires OS-backed owner authentication:
   transaction, typed-data, and message signing at exceptional review, key
   export, and wallet removal. Replacing a wallet's policy requires it too:
   the policy is what stands between an agent and a signature, so rewriting
   it grants signing authority even though it touches no key material.

   Stored metadata requires it as well, for a reason that took a while to
   state plainly. Nothing an MCP client hands this wallet is trusted, and
   that includes the data that never reaches a signature: token names and
   decimals, address-book aliases and notes, network profiles. None of it is
   an input to the policy engine — the `is_token` and `is_address_book`
   predicates that once made it one have been removed, so a row written to
   improve a label can no longer widen what signs — and all of it is an input
   to the person.
   A transfer to `0x8f3c…21ab` reads one way and a transfer to
   `Coinbase deposit` reads another; `1.0 USDC` and `1000000 units of
   0xa0b8…eb48` are the same transaction described twice. An attacker who
   cannot widen the policy can still change the sentence the owner is
   deciding on, and that is the same outcome by a different route.

   So metadata is security state and moves like it. An agent may **propose**
   — that is the whole of what the MCP surface does for it, and the reason
   those tools exist at all is that assembling a token list or an alias by
   hand is tedious work an agent is good at. Promoting a proposal into the
   database takes two separate human acts: confirmation in the local
   terminal, which establishes intent and shows exactly what will be named,
   and OS-backed presence, which establishes that a person is at the machine.
   Neither substitutes for the other. Rejecting a proposal needs neither:
   deleting a suggestion can mislead nobody, and asking someone to
   authenticate in order to say no only teaches them to authenticate through
   prompts.

   The MCP has no approval operation.
7. Exact signed bytes and their hash are durably stored before first
   submission. An ambiguous submission can only rebroadcast those bytes.
8. An export timestamp is committed before raw key material is returned, so a
   failed metadata write cannot leak a key unrecorded. That record is a sound
   positive and an unsound negative: a timestamp proves this tool revealed the
   key, while its absence proves only that `account export` never ran. Keys live
   in the OS credential store, which the owner can read with their login
   credential and anything running as them can reach, so no wallet is ever
   described as exclusively controlled and nothing in the policy, signing, or
   approval path reads the record.

## Policy and database state

Policies contain only stateless, per-transaction or per-batch controls: chains,
targets, selectors, recipients, token spends, approval spenders/amounts, native
value, and batch size. There are no daily limits, rolling windows, counters,
reservations, or spend-history records.

One SQLCipher database stores current policy rows and separate pending
lifecycle rows. Its random 256-bit key is stored outside the database in the OS
credential store and zeroized after use. Production startup does not generate a
replacement key for an existing database. It also fails if configured wallet
metadata has no corresponding policy.

SQLCipher page authentication, cipher/logical integrity checks, fixed
parameterized SQL, private filesystem permissions, disabled trusted schema,
secure deletion, full synchronization, and DELETE journal mode reduce the
filesystem attack surface. A transient rollback journal can exist during a
write; there is no persistent WAL.

## RPC boundary

Signing simulation uses `eth_simulateV1` against a pinned parent block. The
process checks returned block linkage and count, sends the exact target/value/
calldata as the first execution call, applies the precise EIP-7702 delegation
override when needed, and derives token/native observations from returned
results and logs. It does not run a local EVM, call `eth_getProof`, or fall
back to `eth_call` for a signing decision.

Temporary simulation forks extend the same request shape rather than the trust
boundary: a fork is an ordered list of already-validated plans replayed as
consecutive simulated blocks in one `eth_simulateV1` call, so the RPC remains
the only executor. A fork cannot create a pending request, produce signed
bytes, mark anything approved, or satisfy a policy rule, and its policy
findings are advisory. Submission re-simulates and re-policy-checks against
real chain state, which closes the obvious attack where an agent establishes a
benign fork history and then submits something else. Fork state is never
persisted and never shown at approval time, so a human is never asked to read
agent-supplied hypotheticals while deciding whether to sign.

The RPC still executes the EVM, supplies state, gas/fee estimates, receipts,
and transaction visibility. It can lie, censor, or be stale. Pinning and local
validation detect structural mismatches, not a coherently dishonest endpoint.
Use a trusted authenticated provider—or an independently designed quorum
boundary—for funded production wallets.

**This is a trust assumption, stated as one**, and its shape is worth being
precise about, because it is narrower than it used to be.

No policy predicate reads anything the endpoint reported. Every rule — targets
and selectors, approval spenders and their ceilings, the declared amount and
recipient of a direct transfer, native value, batch size — is decided from the
execution plan's own bytes, which the caller submitted and the digest pins. A
dishonest endpoint cannot relax a rule by misreporting what a transaction did,
because no rule is scored against what it says. `evaluate_policy` takes the plan
and the policy and nothing else, and `tests/boundary.rs` pins that signature so
restoring such a channel has to be deliberate.

What the endpoint still decides is everything around the policy. It says whether
the simulation succeeded, and a plan that does not succeed is refused — so a
lying endpoint can withhold a signature the policy would have allowed, or let
through one that will revert on chain. It supplies the gas the transaction
carries, the balances and predicted effects a human reads at approval time, and
whether a receipt exists afterwards. Availability, correct pricing, and the
truthfulness of what a human is shown all still rest on it, so the practical
advice is unchanged: use a trusted provider, and prefer your own node for a
wallet holding real value.

What changed is that a coherently dishonest endpoint can no longer cause an
automatic signature the policy would otherwise have denied. It can deny, mislead
a human, or misprice — it cannot widen the automatic path. The residual risk is
bounded by the calldata rules the owner wrote, which is the point of writing
them there.

Two ways out exist, and both cost more than they first appear:

- **Verify state rather than accept it.** `eth_getProof` returns Merkle proofs
  against a block's state root, so balances and storage slots could be checked
  against a root rather than believed. That bounds state, not execution: it
  says what the chain held before the transaction, not what running the
  transaction does. It also needs a trustworthy block root to check against,
  which is the same problem one level down unless it comes from a light client
  or a second, independent provider.
- **Execute locally.** A local EVM — `revm` over fetched state — removes the
  endpoint from execution entirely and leaves it supplying only state, which
  the previous point can then prove. This is the complete answer and the
  expensive one. `eth_simulateV1` is a single round trip that returns the
  result of a whole ordered plan; local execution means fetching every account,
  slot, and code object each step touches, discovering them as execution
  proceeds, at a round trip per miss. For an interactive approval, or an agent
  loop running unattended against a long-running goal, that difference is the
  product.

Neither is planned for this release, and saying "trusted RPC is required" is
the honest description of what is shipping rather than a placeholder for them.
Removing simulation-derived predicates from the policy was the cheap part of
this problem, and it is done; what these two would buy is a truthful account of
gas, of what a human is shown, and of whether a plan really executes.
The tradeoff is real in both directions: a wallet that verified everything and
took ten seconds to answer would be a different product, and the reason to
write this down is so the choice stays visible rather than becoming an
assumption nobody remembers making.

### What verifying an endpoint would actually take

None of what follows is scheduled or committed to. It is recorded here so the
next person to reach for a fix reaches for one that helps, because the obvious
ordering is the wrong one.

There are two separable problems, and the expensive answer only addresses the
second:

1. **Chain identity and head authenticity** — is this the real head of the chain
   this wallet thinks it is on? Local execution does not help at all. Only
   consensus verification, an L1 anchor for a rollup, or pinned identity plus
   agreement across independent operators answers it.
2. **State authenticity for that head** — is this state real for that header?
   `eth_getProof` against a verified state root answers it, and local execution
   in `revm` then removes the endpoint from execution too.

Running a local EVM without solving the first proves a state transition against
a root the attacker chose, which is worth close to nothing. Sequencing is the
whole of the advice.

**A sync-committee light client**, for the chains that have one.
[Helios](https://github.com/a16z/helios) verifies beacon-chain headers against
the sync committee and serves a standard `eth_*` endpoint locally, syncing in
seconds with no storage. The header — and so the state root everything else
hangs off — becomes signed by 512 validators rather than asserted by whoever
answers the socket, and it composes with this design rather than replacing it:
point a network's RPC URL at the local endpoint and `eth_simulateV1`, the pinned
parent, and preflight validation keep working unchanged. Out of process that
works today, since a loopback endpoint from owner configuration is admitted,
but leaves the wallet unaware the endpoint is verified; embedded as a library,
the wallet could mark those networks verified and say so at approval time. The
residual is a weak-subjectivity checkpoint, which is genuine but categorically
better — one value, fixed in time, auditable by a human and cross-checkable
against independent sources, rather than trusting every answer from one party
forever. It covers Ethereum, OP Mainnet, and Base out of the shipped defaults.

**An L1 anchor for OP Stack rollups.** Output roots are posted to a contract on
Ethereum, so an L2 state root can be checked against L1 rather than believed
from the L2 endpoint, reducing trust in every OP Stack chain here to trust in
Ethereum. The catch is finality lag: roots are posted periodically, so an anchor
verifies a root minutes to hours behind the head, and a wallet signing against
the head cannot wait. The honest use is a consistency check rather than a
signing precondition — the endpoint's account of history must stay compatible
with what L1 recorded, and divergence is strong evidence of a lying endpoint
even when it arrives late. Fault-proof and output-oracle mechanics differ across
deployments and have changed over time, so this needs per-chain verification
rather than one implementation assumed to fit all of them.

**Pinned identity and a local header chain, everywhere else.** Most of the
shipped defaults have no embeddable light client, so there is no cryptographic
answer to "am I talking to the real chain" for them. Two cheap measures still
apply. Chain-ID verification asks the endpoint who it is, which a hostile
endpoint answers correctly while lying about everything else; shipping a pinned
genesis hash and one known historical block hash per network, checked at
acceptance and periodically, would at least catch being pointed at a fork, a
testnet, or a private chain replaying mainnet addresses. And persisting the last
seen `(number, hash)` per network, requiring each new head to descend from it,
makes the endpoint's account of history tamper-evident over time: it must stay
consistent with everything it has already said, and cannot quietly rewrite
history between sessions or be swapped mid-life without detection. Reorg
handling is the part that needs care — tolerate legitimate reorgs within a
bounded depth, treat a deep or incompatible rewrite as divergence.

**Whatever lands, the difference has to be visible.** Once some networks are
consensus-verified and others are not, a per-network tier — consensus-verified,
L1-anchored, single-endpoint, self-hosted — belongs in `wallet_get_status`, at
network acceptance, and here. Saying a chain is single-endpoint is not an
embarrassment; implying it is verified when it is not would be. Inventing a
bespoke verification scheme for a chain that provides none is out of scope.

Two approaches were considered and declined rather than deferred. Simulating
against several endpoints and refusing to sign when they disagree turns every
signature into a liveness problem across operators who are frequently the same
infrastructure wearing different names, and it answers neither question above.
Re-checking broadcast outcomes against a second endpoint after the fact reports
a divergence when the transaction has already executed, which is monitoring
rather than a control.

RPC URLs can contain provider credentials, and the wallet deliberately does not
treat them as secrets: `wallet_list` returns them, and surfaced RPC errors name
the endpoint verbatim. Such credentials are read-only and easy to rotate, so
hiding them bought little and cost error fidelity. Use credentials whose
disclosure scope is appropriate for the local MCP host.

A network lists several endpoints and fails over between them, which widens
this exposure rather than changing its character: any endpoint in a network's
list can end up serving a given request, so all of them see the addresses that
network is used with. It does not weaken the trust model, because no endpoint
was ever trusted — every answer is either structurally cross-checked or
attributable to a plan's own digest, and each endpoint's chain ID is verified
before its answer is used. What it does change is that a *single* dishonest
operator no longer needs to be chosen by the owner to be reached; it needs only
to be in the list. That is the argument for pointing a valuable wallet at one
provider you chose, which `network add --rpc-url` does by replacing the list.

`wallet_propose_network` is the one MCP tool that makes this process send a request
to an address its caller chose, so the address is admitted before the request
rather than judged by whether the request succeeds: public `https` only, no
credentials in the URL, and no host that resolves to a private or reserved
address — the same admission a referenced plan URL passes. The CLI path is
deliberately laxer, since an owner naming a loopback devnet from their own
terminal is describing a machine they already control. The chain ID is then
verified before storage, and that probe's own failure never reaches the caller:
an RPC error carries the response body verbatim, so returning it would make a
chain-ID check into a way to read whatever answered. This admission cannot pin
what it vetted the way a plan fetch does — the URL is stored and used later, so
a resolver that answers differently afterwards is not caught — and the backstop
is that the stored endpoint is visible to the owner in `network list`.

A network profile is metadata an MCP client supplies, and the endpoint in it is
the wallet's entire view of its chain, so it moves like the rest of the
metadata: `wallet_propose_network` queues a profile and writes nothing.
`ekubo-wallet network review` shows the owner what would be stored — naming the
endpoint being replaced, when the proposal edits a chain they already use,
because the difference between two URLs is the whole decision — verifies the
chain ID against that endpoint, and takes an OS presence check before the
write. A name or alias belonging to a different chain is refused at proposal
time rather than becoming a decision nobody can act on.

The chain ID is deliberately verified at acceptance rather than at proposal.
Proving something about an endpoint when it was suggested, and storing that
result for the owner to read later, is the weaker claim; the check that matters
is the one taken immediately before the profile is written. It also keeps an
unconfirmed agent action from producing a JSON-RPC request.

## Rollback decision

There is no anti-rollback checkpoint, authenticated external event chain, or
hardware monotonic counter. An attacker who can replace `policies.db` with an
older valid encrypted copy can restore an older policy. If it was more
permissive, signing can become more permissive. This is an accepted residual
risk for this release.

Rollback can also resurrect an earlier pending state. The wallet never
implicitly re-signs a broadcast record; it reconciles the exact stored hash and
only rebroadcasts the stored envelope. A restored, still-valid signed
transaction can therefore be rebroadcast. There is no daily allowance to
replenish because no such accounting exists.

## Attack analysis

| Attack | Control and residual risk |
| --- | --- |
| Request arbitrary signature | No MCP/CLI primitive; only validated execution plans reach signing. |
| Change recipient/value/calldata after review | Plan and prepared-review digests plus post-signature envelope validation fail closed. |
| Change nonce/gas/fees after exceptional review | Prepared fields are reviewed and signed without another RPC lookup. |
| MCP approves its own exception | No approval tool; separate terminal plus OS authentication is required. |
| Edit/open encrypted policy bytes | SQLCipher authentication/integrity checks and separate key reject wrong-key or corrupt state. |
| Replace database with a new empty file | Existing wallet metadata without policy fails startup. |
| Restore older valid encrypted database | Not detected; may restore an older policy or signed transaction. Accepted residual risk. |
| Race a policy change | Revision checks cancel or reject stale signing/lifecycle transitions. |
| Flood denied requests | Identical plans deduplicate; awaiting approvals are capped at 64 per wallet. Historical terminal rows still consume disk. |
| Concurrent transactions reuse a nonce | Only one signed/submitting/broadcast row is allowed per wallet and chain. External use of the same key can still invalidate the chosen nonce. |
| Malicious RPC fabricates state | No policy predicate reads a simulation, so a fabricated one cannot widen the automatic path: every rule is decided from the plan's own bytes. A coherent lie can still refuse a signature, misprice gas, or mislead a human at approval time. Trusted RPC remains an assumption of this release for availability and for what a human is shown; see the RPC boundary section. |
| RPC or network fails after send | Bytes/hash were stored first; status remains reconcilable and only exact bytes can be retried. |
| Same-user process accesses credential APIs | Platform isolation and prompts vary; OS compromise or process injection is out of scope. |
| Agent forges a token name or alias to misdescribe a transfer | Both are proposals; becoming a stored name takes terminal confirmation plus OS presence. Symbols are re-sanitized at render time and refused if they contain `0x`. An unnamed token renders by address in base units — readable, not trusted. |
| Agent points the wallet at an RPC it controls | It can only propose one. Endpoint admission refuses non-public and credential-bearing URLs, and acceptance takes a terminal confirmation naming the endpoint being replaced, a chain-ID verification, and an OS presence check. |

Any future stateful allowance or daily accounting requires a new threat model
and an external rollback defense. It must not be added under this design.
