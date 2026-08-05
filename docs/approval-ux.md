# Exceptional approval flow

An MCP client cannot approve a policy exception. It can create a pending
request by attempting a plan that fails policy or simulation, and it can wait
for or observe the result. The user must independently run the local CLI in a
real terminal:

```sh
ekubo-wallet review <request-id>
```

There is no loopback browser or MCP App approval surface in this release.

## Not every failure is worth a human's time

A plan reaches this queue for one of two unrelated reasons: the policy denied
it, or its simulation failed. Only the first is a question a human can answer.
A plan that reverts needs fresh calldata from whoever produced it, so queuing
it costs the user an interruption to approve something that will fail anyway.

Callers that can act on a failure themselves send `on_simulation_failure:
"fail"` to `wallet_send_execution_plan` or `wallet_send_transfers` and get the
failure back instead: nothing is written and nothing is queued. The default
stays `"request_approval"`, so a caller that never sets it behaves exactly as
before.

The choice controls only whether the user is asked, never whether the failure
is enforced. `"fail"` means "return the error without queuing" — there is no
value that signs a plan whose simulation failed, and a policy denial queues for
approval regardless of what is passed here.

## What the agent does while the user reviews

A policy denial is the ordinary way a user gets asked about something, so an
agent that treats `allowed: false` as a blocker breaks the flow the policy
exists to produce. The findings from `wallet_simulate_execution_plan` describe
what the review will say; they are not a reason to stop and report, and they are
not a reason to send the user off to widen their policy before the action they
just asked for can proceed. Send the `simulation_id`, let the wallet queue the
request, and carry on:

1. `wallet_send_execution_plan` returns `approval_required` with a request ID.
2. Tell the user the exact `ekubo-wallet review <request-id>` command.
3. Call `wallet_wait_for_approval` immediately, and again after each timeout,
   until the request is approved or rejected. A queued request does not
   expire, so this can span a lunch break or a night's sleep.
4. On `approved`, call `wallet_send_execution_plan` with the same `request_id`
   to submit the already-signed bytes, then `wallet_wait_for_execution`.

`wallet_wait_for_execution` does not cover step 3. It polls a *broadcast*
transaction and returns straight back for a request that is still awaiting
approval, so only `wallet_wait_for_approval` blocks through the human pause.

Handing back a request ID and ending the turn puts the user in the position of
reporting their own approval in chat, which the wait tool exists to avoid.
`wallet_propose_policy` is for an action the user wants to repeat without review
in future — it is never a precondition for the request already queued.

## What the user reviews

The CLI reloads the encrypted pending request and active policy, then runs a
fresh `eth_simulateV1` simulation. Before asking for approval, it resolves the
transaction's pending nonce, gas limit, EIP-1559 maximum and priority fees, and
any EIP-7702 authorization. No signing key is loaded during these RPC calls.

The review includes:

- full wallet, network, chain, and sender identifiers;
- every ordered call's kind, condition, full target, native value, selector,
  and calldata size;
- a supplemental human reading of each call: an [ERC-7730](https://eips.ethereum.org/EIPS/eip-7730)
  clear-signing rendering when a vendored descriptor matches the exact chain,
  target, and selector — an intent line such as "Swap on Ekubo" plus labeled,
  formatted fields, including nested multicall actions — otherwise a decoded
  reading of standard `approve`, `transfer`, `transferFrom`,
  `setApprovalForAll`, or `multicall(bytes[])` calldata, with amounts rendered
  using token symbols and decimals when they can be read;
- the portable execution-plan digest and simulation parent block;
- transaction type, nonce, gas limit, fee fields, and worst-case fee;
- the canonical Calibur implementation and authorization nonce, if applicable;
- policy findings, decoded simulation failure details, balance changes, and
  the active policy revision; and
- a review digest that commits to the plan digest plus the exact outer target,
  value, calldata, chain, nonce, gas, fees, transaction type, and delegation.

The terminal decision is a two-way choice, Reject and Approve, with the cursor
starting on Reject; Esc and Ctrl+C also reject. Whichever way it goes is
recorded against the request before the command returns, so an agent waiting on
it learns the answer as soon as the user gives it. `--decision approve`
and `--decision reject` skip only that prompt; approving still prints the review
and still requires platform owner authentication.

Decoded readings and token metadata are decoration on top of the exact fields,
never a substitute for them. Calldata is decoded locally and only when it is
canonically encoded; anything else is presented as an unrecognized selector
rather than as a possibly wrong interpretation. Token symbols and decimals come
from bounded, short-timeout, best-effort reads of the configured RPC, which is
itself untrusted: a failed lookup degrades the line to exact base units, and a
returned symbol is stripped of control and parenthesis characters so a hostile
token cannot forge additional review fields. Effectively unlimited allowances and
blanket `setApprovalForAll` grants are surfaced as explicit warnings. The review
digest binds the exact calldata, not this rendering.

ERC-7730 descriptors are vendored in the repository (`clearsign/`), embedded
at compile time, and never fetched from the network; updating the snapshot is
a reviewed git commit. The test suite parses every vendored descriptor,
recomputes each function selector, and validates every display path and
reference, so a malformed descriptor fails CI. Descriptor-supplied text is
control-stripped and length-capped before display, nested calldata rendering
is depth- and count-limited, and a descriptor can never change what is signed
— only how it is described.

After terminal confirmation, the CLI asks the platform to authenticate the
owner, naming the wallet about to sign. It then reloads the pending row,
wallet/network configuration, and encrypted policy, and aborts if any of them
moved during the human pause — that re-read, not the wording of the system
dialog, is what keeps the signed fields the reviewed ones. Signing is
synchronous from that point
and performs no further RPC request, so the signed fields are exactly those
reviewed. The process validates the resulting envelope and atomically stores
the review digest, exact bytes, and transaction hash.

## Signature requests

`ekubo-wallet review <request-id>` also resolves queued signature requests,
which carry no transaction and are therefore never simulated. Both kinds are
stored in the same encrypted database, wait indefinitely for a decision,
deduplicate an identical repeated request, and re-derive their signing hash from the stored
payload on every read, so an edited row can never present one payload while
binding a signature to another.

EIP-712 typed data prints the complete payload above the summary, with the
primary type, domain, and signing hash as facts. A recognized permit (ERC-2612,
DAI, or canonical Permit2, matched by its complete type encoding) lists the
token approvals signing would grant, and warns that nothing limits how many
more of them the same holder can collect; anything unrecognized carries a
blanket warning that a typed-data signature can authorize transfers, orders, or
delegations. No typed-data payload is ever policy-checked, so every one of them
queues here.

EIP-191 `personal_sign` messages print their exact bytes as hex beside the
decoded text. Nothing about a message is policy-evaluable either, so every
message queues too — there is no automatic path, not even for logins. The review:

- escapes control characters, terminal escape sequences, and Unicode
  bidirectional overrides, and warns when any are present, so a message cannot
  repaint or reorder the screen used to review it;
- shows byte length, line count, and whether the requester sent text or raw
  bytes, and refuses an oversized message rather than truncating one;
- warns when the bytes are not valid UTF-8, or are a bare hexadecimal string
  that tells a human nothing;
- states that any `chain_id` is a requester claim, because an EIP-191
  signature binds no chain; and
- parses a recognized ERC-4361 sign-in message into labeled fields — domain,
  account, statement, URI, chain, nonce, timestamps, request ID, and every
  listed resource — warning when the chain is unconfigured or disagrees with
  the requester's claim, when the login is expired or post-dated, when a
  timestamp is malformed, when the domain disagrees with its own URI, and
  whenever resources are attached.

A sign-in message naming an account other than the signing wallet is refused
when it is requested and again at approval time. Legacy raw `eth_sign` over a
bare unprefixed 32-byte digest is refused outright: such a digest is
indistinguishable from a transaction, permit, or EIP-7702 authorization hash,
so no honest review can be drawn for it.

Both flows require terminal confirmation plus OS owner authentication, re-check
the stored request and wallet configuration after the human pause, and store the
signature atomically. The waiting agent reads it
through `wallet_wait_for_typed_data` or `wallet_wait_for_message`.

## Lifecycle

```text
awaiting_approval ── reject ─────────────────────▶ rejected
        │
        │ terminal review + OS owner authentication
        ▼
      signed ── submission lease ──▶ submitting ──▶ broadcast
                                                   │
                                                   ▼
                                          confirmed | reverted
```

Removing a wallet cancels its unsubmitted pending records. Changing the active
policy invalidates approval or cancels a signed request before submission. A
transient pre-submission failure can release the submission lease back to
`signed`. Once submission may have reached the RPC, recovery can only reconcile
or rebroadcast the identical persisted envelope; it never prepares or signs a
replacement.

Only one signed/submitting/broadcast transaction may exist per wallet and chain
at a time. Identical outstanding plans reuse one pending request, and each
wallet may have at most 64 requests awaiting approval. These are queue safety
controls, not spending limits.

## Platform owner authentication

The platform prompt is asked for at two boundaries. The first is the private
key coming out of the credential store, or leaving it for good: transaction,
typed-data, and message signing, `wallet export`, and `wallet remove`. The
second is the signing policy being replaced — `policy set`, the presets, or an
agent proposal applied through `policy review`. A policy change reads no key
material, but the policy is what decides what gets signed with nobody
watching, so rewriting it is authenticated like signing. Changing a network,
the address book, or the token database grants no signing authority and is
confirmed in the terminal instead — a plain yes-or-no under the same facts,
defaulting to no. A prompt that also appears before every saved alias is a
prompt people clear without reading, and that costs more than it buys at the
prompts that matter.

The dialog says which wallet and what is about to happen to it: "sign a
transaction from wallet primary", "reveal the private key for wallet primary",
"replace the signing policy for wallet primary".
It carries no digest. A digest in an OS dialog is not something a reader can
check against anything, and it pushed the one clause they could read off the
end of the line. What the signature is bound to is established by the terminal
review and by the re-reads after it, not by text in a system alert.

- macOS uses Local Authentication with device-owner authentication.
- Windows uses Windows Hello's user-consent verifier.
- Linux uses the `com.ekubo.wallet.human-presence` polkit action shipped under
  `contrib/polkit`; the action must be installed by an administrator.

If the platform mechanism is missing, denied, canceled, or times out, the
operation fails closed. The MCP server never receives an approval token and has
no tool that can emulate this step.

## Failure behavior

- A presenter error, terminal disconnect, or authentication denial produces no
  signature.
- A changed pending row, wallet, network, or policy aborts before signing.
- If another signed transaction is already in flight for that wallet and
  chain, the newly reviewed signature is not persisted or returned; the
  request remains available for a fresh approval after the first transaction
  reaches a terminal state.

## What the terminal shows

When policy rejects a plan or simulation fails, the wallet stores an owner-only
pending record whose digest commits to every ordered call. `ekubo-wallet review
<request-id>` then re-simulates and prints the exact nonce, gas, fees, calls, and
delegation alongside a decoded reading of each step:

```text
Call 1: kind=Approval; target=0xa0b8…eb48; value=0 wei; selector=0x095ea7b3; calldata=68 bytes
Call 1 reads as: approve spender 0x1111…1111 for 1000 USDC (1000000000 base units)
Simulated net balance change (excludes live gas): USDC (0xa0b8…eb48): -1000 USDC (-1000000000 base units)
```

When a vendored [ERC-7730](https://eips.ethereum.org/EIPS/eip-7730)
clear-signing descriptor matches the exact chain, contract, and function
selector, the call renders as its declared intent plus labeled, formatted
fields — token amounts with symbols and decimals, dates, durations, enums, and
nested multicall actions:

```text
Call 1 reads as: Swap on Ekubo [Ekubo Protocol — Ekubo MEV-Capture Router]
Call 1 ·: Pool token 0: 0x1111…
Call 1 ·: Specified pool token: Token 1
Call 1 ·: Specified amount: 1000000
```

Descriptors are vendored in [`clearsign/`](../clearsign), embedded at compile
time, and never fetched from the network; the test suite re-derives every
selector and validates every display path, so updating the snapshot is a
reviewed git commit that cannot silently drift.

Otherwise, standard `approve`, `transfer`, `transferFrom`, `setApprovalForAll`,
and `multicall(bytes[])` calldata is decoded locally. Token symbols and decimals
come from bounded, best-effort reads of the configured RPC; when a lookup fails
the line degrades to exact base units rather than to a guess, and all
descriptor- and token-supplied text is sanitized so it cannot forge additional
review output. Effectively unlimited allowances and blanket `setApprovalForAll`
grants raise explicit warnings.

These readings are supplemental. The review digest binds the exact ordered
calldata, and the displayed target, selector, and value remain authoritative.
An agent must never run the approval command for you.
