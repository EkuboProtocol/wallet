# Exceptional approval flow

An MCP client cannot approve a policy exception. It can create a pending
request by attempting a plan that fails policy or simulation, and it can wait
for or observe the result. The user must independently run the local CLI in a
real terminal:

```sh
ekubo-wallet approve <request-id>
```

There is no loopback browser or MCP App approval surface in this release.

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

The terminal confirmation defaults to rejection. `--no-confirm` skips only that
yes/no prompt; it still prints the review and still requires platform owner
authentication.

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

After terminal confirmation, the CLI binds the native authentication prompt to
the review digest. It then reloads the pending row, wallet/network
configuration, and encrypted policy. Signing is synchronous from that point
and performs no further RPC request, so the signed fields are exactly those
reviewed. The process validates the resulting envelope and atomically stores
the review digest, exact bytes, and transaction hash.

## Lifecycle

```text
awaiting_approval ── reject/timeout ─────────────▶ rejected | expired
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
- A request that expires during review cannot be stored as approved.
- If another signed transaction is already in flight for that wallet and
  chain, the newly reviewed signature is not persisted or returned; the
  request remains available for a fresh approval after the first transaction
  reaches a terminal state.
