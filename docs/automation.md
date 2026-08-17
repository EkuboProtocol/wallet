# Automations

An automation is raw EVM runtime bytecode plus a cron schedule. On each cron
tick the wallet polls the bytecode through `eth_simulateV1`, with the bytecode
installed as the code at the wallet's own address, and reads back a list of
calls. Those calls are queued into the ordinary automatic-transaction pipeline:
synthesized execution plan, exact simulation, policy evaluation, signature,
broadcast. The point is latency — an agent that would otherwise have to be
awake and holding a conversation to react to a chain condition instead compiles
the condition once and lets the wallet watch for it.

Automations get their own tab in the desktop shell, alongside activity,
permissions, connections, reference data, and settings.

This document is the design, and it is implemented: the poll, the decoder, plan
synthesis, storage, the cron driver, the MCP tools an agent writes automations
with, and the Automations tab.

## An automation is a plan source, not an authority

The wallet already executes plans nobody reviews: `orchestrator::execute_automatic`
signs when, and only when, the currently installed policy allows every call in
the batch and the exact prepared envelope. Automations supply a third source of
plans alongside agent-supplied inline plans and `plan_fetch` artifacts. They add
a scheduler and a return-value decoder. They add no signing path, no
authorization path, and no policy exemption.

That is why installing an automation is not a widening of authority. A blob can
only emit calls; every call is evaluated against the installed policy at send
time, and a batch that does not resolve to all-allow never reaches the signer.
An automation the owner installs and then forgets is bounded by the policy the
owner installed, the same way an agent they leave running is.
[security-boundary.md](security-boundary.md) is unchanged by this feature.

## The in-process cron

Each automation carries a cron expression. One scheduler runs inside the wallet
process on the Tokio executor: it holds the next fire time for every enabled
automation, sleeps until the earliest, runs that job, and recomputes. No
external scheduler, no OS cron, no separate daemon — the wallet is already a
long-lived process with an executor, a key store, and the RPC configuration a
job needs.

**Seconds resolution.** The expression is six fields, seconds first
(`*/12 * * * * *` fires every twelve seconds). Minute-resolution cron cannot
express "about every block", which is the cadence this feature exists for. The
`cron` crate parses exactly this shape, is MIT, and is built on the `chrono`
already in the tree; it is a smaller dependency than a full scheduler crate and
the sleep loop is a dozen lines.

**UTC.** Schedules evaluate in UTC. A local-time schedule has to answer what
happens to a 02:30 job in a DST transition, and the answer is never worth what
it costs. An owner who wants a job at a local hour writes the UTC hour.

**Missed ticks are skipped, never backfilled.** If the application was closed,
the wallet was locked, or the machine was asleep across ten fire times, the
automation runs once at the next tick — not eleven times. Every tick derives
its calls from live chain state, so a backlogged tick would be executing an
intent computed for a chain that no longer exists. The same rule covers a tick
that arrives while the previous run is still working: it is dropped, with the
reason recorded, and the next scheduled tick recomputes from scratch.

## The job

Each tick, for one automation:

1. **Call the RPC.** One `eth_simulateV1` request against the network's
   configured endpoint, at the latest block, with a `stateOverride` entry
   setting the wallet address's `code` to the installed bytecode, and one call
   `to` and `from` the wallet address, calldata `automate(bytes config)` — a
   fixed 4-byte selector plus the owner's stored `config` bytes.
2. **Read the automation's state.** Whatever the blob decides is state: chain
   reads it performs, balances, positions, the effects of its own last
   transaction.
3. **Produce the calls.** The blob returns the list, ABI-encoded.
4. **Queue them.** A non-empty list is synthesized into an `ExecutionPlan` and
   handed to `execute_automatic`, which simulates, prepares exactly, evaluates
   the policy, and writes a pending row — signed and broadcast if the policy
   allowed every call, and otherwise left as the one row that says which call it
   did not.

The bytecode is **deployed runtime code**, not initcode. The wallet does not run
a constructor, and it never deploys anything.

### Why the wallet's own address

The alternative was to override the code at a scratch address and call it with
`from` set to the wallet. That gives the top-level call the right `msg.sender`
and nothing else: every call the blob makes downstream originates from the
scratch address, so any `msg.sender`-as-owner check — `claim`, `collect`,
`withdraw`, a position NFT's operator check — reverts during the poll even
though the identical call succeeds in the batch the wallet would actually send.
A blob at the wallet's own address makes sub-calls that carry the wallet as
`msg.sender`, which is exactly what the executed Calibur batch does. One
arrangement is faithful to execution; the other systematically misreports it.

`from` is the wallet too, so inside the blob `msg.sender == address(this) ==
the wallet`, matching a Calibur self-batch.

### What the blob can and cannot see

`SLOAD` reads the wallet's real storage. For an EIP-7702 delegated account that
is Calibur's storage, at Calibur's layout. Writes are discarded with the rest of
the simulation, so **the blob has no memory between ticks**: any "have I already
done this" test has to be derived from on-chain state it can read — the effects
of its own previous transaction, a timestamp or nonce on the target contract, a
balance. There is no counter to keep.

`automate` is deliberately **not** `view`. The blob runs inside a simulation
whose writes are thrown away, so it is free to perform the state-changing call
it is considering and inspect the result before deciding to emit it. Probing is
the intended pattern: call `claim` and see what it returns, then emit it only if
the amount clears your threshold.

### The delegation is displaced during the poll

The state override replaces the wallet's code for the duration of the poll, so
while the blob runs the wallet is not delegated to Calibur — the wallet's code
*is* the blob. Any call the blob makes into a contract that calls back into the
wallet reaches the blob's dispatcher instead of Calibur: ERC-1271
`isValidSignature`, `onERC721Received`, `onERC1155Received`, any receiver hook.
Such a probe fails unless the blob answers those selectors itself, or
`DELEGATECALL`s to the canonical Calibur implementation for selectors it does
not handle. This is an authoring constraint, not something the wallet can paper
over: an address has one code, and the poll needs it to be the blob's.

The constraint is confined to the poll. The batch the wallet actually sends
executes through the intact delegation.

## The return value

`automate` returns one ABI-encoded `(address to, uint256 value, bytes data)[]`.

- An **empty array** means nothing to do. The tick ends there: no plan, no
  simulation, nothing queued.
- A **non-empty array** becomes one atomic batch — entry `i` maps to
  `ordered_steps[i + 1]` of the synthesized plan, executed as a single Calibur
  EIP-7702 batch with `revertOnFailure`, which is already how every multi-step
  plan executes.
- A **revert, or a return value that does not decode** to that type, is a failed
  tick. It counts toward eventual auto-disable.

The list is bounded by the limits the plan schema already enforces —
`MAX_EXECUTION_STEPS` (4096) and `MAX_TOTAL_CALLDATA_BYTES` (8 MiB) in
`crates/ekubo-wallet-core/src/core/execution_plan.rs`. Reusing them keeps one
set of numbers rather than inventing a parallel set that can drift.

Nothing else crosses the boundary. No deadline, no gas hint, no per-call flags:
the blob decides *what*, the wallet decides *whether* and *how*.

## Authorization and what happens when it fails

The synthesized plan goes through `execute_automatic` unchanged, which means it
is simulated, exactly prepared, and evaluated against the current policy at send
time. `SendDisposition::Signed` broadcasts. `SendDisposition::Queued` — a
`review` rule, a call no rule matched, a `deny`, or a failed simulation —
**disables the automation** and notifies the owner.

Disabling rather than leaving it enabled is the whole answer to the obvious
failure mode. A blob that emits a non-allowed call emits it on every tick;
queuing each one for approval would turn a cron job into an approval-queue
flood. Because the automation stops, exactly one row survives, and that row is
the diagnostic: it shows the owner precisely which call their policy did not
permit.

Owners running automations should also set the network's `max_fee_per_gas`
(documented in `config.rs` as the bound on what a dishonest endpoint can cost an
unreviewed automatic send). It is an existing knob and it is the right one;
automations add no separate fee cap.

## An automation is bound to a wallet and a policy revision

Every automation records the policy revision that was active when the owner
installed it. A tick reads the current revision first: if it does not match, the
automation does not run, and it does not fail either — it moves to
`awaiting_relink` and waits for the owner to look at it again in the Automations
tab.

The threat this closes is the one that only appears later. An automation whose
calls the policy rejects stops, which is correct and visible. But the owner then
widens the policy for some unrelated reason — a new protocol, a raised limit —
and under a design that only checks the policy at send time, the stopped
automation silently becomes live again, now authorized by a rule written for
something else entirely. Nobody decided that. The policy edit was about the new
protocol, and its side effect was to re-arm a job the owner may not have thought
about in weeks.

Binding makes that re-arming an explicit act. Relinking shows the same review as
the original install — bytecode hash, cron, config, network — against the new
policy, and rebinds to the current revision. The check is cheap: one comparison
against `PolicyStore`'s revision at the top of every tick.

This is deliberately stricter than "the policy is re-evaluated at send anyway".
Send-time evaluation answers "may this call proceed"; the binding answers "did
the owner intend this job to run under this policy", and no amount of
per-call checking answers the second question. It is also why the binding is to
the revision rather than to a hash of the rules an automation happens to touch:
a narrower rule would be a guess about which edits matter, and the whole point
is that the owner decides.

An automation is likewise bound to one wallet. It does not follow a key that is
imported elsewhere, and there is no operation that moves one between wallets —
install it again if that is what you meant.

## Serialization

A tick is skipped whenever the automation's own last transaction is still
pending — submitted, broadcast, or mined but not yet `finality_confirmations`
blocks deep — and whenever any other send holds the wallet and chain's signing
slot. It is skipped, not deferred: the next scheduled tick recomputes from live
state rather than replaying an intent formed against a chain that has since
moved.

That is not new machinery. `PendingStore`'s in-flight unique index already
permits one live row per wallet and chain, and a receipt keeps the signing slot
until it reaches the configured depth; the scheduler reads that state rather
than tracking its own.

For per-block cadence, set `finality_confirmations: 1` on the automated network.
It is an existing supported value (1–1000). The exposure it accepts is that a
reorg can un-mine the send the next tick was planned on top of; in practice the
transaction is nearly always re-mined, and a blob that re-derives its intent
from live state on every tick self-corrects when it is not. That is a good trade
for an automation, which is why it is worth writing down that a network carrying
reviewed transfers may prefer a deeper number.

Several automations on one wallet and chain share that single slot. They are
scheduled independently, but only one is in flight at a time, and the losers
skip rather than stack up.

Ticks run while the application is running and the wallet is unlocked. There is
no headless mode.

## Failure handling

Each of these disables the automation and notifies the owner:

- a queued (non-allow) disposition,
- an on-chain revert (`status == 0`) on a sent batch,
- a batch that never mines, after a timeout,
- ten consecutive failed ticks — RPC error, blob revert, or undecodable return.

Nothing retries a reverted batch automatically. A blob that emitted a reverting
call will emit it again on the next tick; stopping is the only response that
does not burn gas in a loop.

## Install, storage, and review

Automations live in their own SQLCipher-backed typed store, keyed by wallet and
chain. Stored fields: the caller's key, name, bytecode, config bytes, cron
expression, network, wallet, the bound policy revision, state, last fire time,
last result, the transaction the last tick sent, and the reason it stopped if it
did. A unique index on (wallet, key) is what makes installing idempotent.

State is one of `enabled`, `disabled` (it failed; the reason says how), or
`awaiting_relink` (the policy revision moved). Only `enabled` ticks.

An agent installs an automation directly, with no owner confirmation step. An
automation is another way to suggest transactions, and the policy is what
decides whether a suggestion sends — the same arrangement, and the same
authority, as an agent submitting a plan itself. A confirmation dialog here
would be asking the owner to approve something that cannot exceed what they
have already approved.

What an install *does* have to name is the policy revision it was written for.
Naming one that is no longer active is refused outright, so an automation is
never bound to a policy the agent did not read. That check plus the tick-time
binding is what keeps installation honest without a dialog.

Installs are idempotent under a caller-chosen `automation_key`, unique per
wallet. Installing again under an existing key replaces that automation rather
than adding a second one. This is not a convenience: an agent whose tool call
timed out after the write landed would otherwise retry into two identical
automations on one wallet, contending for one signing slot and each reporting
the other as the reason it skipped — a confusing way to discover you installed
something twice. Replacement resets the failure count, stopped reason, and last
transaction, because those describe bytecode that is no longer there.

An agent may also disable an automation, which is authority-reducing. There is
no re-enable: installing again under the same key is how one starts back up,
which keeps "run this" and "here is exactly what it runs" a single operation.

The owner comes in when transactions stop working, not to authorize the job.

The tab lists each automation with its key, schedule, next fire time, and —
when it stopped — why, above that automation's run history.

## Every run is kept, and every transaction stays openable

The automation row carries only the latest outcome, which answers "is this
working right now". A person deciding whether to keep trusting something that
runs unattended has a different question — what has it been doing — so every
tick appends to `automation_runs`: the quiet ones that found nothing to do, the
skips, the failures, and the sends. A log that kept only the eventful runs could
not tell a quiet automation from a stopped one, which is usually the distinction
the reader came for. The log is capped per automation and trimmed oldest-first
on the way in, because a per-second schedule writes 86,400 rows a day.

A run that produced a transaction names it, and the tab opens it in the same
activity detail any other transaction opens in. That link has to keep working
however long ago the run happened, which is why **clearing activity history
hides rows rather than deleting them**. A hidden row is absent from every list
and still resolves by id. The per-wallet history cap likewise skips any row an
automation run points at: the cap exists to bound storage, not to break the
audit trail of what the wallet did while nobody was watching.

Clearing history was a delete before this feature. Making it a hide is the
smaller change of the two available — the alternative, exempting only
automation-produced rows from the delete, would have made "clear history" mean
different things for different rows, which is worse to explain and worse to
rely on. It shows the bytecode's
keccak256 and byte length and cannot show what the bytecode *does*; that limit
is the honest one to state rather than paper over. See the open questions.

## The authoring surface

The wallet does not compile Solidity and will not. What it owes an agent is
everything needed to compile *correctly elsewhere* and to test the result
against this exact wallet, this policy, and this network before anything is
installed. This section is the feature, as much as the cron loop is: bytecode an
agent cannot debug is bytecode an agent cannot write.

### 1. A published skill, with worked examples

`docs/skills/write-ekubo-automation/SKILL.md`, bundled into the MCP server the
way `use-ekubo-wallet` is — `include_str!` plus a
`wallet://skills/write-ekubo-automation/SKILL.md` resource entry in `mcp.rs`. A
test holds the skill and the tool surface together: it asserts the skill names
`wallet_dry_run_automation` and that the tool is registered, so the two cannot
drift into a skill that teaches an agent to call something that is not there.

It carries the interface, the hard rules, and four worked Solidity examples —
the empty case, a threshold-gated claim that probes before emitting, a
two-call batch that keeps its cadence in chain state because it has no memory,
and a receiver-hook stub for probing a call that reenters the wallet.

Two things the skill states that the wallet does not enforce:

**Language and compilation are the agent's problem.** The wallet has no
compiler and no opinion about source language; the contract is deployed runtime
bytecode as hex — `deployedBytecode`, not `bytecode` — that runs on the target
network. Consequences the skill spells out because they bite in artifact form:
no `immutable` values and no constructor (their slots are unresolved
placeholders in a deployed-bytecode artifact), and no external libraries (link
placeholders).

**An automation is network-specific**, in two independent senses. Addresses
are: every protocol, token, and pool identifier exists on one chain. The EVM is
too: compile against the fork the target network actually runs, or `PUSH0` on a
pre-Shanghai chain and `MCOPY`/`TSTORE` on a pre-Cancun one revert on the first
tick. An automation is installed against one wallet and one network and is not
portable.

The interface it publishes:

```solidity
interface IEkuboAutomation {
    struct Call {
        address to;
        uint256 value;
        bytes data;
    }

    /// Runs as the wallet, at the wallet's address, inside a discarded
    /// simulation. Not `view`: probe freely.
    function automate(bytes calldata config) external returns (Call[] memory);
}
```

The skill carries the semantics above in the form an author needs them:
`msg.sender` is the wallet, storage is the wallet's — so a contract that
declares a state variable reads Calibur's slot, not its own — writes are
discarded, there is no memory between ticks, the delegation is displaced so
receiver hooks and 1271 need handling, empty array means idle, and every
emitted call must be allowed by the installed policy.

### 2. A dry-run tool — the compile-test-fix loop

`wallet_dry_run_automation` takes bytecode, config, wallet, and network. It
installs nothing, signs nothing, schedules nothing, and persists nothing. It
returns:

- the decoded call list,
- the policy verdict for each call — `allow`, `review`, `deny`, or unmatched —
  and the index of the rule that decided it,
- the simulation result for the synthesized plan, so the agent sees whether the
  batch would actually succeed,
- gas used by the poll itself,
- and on any failure, **verbose** diagnostics: the revert selector, a decoded
  `Error(string)` or `Panic(uint256)`, the raw return bytes as hex, and the
  precise reason an ABI decode failed.

The verbosity is load-bearing. An agent iterating on bytecode against a terse
"decode failed" has nothing to iterate on, and the loop stalls at exactly the
point where it should be cheapest.

### 3. Status tools for live automations

`wallet_list_automations` and `wallet_get_automation_status` expose the cron
expression and next fire time, the last tick's time and outcome, the calls it
returned, the last transaction hash and its status, the consecutive-failure
count, and the disable reason. An automation that stopped should be debuggable
without the owner reading a log.

A schedule-validation tool — expression in, next N fire times out — costs
nothing and keeps an agent from installing `*/12 * * *` and wondering why it
never fires.

## Implementation shape

- The scheduler belongs in `ekubo-wallet-core`, on the Tokio executor, driven by
  `ApplicationAuthority` and holding its own `AgentExecutionAuthority` — the
  same narrow capability the MCP server gets. `execute_automatic` is already the
  whole plug point; nothing about it is MCP-shaped.
- The poll itself is a `simulation`/`fork`-style `eth_simulateV1` request with a
  code override; both modules already build these.
- Plan synthesis produces an ordinary `ExecutionPlan` and reuses its validation
  rather than a parallel one.
- Domain events carry tick results, sends, and disables to GPUI, which is what
  the Automations tab renders.

## Not in scope

- Compiling anything inside the wallet.
- Running ticks while the wallet is locked or the process is not running.
- Backfilling missed ticks.
- Cumulative spend budgets. The bound is the policy, `max_fee_per_gas`, and the
  fact that a send must confirm before the same wallet and chain runs again.
- Any automation-specific relaxation of the policy engine.

## Open questions

- **Unverified source display.** An owner looking at 4 KB of hex has no way to
  understand it. The agent could attach the Solidity it compiled, shown clearly
  labeled as unverified. This makes the tab more useful and also creates a place
  to display source that does not correspond to the bytecode. Not committed
  either way.
- **Selector for `automate`.** Left to implementation; the interface above is
  the candidate.
- **A floor on fire frequency.** Six-field cron can express `* * * * * *` —
  every second — which no RPC endpoint will enjoy. Whether to reject such an
  expression at install time or let the serialization rule absorb it is open.
