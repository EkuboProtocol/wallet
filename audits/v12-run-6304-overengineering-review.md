# Run 6304 fixes — overengineering review

Reviewed: `f29bafc..HEAD` (106 commits, 58 files, 2,947 added production
lines, ~3,500 test lines, 2,184 lines of audit log).

**Coverage.** Ten commits read at diff level and traced through their call
sites; another eight read as commit message plus diffstat; the rest judged
from message and diffstat alone, with the audit log consulted for
203449, 203525, and 203684. So "everything else is proportionate" below
means "nothing in the messages or diffstats suggested otherwise," not
"every line was read."

**Test applied,** per the maintainer's framing: *"the agent cannot do X"*
means *"cannot do X without explicit human approval."* So the question for
each fix is not "is it correct" but:

> Did this delete a capability a human could legitimately have approved,
> instead of routing it through the approval the product already has?

A hard `Err` on the path to a human approval prompt is the failure mode.
Everything else — correctness fixes, boundary moves, disclosure — is judged
on whether it earns its weight.

## Verdict

**Not overengineered.** I went looking for capability deletion and found
essentially one instance of it (finding 2). The sweep shows real restraint
where overreach would have been easiest, and four commits are model examples
of the intended shape.

Two of the items I first flagged turned out to be the *opposite* problem once
I read the call sites — a check that covers one door of two, and a
supply-chain fix that stops short of the README. Both are worth fixing;
neither is excess.

What is left is one recurring placement mistake: **a refusal in front of an
approval screen the code already builds.** It appears twice (finding 2), and
in the sharper case the screen already prints the exact value being objected
to. That is the shape worth naming, because it is what "the agent cannot do
X" turning into "nobody can do X" looks like in practice.

The genuine overengineering risk is not in this range at all. It is in what
the next pass does with the ~40 unfixed mediums that all restate "a limit
applied after the work it was meant to prevent." See the forward-risk section
— that is the part worth your time.

## The discipline is real — four commits prove it

Worth stating first, because it is the evidence that the four findings below
are slips rather than a pattern.

- **`d2de786` (203449)** — the exemplar. `review --decision approve` mapped
  to `no_confirm`, which skipped the review component. The fix kept the flag
  and removed the bypass, and explicitly kept *scripted reject* working
  because "a scripted session must always be able to say no." That is the
  gloss applied correctly: refuse to let automation approve, never refuse to
  let it decline.
- **`40a9796` (203533)** — scoped to `transaction discard` alone, with the
  non-destructive reads left as known work rather than swept in.
- **`f6429a9`** — draws `IN_FLIGHT_STATUSES` no wider than it needs, and says
  why: "a request merely awaiting approval holds no bytes that can reach the
  chain, and blocking removal on those would make every pending review an
  obstacle."
- **`720343e`** — puts the rule on admission rather than in `validate_config`,
  precisely so an existing plaintext config still loads and can be repaired.
  The reasoning is right even though the rule itself is too absolute (below).

`7ac48f2` (policy store opened once per approval, not once per signature)
moves the right way on friction. Nothing in the range moves the other way —
no fix converts an agent-side block into "prompt the human every time" for a
high-frequency operation.

## Findings

### 1. `7c72cd3` — the zero-address refusal covers one of two doors

Not overengineering. The opposite: the check is in the wrong place and
half the paths miss it.

`transfers.rs:51` hard-refuses `to == 0x0`. `transfer_plan` has one caller,
`src/mcp.rs:1710` (`wallet_send_transfers`), which calls `send_new_plan` →
`plan.validate()` → `simulate_execution` → `execute_automatic`. But
`wallet_send_execution_plan` at `src/mcp.rs:1728` reaches **the same
`send_new_plan`** with an arbitrary producer-supplied plan, and
`ExecutionPlan::validate` does not check the recipient — the commit message
says so itself, and `grep is_zero()` confirms `transfers.rs:51` is the only
such check in the kernel. An agent that wants a plan targeting `0x0` routes
it through a producer MCP and is untouched.

So the control blocks the honest, well-typed door and leaves the general one
open — the audit's own theme 4, *a check trusted for where it was put*,
reintroduced by one of its own fixes.

**The refusal itself is justified, and a warning would not substitute.**
`execute_automatic` signs a policy-covered plan with no human screen at all
— an ordinary token allowlist authorizes this — so there is no approval
prompt to hang a disclosure on. Under the gloss, the owner's prior consent
here is the policy they wrote, and a policy that says "allow transfers of
USDC" is not consent to destroy USDC. Refusing is right.

**One caveat on the stated rationale.** The commit argues "many ERC-20s burn
the amount rather than refusing the call." Standard implementations —
OpenZeppelin included — revert on `transfer` to the zero address, so the
ERC-20 leg is weaker than written. Native value to `0x0` is the real
destructive case, and it alone justifies the check.

**Recommendation:** move the check to `ExecutionPlan::validate` so it covers
both doors, and drop it from `transfers.rs`. If an owner ever needs a
deliberate burn, that is the point to add an explicitly-approved override —
but nothing needs it today, and adding one now would be the
overengineering.

### 2 and 3 — two refusals placed in front of an approval screen that already exists

These are one pattern, not two findings. In both, the code builds a review
surface for the owner and then `bail!`s before the owner can reach it.

#### 2a. `720343e` — plaintext RPC

`validate_admissible_endpoints` refuses `http` to anything but loopback.
Four call sites, and the placement is the finding:

| Site | Path |
|---|---|
| `cli.rs:3629` (`network_candidate`) | human `network add` / `network edit` |
| `config.rs:995` (`add_configured_network`) | shared write helper |
| `config.rs:1038` (`replace_configured_network`) | shared write helper |
| `policy_store.rs:703` (`put_network_proposal`) | agent's network proposal |

The human `network add` flow at `cli.rs:3378` is: `network_candidate` →
`confirm_network_change` (a full-screen review printing the **complete RPC
URLs**, chain ID, and strategy) → `verify_chain_id` (a live probe) →
`PlatformHumanPresence.confirm` (an OS authentication prompt) → write.

That is three separate human gates, and the refusal fires before the first
of them. The comment at `cli.rs:3623` says so deliberately — "a profile that
will be refused should be refused before the owner is walked through a
confirmation screen, a live chain-ID probe, and an operating-system
authentication prompt." Sound reasoning for a malformed chain ID. Wrong for
a rule the owner is entitled to overrule: an operator with a node at
`http://192.168.1.10:8545`, on Tailscale, or in a lab VLAN is told no, and
the screen that would let them say "yes, I know" is already written and
already prints the exact URL being objected to.

For `put_network_proposal` the refusal is correct exactly as it stands.

**Repair, with the constraint that makes it non-trivial.** A plain
`--allow-plaintext` flag threaded into `add_configured_network` /
`replace_configured_network` would hand the agent the bypass, because
`put_network_proposal` and the agent-acceptance path at `cli.rs:4706-4708`
cross those same helpers. The exemption has to be something only the
interactive owner path can produce — an owner-confirmed variant of the write
helper, or a witness value the CLI mints after `confirm_network_change`
returns true and `put_network_proposal` has no way to construct. Then:
drop the early `ensure!` from `network_candidate`, render the plaintext
sentence as a warning line inside `confirm_network_change`, and let the
unconditional refusal stay in the helper for every caller that cannot
present the witness.

#### 2b. `f6429a9` — wallet removal

Same shape, milder. The `bail!` in `src/cli.rs` runs immediately before
`require_approval(ApprovalKind::RemoveWallet)`, so the owner never sees the
in-flight list on the approval screen. An owner whose node is gone, whose
transaction will never mine, and who wants the wallet off this machine has
no path but editing the database — the outcome the commit criticizes
elsewhere.

The concern is sound and the error message is genuinely good — it names the
transactions and the two commands that resolve them. But the list belongs
*in* the approval prompt as warnings, not as a wall in front of it.

**Repair:** move the descriptions into the `ApprovalRequest` as warnings and
let the human approve past them. No agent path reaches `account remove`, so
this one has none of 2a's threading constraint. Lowest priority here.

### 3. `01d13cb` — the install verification stops short of the two places most people read

Also not overengineering — an incomplete fix, and the inconsistency is
worse than either end of it alone.

Signing `install.sh` and verifying it before execution is correct, and the
agent-facing `upgrade_command` is now exactly as strict as it should be. The
release notes and `docs/releasing.md` emit the verifying form.

But `README.md:30` and `docs/installation.md:15` still say:

```sh
curl -fsSL https://raw.githubusercontent.com/EkuboProtocol/wallet-mcp-server/main/install.sh | sh
```

That is the precise construction the commit message condemns — raw source
tree, piped to a shell, verified by nothing — and it is worse than what the
commit replaced, because it tracks `main` rather than a tag. `README.md:33`
tells the reader to "read `install.sh` before piping it to a shell," which is
advice a human cannot act on when the shell starts executing as the bytes
arrive.

The residual question is whether a cosign-mandatory install is too much
friction for first-time users. It is a real cost, but with the current split
the project pays that cost in its docs *and* keeps the unverified path as the
default, which is the worst of both.

**Recommendation:** update `README.md` and `docs/installation.md` to the
verified form. If the friction is judged too high for onboarding, make that
choice explicitly — pin to a tag and document the checksum check as the
weaker fallback — rather than leaving the `main`-tracking pipe in place by
omission.

## Two smaller notes

**Redundant recursion in policy admission (`856a333`).** `Rule::deserialize`
validates the rule; `ChainPolicy::validate` re-validates every rule;
`WalletPolicy::validate` re-validates every chain, which re-validates every
rule again. Three passes over each rule on every document load. Harmless at
policy-document scale and the parent recursion is still needed for
in-crate construction, but it is redundant work introduced by the boundary
move and worth a comment if not a fix.

**Decode-on-every-read in `f11cd5c`.** `PendingRow::parse` now hex-encodes
the stored envelope into a `String` and RLP-decodes it on *every row read*,
including plain listings, to catch bytes that could only have been written
once. Validating at the write (`mark_signed`) costs once instead of once per
read and closes it at the source. The "every reader crosses parse" argument
is the audit's own principle applied faithfully, so this is a trade-off
rather than a mistake — but the allocation-per-row is a real cost paid on the
common path to defend against a state no current writer can produce.

## The forward risk, which is larger than anything above

The readiness note reports 192 unfixed mediums, and the audit log says the
dominant shape among them — about forty findings — is *"a limit applied after
the work it was meant to prevent."* `35ed495` is the first fix of that shape:
`MAX_CHAINS`, `MAX_RULES_PER_CHAIN`, `MAX_PREDICATE_DEPTH`,
`MAX_PREDICATE_NODES`, and a new `check_size` tree walk — about 50 production
lines plus 84 test lines, to bound a document the owner authors and approves,
where `serde_json` already caps depth at 128 and the worst outcome is the
owner's own machine doing pointless work.

Taken one at a time each such fix is cheap and defensible. Taken forty times
it is a second validation layer across the kernel, with its own tests, its
own constants, and its own maintenance, defending a single-user local process
against resource exhaustion by an agent the owner installed. **That is where
this codebase will get overengineered, and the decision is worth making once
as a policy rather than forty times as individual judgement calls.**

Suggested policy before the next pass: fix a resource bound only where the
work happens *before* a human decision point and *on behalf of an untrusted
remote party* (RPC responses, dapp payloads, WalletConnect sessions). Where
the input is a document the owner wrote or approved, record the finding as
`accepted` and move on.

## One thing that is not a problem

45% of the added production lines (1,317 of 2,947) are comments. That is
high, matches the repo's existing register, and in a security kernel the
"why here and not there" arguments are the load-bearing part of several
fixes. The only place it tips over is `transfers.rs`, where an 18-line
comment restating the commit message sits above a 5-line check — and most of
that prose argues for a placement finding 1 recommends changing, so it should
move with the check rather than be duplicated at the new site.

Likewise, the test-to-production ratio is not bloat: revert-verified
regression tests for a signing kernel are the right spend.

## Summary

| Item | Verdict |
|---|---|
| `720343e` plaintext RPC | **Refuses in front of a review screen that already prints the URL.** The one real capability deletion |
| `f6429a9` wallet removal | Same shape, milder — belongs in the approval prompt, not in front of it |
| `7c72cd3` zero-address refusal | Justified, but under-placed — move to `ExecutionPlan::validate`, which covers both doors |
| `01d13cb` install verification | Incomplete — README and `docs/installation.md` still pipe an unverified script from `main` |
| `856a333` policy admission | Correct; triple-validates each rule |
| `f11cd5c` envelope decode | Correct; pays per read for a write-time invariant |
| `35ed495` policy bounds | Defensible alone; the template for ~40 more, which is the real risk |
| Everything else examined | Proportionate |

Only `720343e` fails the maintainer's test outright. `7c72cd3` and `01d13cb`
came out of this review needing *more* work, not less.
