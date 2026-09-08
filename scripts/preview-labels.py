#!/usr/bin/env python3
"""Assign a class, a risk band, and a summary template to every decoded call.

This is the teacher the small model is distilled from, and it is deliberately
a *rule table* rather than a per-format label sheet.

Two reasons. A rule reviewed once applies to every format it matches, including
formats added to the vendored registry later, whereas 1119 hand labels are 1119
chances to be inconsistent about what "Withdraw" means. And a rule can be read:
the mapping from a descriptor's human-authored intent to a category is right
there to argue with, where a label sheet only records that someone once decided.

The model is not the rules. It is fitted on what the rules produce and then
runs on calls the rules have nothing to say about -- an unlisted protocol, a
standard ERC-20 call with no descriptor, a phrasing the keyword table misses.
Generalizing past this table is the entire reason it exists.

Risk is derived, never labeled. An unlimited allowance, blanket operator
control, an authority delegation, or value sent to a target nothing decoded are
Critical because of what they are, and a language model asked to judge them
would answer inconsistently and teach the small one noise.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import re
import sys
from typing import Any

# Ordered: the first pattern that matches an intent decides the class. Order is
# what resolves the overlaps -- "Claim fees and extend" is a claim, "Approve
# position operator" is an approval and not a position action, and "Withdraw
# liquidity" is a liquidity removal rather than a plain withdrawal.
CLASS_RULES: list[tuple[str, str]] = [
    # Removing an authority, before the rule that grants one: "Revoke
    # Delegation" is not a delegation and "Decrease allowance" is not an
    # approval.
    (r"\brevoke|\bderegister|\bunwhitelist|\bdeaffiliate"
     r"|\bremove (signer|member|vote signer|addresses|root)"
     r"|\bdelete delegation|\bdecrease allowance|\bclear .*vote|\brenounce", "revocation"),
    # "Authorize" alone is not an allowance -- Celo's "Authorize Validator" and
    # a Safe's "Authorize Signer" are governance -- so only the spending sense
    # belongs here. "Approve Safe hash" is likewise a multisig action.
    (r"\bapprove safe hash", "governance"),
    (r"\bapprove|\bauthorize spending|\bpermit\b|\bincrease allowance|\bcheck allowance"
     r"|\bset (position|stake) operator", "approval"),
    # Anything naming an NFT explicitly, before the class rules that would
    # otherwise claim it: "Transfer Stake NFT" is an NFT movement, not a stake,
    # and "Burn empty vote-escrow NFT" is not either.
    (r"\bnft\b|\bpoap", "nft"),
    # A Safe "Swap signer" replaces a multisig owner and trades nothing.
    (r"\bswap signer", "governance"),
    (r"\bswap|\bmultihop|\broute node|\bpartial.fill|\bfill order|\breprice"
     r"|\binstantly buy|\bbuy\b|\bsell\b", "swap"),
    (r"\bbridge|\bcctp|\bmigrate chsb|\breceive bridged", "bridge"),
    # Leaving a staked position, before the rule for entering one. A cooldown
    # and a validator exit request both begin an exit.
    # Extending a lock keeps funds staked, so it must be read before the
    # "unlock" that would otherwise claim it.
    (r"\bincrease unlock|\bupdate lock", "stake"),
    (r"\bunstake|\brequest unstaking|\bcooldown|\bunlock\b|\bwithdraw expired stake"
     r"|\brequest validator exit|\benter exit queue", "unstake"),
    (r"\bclaim unstaked|\bclaim|\bcollect|\bexit funds|\bexited assets|\brefund"
     r"|\bwithdraw protocol fees|\bwithdraw pol rewards|\bopt out", "claim"),
    (r"\bbatch|\bmulticall|\bbundler", "batch"),
    (r"\bstake\b|\bstaking|\brelock|\block\b|\block tokens|\block celo"
     r"|\bincrease lock|\bupdate lock|\bincrease unlock|\bcreate .*stake"
     r"|\bextend .*stake|\bmerge .*stake|\bsplit .*stake|\bvote.escrow", "stake"),
    (r"\bdelegate|\bundelegate|\bredelegate|\baffiliate|\bmove staked", "delegation"),
    (r"\bvote|\bupvote|\bpropose|\bproposal|\bhotfix|\bfellowship|\bgovernance"
     r"|\bsigner|\bthreshold|\bownership|\bowner transfer|\bset (executors|recipients"
     r"|account name|metadata|withdraw address)|\bcreate (safe|account|operator|splitter"
     r"|validator|fellowship|eigenlayerpod)|\bsetup safe|\bmigrate safe|\bregister"
     r"|\bedit validator|\bauthorize (validator|signer)|\bactivate"
     r"|\breset slashing|\bslashing|\bdequeue|\bwhitelist|\badd member|\breorder member"
     r"|\bmultisig|\bverify impact|\bmanage collateral|\bstorage root|\binitiali[sz]e"
     r"|\bschedule .*emissions|\bupdate vault state|\brefresh|\breenter"
     r"|\bexecute (hotfix|proposal)|\bcreate (dca|order)|\bincrease dca|\breduce dca"
     r"|\bcancel", "governance"),
    (r"\badd .*liquidity|\bcreate .*liquidity|\bcreate salted liquidity", "liquidity_add"),
    (r"\bremove liquidity|\bwithdraw .*liquidity", "liquidity_remove"),
    (r"\bwrap|\bunwrap", "wrap_unwrap"),
    (r"\bsupply|\bdeposit", "supply"),
    (r"\bborrow", "borrow"),
    (r"\brepay", "repay"),
    (r"\bwithdraw|\bredeem|\brequest (redeem|withdrawal|a redemption)"
     r"|\bwithdrawal|\binstantly redeem", "withdraw"),
    (r"\btransfer|\bsend\b", "transfer"),
    (r"\bmint|\bburn", "nft"),
]

# What a class implies about attention, before the call's own facts are read.
# Anything that hands another party spending power or assets is at least
# Caution; the rest is Routine until a warning says otherwise.
CAUTION_CLASSES = {
    "approval",
    "transfer",
    "bridge",
    "delegation",
    "nft",
}

# Phrases the deterministic interpretation attaches when a call grants
# authority that outlives it. These decide Critical regardless of class,
# because that is what they mean.
CRITICAL_WARNINGS = (
    "unlimited",
    "setapprovalforall",
    "operator",
    "all tokens",
    "unrecognized",
)

# One template per (class, shape). `{kind}{n}` names the nth slot of that kind
# within the call, counting from one. A template whose roles a call cannot fill
# falls through to the next, and the last entry of each class fills nothing, so
# every class always has something to say.
TEMPLATES: dict[str, list[str]] = {
    "swap": [
        "swap {amount1} for {amount2}",
        "swap {amount1} through {token1}",
        "swap {amount1}",
        "swap through {address1}",
        "swap tokens",
    ],
    "approval": [
        "approve {address1} to spend {amount1}",
        "approve {address1} to spend {token1}",
        "approve {address1}",
        "grant an allowance",
    ],
    "revocation": [
        "revoke {address1} for {token1}",
        "revoke {address1}",
        "revoke an approval",
    ],
    "transfer": [
        "send {amount1} to {address1}",
        "send {token1} to {address1}",
        "send to {address1}",
        "transfer tokens",
    ],
    "bridge": [
        "bridge {amount1} to {address1}",
        "bridge {amount1}",
        "bridge tokens",
    ],
    "supply": [
        "supply {amount1} to {address1}",
        "supply {amount1}",
        "supply {token1}",
        "supply to {address1}",
        "supply funds",
    ],
    "borrow": ["borrow {amount1} from {address1}", "borrow {amount1}", "borrow funds"],
    "repay": ["repay {amount1} to {address1}", "repay {amount1}", "repay a loan"],
    "withdraw": [
        "withdraw {amount1} to {address1}",
        "withdraw {amount1}",
        "withdraw {token1}",
        "withdraw to {address1}",
        "withdraw funds",
    ],
    "stake": [
        "stake {amount1} with {address1}",
        "stake {amount1}",
        "stake {token1}",
        "stake with {address1}",
        "stake funds",
    ],
    "unstake": ["unstake {amount1}", "unstake {token1}", "unstake from {address1}", "unstake"],
    "claim": [
        "claim {amount1} to {address1}",
        "claim {amount1}",
        "claim rewards from {address1}",
        "claim rewards",
    ],
    "liquidity_add": [
        "provide {amount1} and {amount2} of liquidity",
        "provide {amount1} of liquidity",
        "provide liquidity to {address1}",
        "provide liquidity",
    ],
    "liquidity_remove": [
        "remove {amount1} of liquidity",
        "remove liquidity from {address1}",
        "remove liquidity",
    ],
    "governance": [
        "vote using {address1}",
        "update {address1}",
        "change a protocol setting",
    ],
    "nft": [
        "transfer an nft to {address1}",
        "mint an nft using {address1}",
        "move an nft",
    ],
    "wrap_unwrap": ["wrap {amount1}", "wrap {token1}", "wrap ether"],
    "delegation": [
        "delegate {amount1} to {address1}",
        "delegate to {address1}",
        "delegate voting power",
    ],
    "batch": ["run {number1} batched calls", "run several batched calls"],
    "unrecognized": ["call {address1}", "call an unrecognized contract"],
}

ROLE = re.compile(r"\{(amount|token|address|number|data|flag)(\d+)\}")

KIND_TAGS = {
    "amount": "<amount>",
    "token": "<token>",
    "address": "<address>",
    "number": "<number>",
    "data": "<data>",
    "flag": "<flag>",
}


def classify(intent: str | None) -> str:
    """The class a descriptor's human-authored intent implies."""
    if not intent:
        return "unrecognized"
    lowered = intent.lower()
    for pattern, name in CLASS_RULES:
        if re.search(pattern, lowered):
            return name
    return "unrecognized"


def risk_of(name: str, warnings: list[str], has_value: bool) -> str:
    """The attention a call warrants, from what it is rather than how it reads."""
    joined = " ".join(warnings).lower()
    if any(phrase in joined for phrase in CRITICAL_WARNINGS):
        return "critical"
    if name == "unrecognized" and has_value:
        return "critical"
    if name in CAUTION_CLASSES:
        return "caution"
    return "routine"


def fill(template: str, slots: list[tuple[int, str]]) -> list[str] | None:
    """Resolve a template's roles against one call's slots.

    `slots` pairs each of the call's slots with its **plan-global** index, and
    that pairing is the whole point. A template is written per call --
    `{address1}` means "this call's first address" -- but a slot reference is
    numbered across the entire plan. Filtering a call's slots out of the plan
    and then using their position in the filtered list would emit `<s0>` for
    the first address of the second call, which is the first address of the
    *first* call: an approve-then-withdraw plan would have said it was
    withdrawing to the spender it had just approved.

    Answers `None` when the call has no slot for some role, which is what
    makes the caller try the next template.
    """
    pieces: list[str] = []
    for word in template.split():
        match = ROLE.fullmatch(word)
        if match is None:
            pieces.append(word)
            continue
        wanted, nth = KIND_TAGS[match.group(1)], int(match.group(2)) - 1
        matching = [index for index, kind in slots if kind == wanted]
        if nth >= len(matching):
            return None
        pieces.append(f"<s{matching[nth]}>")
    return pieces


def summarize(name: str, slots: list[tuple[int, str]]) -> list[str]:
    """The first template of a class whose roles this call can fill."""
    for template in TEMPLATES.get(name, TEMPLATES["unrecognized"]):
        pieces = fill(template, slots)
        if pieces is not None:
            return pieces
    return ["call", "a", "contract"]


def plan_class(names: list[str]) -> str:
    """The class of a whole plan, from the classes of its calls.

    An approval before the action it exists for is not a plan about approving:
    the owner is being asked for the swap. So a leading approval is absorbed,
    and only a genuinely mixed plan reads as a batch.
    """
    if not names:
        return "unrecognized"
    meaningful = [name for name in names if name not in ("approval", "unrecognized")]
    if not meaningful:
        return names[0]
    if len(set(meaningful)) == 1:
        return meaningful[0]
    return "batch"


def join_summaries(summaries: list[list[str]]) -> list[str]:
    """Join per-call summaries into one sentence.

    Capped rather than concatenated without limit: a plan of twenty calls gets
    its first two named and the rest counted, because a sentence that lists
    twenty things is not a summary.
    """
    if not summaries:
        return ["call", "a", "contract"]
    if len(summaries) == 1:
        return summaries[0]
    if len(summaries) == 2:
        return summaries[0] + [","] + ["then"] + summaries[1]
    remaining = len(summaries) - 2
    tail = ["and", str(remaining), "more", "calls"] if remaining > 1 else ["and", "1", "more", "call"]
    return summaries[0] + [","] + ["then"] + summaries[1] + tail


def label(example: dict[str, Any], intents: dict[str, str | None]) -> dict[str, Any] | None:
    """Attach a class, a risk band, and a summary to one generated example."""
    # A call the registry describes is classified from its human-authored
    # intent. One it does not -- a standard token call, an opaque target -- is
    # classified from the deterministic reading instead, which is what the
    # model will have to do at inference for every protocol not vendored here.
    descriptions = example.get("call_descriptions", [])
    names = [
        classify(intents.get(key) or (descriptions[index] if index < len(descriptions) else None))
        for index, key in enumerate(example["formats"])
    ]
    per_call: list[list[str]] = []
    for call in range(len(names)):
        slots = [
            (index, kind)
            for index, (kind, owner) in enumerate(
                zip(example["slot_kinds"], example["slot_calls"], strict=True)
            )
            if owner == call
        ]
        per_call.append(summarize(names[call], slots))
    # Every reference a call's summary makes must be to a slot that call
    # produced. This is the invariant the plan-global indexing above exists to
    # keep, and it is checked rather than trusted: getting it wrong is silent,
    # and what it produces is a fluent sentence naming another call's address.
    for call, pieces in enumerate(per_call):
        for piece in pieces:
            if not piece.startswith("<s"):
                continue
            index = int(piece[2:-1])
            owner = example["slot_calls"][index]
            if owner != call:
                raise ValueError(
                    f"call {call} referenced {piece}, which belongs to call {owner}"
                )
    summary = join_summaries(per_call)
    # A tail count is prose, not a value the model may invent, so the digits
    # written above must not reach the summary. Anything numeric is dropped
    # here rather than entering the vocabulary through the back door.
    summary = [piece for piece in summary if not piece[:1].isdigit()]
    name = plan_class(names)
    labeled = dict(example)
    labeled["class"] = name
    labeled["risk"] = risk_of(name, example.get("warnings", []), example.get("has_value", False))
    labeled["summary_pieces"] = summary
    return labeled


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--spec", type=pathlib.Path, required=True)
    parser.add_argument("--corpus", type=pathlib.Path, required=True)
    parser.add_argument("--out", type=pathlib.Path, required=True)
    arguments = parser.parse_args()

    spec = json.loads(arguments.spec.read_text(encoding="utf-8"))
    intents = {f"{entry['descriptor']}::{entry['canonical']}": entry["intent"] for entry in spec}

    written = 0
    classes: dict[str, int] = {}
    with arguments.out.open("w", encoding="utf-8") as out:
        for line in arguments.corpus.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            labeled = label(json.loads(line), intents)
            if labeled is None:
                continue
            classes[labeled["class"]] = classes.get(labeled["class"], 0) + 1
            out.write(json.dumps(labeled) + "\n")
            written += 1

    print(f"labeled {written} examples", file=sys.stderr)
    for name, count in sorted(classes.items(), key=lambda item: -item[1]):
        print(f"  {name:18} {count}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
