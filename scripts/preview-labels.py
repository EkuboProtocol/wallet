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
    # `setApprovalForAll` first, both directions, because it is the single
    # most dangerous shape a wallet signs -- blanket operator control of an
    # entire collection -- and because the word-boundary rules below miss it
    # entirely: "setapprovalforall" has no boundary in front of "approve", so
    # it fell through every rule and landed on "unrecognized". A drainer
    # approval labelled as an unrecognized call is the worst outcome this
    # table can produce.
    (r"setapprovalforall.*\brevoke|setapprovalforall.*\bfalse", "revocation"),
    (r"setapprovalforall|\bblanket operator|\boperator .*\bcontrol of all", "approval"),
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

# How a call's values are attached to its verb phrase.
#
# `{verb}` is the descriptor's own human-authored intent -- "Burn vote-escrow
# NFT", "Register Group", "Claim unstaked AVAX" -- not a word invented here.
# That is the whole point of this table's shape. An earlier version wrote the
# verb itself, three phrasings per class, and the result was that every
# governance call became "vote using X" whether it registered a group or
# deaffiliated an account, and every NFT call became "transfer an nft" whether
# it minted or burned one. The model learned that faithfully, because a model
# cannot be better than what it is shown.
#
# The registry already carries a reviewed one-line intent for every format.
# Using it means the summary says what the protocol's own authors say it does,
# and this table only decides where the amounts and addresses go.
#
# Every shape exists twice: once leading with `{protocol1}` and once without.
# The protocol is the most recognizable thing in a transaction -- somebody who
# cannot read calldata still knows whether they meant to be talking to Lido --
# so a summary says it whenever the descriptor declared one, and the bare form
# is only reached for standard token calls and opaque targets, which belong to
# no protocol.
#
# Ordered: the first shape whose roles the call can fill wins. The last entry
# of each class fills nothing, so every call always has something to say.
TEMPLATES: dict[str, list[str]] = {
    "swap": [
        "{protocol1}: {verb} {amount1} for {amount2}", "{verb} {amount1} for {amount2}",
        "{protocol1}: {verb} {amount1}", "{verb} {amount1}",
        "{protocol1}: {verb} through {address1}", "{verb} through {address1}",
        "{protocol1}: {verb}", "{verb}",
    ],
    "approval": [
        "{protocol1}: {verb} letting {address1} spend {amount1}", "{verb} letting {address1} spend {amount1}",
        "{protocol1}: {verb} letting {address1} spend {token1}", "{verb} letting {address1} spend {token1}",
        "{protocol1}: {verb} for {address1}", "{verb} for {address1}",
        "{protocol1}: {verb}", "{verb}",
    ],
    "revocation": ["{protocol1}: {verb} for {address1}", "{verb} for {address1}", "{protocol1}: {verb} {token1}", "{verb} {token1}", "{protocol1}: {verb}", "{verb}"],
    "transfer": [
        "{protocol1}: {verb} {amount1} to {address1}", "{verb} {amount1} to {address1}",
        "{protocol1}: {verb} {token1} to {address1}", "{verb} {token1} to {address1}",
        "{protocol1}: {verb} to {address1}", "{verb} to {address1}",
        "{protocol1}: {verb}", "{verb}",
    ],
    "bridge": ["{protocol1}: {verb} {amount1} to {address1}", "{verb} {amount1} to {address1}", "{protocol1}: {verb} {amount1}", "{verb} {amount1}", "{protocol1}: {verb}", "{verb}"],
    "supply": [
        "{protocol1}: {verb} {amount1} to {address1}", "{verb} {amount1} to {address1}",
        "{protocol1}: {verb} {amount1}", "{verb} {amount1}",
        "{protocol1}: {verb} {token1}", "{verb} {token1}",
        "{protocol1}: {verb} to {address1}", "{verb} to {address1}",
        "{protocol1}: {verb}", "{verb}",
    ],
    "borrow": ["{protocol1}: {verb} {amount1} from {address1}", "{verb} {amount1} from {address1}", "{protocol1}: {verb} {amount1}", "{verb} {amount1}", "{protocol1}: {verb}", "{verb}"],
    "repay": ["{protocol1}: {verb} {amount1} to {address1}", "{verb} {amount1} to {address1}", "{protocol1}: {verb} {amount1}", "{verb} {amount1}", "{protocol1}: {verb}", "{verb}"],
    "withdraw": [
        "{protocol1}: {verb} {amount1} to {address1}", "{verb} {amount1} to {address1}",
        "{protocol1}: {verb} {amount1}", "{verb} {amount1}",
        "{protocol1}: {verb} {token1}", "{verb} {token1}",
        "{protocol1}: {verb} to {address1}", "{verb} to {address1}",
        "{protocol1}: {verb}", "{verb}",
    ],
    "stake": ["{protocol1}: {verb} {amount1} with {address1}", "{verb} {amount1} with {address1}", "{protocol1}: {verb} {amount1}", "{verb} {amount1}", "{protocol1}: {verb}", "{verb}"],
    "unstake": ["{protocol1}: {verb} {amount1}", "{verb} {amount1}", "{protocol1}: {verb} {token1}", "{verb} {token1}", "{protocol1}: {verb}", "{verb}"],
    "claim": ["{protocol1}: {verb} {amount1} to {address1}", "{verb} {amount1} to {address1}", "{protocol1}: {verb} {amount1}", "{verb} {amount1}", "{protocol1}: {verb}", "{verb}"],
    "liquidity_add": [
        "{protocol1}: {verb} {amount1} and {amount2}", "{verb} {amount1} and {amount2}",
        "{protocol1}: {verb} {amount1}", "{verb} {amount1}",
        "{protocol1}: {verb} to {address1}", "{verb} to {address1}",
        "{protocol1}: {verb}", "{verb}",
    ],
    "liquidity_remove": ["{protocol1}: {verb} {amount1}", "{verb} {amount1}", "{protocol1}: {verb} from {address1}", "{verb} from {address1}", "{protocol1}: {verb}", "{verb}"],
    "governance": ["{protocol1}: {verb} using {address1}", "{verb} using {address1}", "{protocol1}: {verb} {number1}", "{verb} {number1}", "{protocol1}: {verb}", "{verb}"],
    "nft": ["{protocol1}: {verb} {number1}", "{verb} {number1}", "{protocol1}: {verb} to {address1}", "{verb} to {address1}", "{protocol1}: {verb}", "{verb}"],
    "wrap_unwrap": ["{protocol1}: {verb} {amount1}", "{verb} {amount1}", "{protocol1}: {verb} {token1}", "{verb} {token1}", "{protocol1}: {verb}", "{verb}"],
    "delegation": ["{protocol1}: {verb} {amount1} to {address1}", "{verb} {amount1} to {address1}", "{protocol1}: {verb} to {address1}", "{verb} to {address1}", "{protocol1}: {verb}", "{verb}"],
    "batch": ["{protocol1}: {verb} {number1}", "{verb} {number1}", "{protocol1}: {verb}", "{verb}"],
    "unrecognized": ["call {address1}", "call an unrecognized contract"],
}

# When a call has no descriptor behind it -- a standard token call, an opaque
# target -- there is no authored intent to borrow, so the class supplies the
# verb instead. These are the only verbs this file still invents, and they
# cover calls whose meaning is fixed by the ERC rather than by a protocol.
CLASS_VERBS: dict[str, str] = {
    "swap": "swap",
    "approval": "approve",
    "revocation": "revoke",
    "transfer": "send",
    "bridge": "bridge",
    "supply": "supply",
    "borrow": "borrow",
    "repay": "repay",
    "withdraw": "withdraw",
    "stake": "stake",
    "unstake": "unstake",
    "claim": "claim",
    "liquidity_add": "provide liquidity",
    "liquidity_remove": "remove liquidity",
    "governance": "update",
    "nft": "move an nft",
    "wrap_unwrap": "wrap",
    "delegation": "delegate",
    "batch": "run batched calls",
    "unrecognized": "call an unrecognized contract",
}

# The owner prefix a descriptor puts in front of its intent: "Ekubo Protocol —
# Swap". Stripped from the verb phrase because it is lifted into a
# `<protocol>` slot instead, so the summary names it verbatim through a copy
# reference rather than through words the model could get wrong.
OWNER_SEPARATOR = "\u2014"

# A verb phrase longer than this stops being a verb phrase.
MAX_VERB_WORDS = 6

# How the tail of a long plan counts its unnamed calls. Spelled, never as
# digits: a digit here would enter the vocabulary as a word the decoder can
# emit, which is exactly the path slotization closes.
COUNT_WORDS = {1: "one", 2: "two", 3: "three", 4: "four", 5: "five", 6: "six"}

ROLE = re.compile(r"\{(protocol|amount|token|address|number|data|flag)(\d+)\}")

KIND_TAGS = {
    "protocol": "<protocol>",
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


def risk_of(name: str, warnings: list[str], has_value: bool, own: bool) -> str:
    """The attention a call warrants, from what it is rather than how it reads."""
    joined = " ".join(warnings).lower()
    if any(phrase in joined for phrase in CRITICAL_WARNINGS):
        return "critical"
    if name == "unrecognized" and has_value:
        return "critical"
    # Moving assets between two accounts this wallet holds is not the thing
    # Caution exists to flag. A reviewer can read an address; what they cannot
    # read off one is whether the other end is also theirs, which is the whole
    # reason the interpretation annotates it -- and having done so, the risk
    # band should not then treat the transfer as though it left.
    if own and name in ("transfer", "bridge"):
        return "routine"
    if name in CAUTION_CLASSES:
        return "caution"
    return "routine"


# The standard ERC calls, whose meaning is fixed by the standard rather than by
# a protocol, so the wording can be too. `setApprovalForAll` earns two entries
# of its own: the class verb "approve" produced "approve letting 0x… spend
# 0x…", which describes an allowance over one token, when what is actually
# being granted is control of every token in a collection. Getting the wording
# right matters most exactly where the transaction is most dangerous.
STANDARD_SHAPES: list[tuple[str, str, list[str]]] = [
    (
        "setapprovalforall: grant",
        "let",
        ["{verb} {address1} control every {token1}", "{verb} {address1} control every token"],
    ),
    (
        "setapprovalforall: revoke",
        "stop",
        ["{verb} {address1} controlling every {token1}", "{verb} {address1} controlling every token"],
    ),
]


def standard_shape(description: str | None) -> tuple[list[str], list[str]] | None:
    """The verb and shapes for a call the ERC defines rather than a protocol.

    Only `setApprovalForAll` so far, and it is here because the class verb got
    it badly wrong: "approve letting 0x… spend 0x…" describes an allowance over
    one token, when what is being granted is control of every token in a
    collection. The wording has to be right exactly where the transaction is
    most dangerous.
    """
    if not description:
        return None
    lowered = description.lower()
    for marker, verb, templates in STANDARD_SHAPES:
        if marker in lowered:
            return verb.split(), templates
    return None


def verb_words(intent: str | None, name: str) -> list[str]:
    """The words a summary should lead with.

    The descriptor's own intent when there is one, reduced to vocabulary words,
    with the protocol owner prefix dropped. Otherwise the class's fixed verb.
    """
    source = CLASS_VERBS.get(name, "call a contract")
    if intent:
        body = intent.split(OWNER_SEPARATOR)[-1]
        found = [word.lower() for word in re.findall(r"[A-Za-z][A-Za-z0-9]*", body)]
        if found:
            source = " ".join(found[:MAX_VERB_WORDS])
    return source.split()


def fill(template: str, slots: list[tuple[int, str]], verb: list[str]) -> list[str] | None:
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
        # A template may punctuate a placeholder -- "{protocol1}:" -- and the
        # punctuation is a piece of its own, because the renderer joins it to
        # whatever precedes it rather than treating it as part of a word.
        trailing = ""
        if word.endswith(":") or word.endswith(","):
            word, trailing = word[:-1], word[-1]
        if word == "{verb}":
            pieces.extend(verb)
            if trailing:
                pieces.append(trailing)
            continue
        match = ROLE.fullmatch(word)
        if match is None:
            pieces.append(word)
            if trailing:
                pieces.append(trailing)
            continue
        wanted, nth = KIND_TAGS[match.group(1)], int(match.group(2)) - 1
        matching = [index for index, kind in slots if kind == wanted]
        if nth >= len(matching):
            return None
        pieces.append(f"<s{matching[nth]}>")
        if trailing:
            pieces.append(trailing)
    return pieces


def summarize(
    name: str,
    slots: list[tuple[int, str]],
    intent: str | None,
    described: str | None,
) -> list[str]:
    """The first template whose roles this call can fill.

    `intent` is the descriptor's authored line and is safe to take words from:
    a human wrote it and it names no addresses. `described` is the decoded
    reading, which does name addresses, so it is only ever *matched against*
    -- never mined for words. Taking words from it put hex fragments into the
    vocabulary, doubling it from 709 entries to 1,476 and handing the decoder
    the ability to emit something that looks like an address.
    """
    standard = standard_shape(described)
    if standard is not None:
        verb, templates = standard
        for template in templates:
            pieces = fill(template, slots, verb)
            if pieces is not None:
                return pieces
    verb = verb_words(intent, name)
    for template in TEMPLATES.get(name, TEMPLATES["unrecognized"]):
        pieces = fill(template, slots, verb)
        if pieces is not None:
            return pieces
    return verb or ["call", "a", "contract"]


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
    # Spelled, not written as digits. A digit here would either enter the
    # vocabulary as a word the decoder can emit -- the one thing slotization
    # exists to prevent -- or be stripped afterwards, leaving "and more calls".
    tail = ["and", COUNT_WORDS.get(remaining, "several"), "more"]
    tail.append("call" if remaining == 1 else "calls")
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
        key = example["formats"][call] if call < len(example["formats"]) else ""
        described = descriptions[call] if call < len(descriptions) else None
        per_call.append(summarize(names[call], slots, intents.get(key), described))
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
    # Nothing in a summary may begin with a digit: it would enter the
    # vocabulary as a word the decoder can emit, which is exactly the path
    # slotization closes. The counts above are spelled for this reason, so
    # this is an assertion rather than a filter -- silently dropping a piece
    # here is what turned "and one more call" into "and more call".
    for piece in summary:
        if piece[:1].isdigit():
            raise ValueError(f"summary piece {piece!r} begins with a digit")
    name = plan_class(names)
    labeled = dict(example)
    labeled["class"] = name
    # The interpretation writes "(your account …)" beside an address it
    # recognizes as the owner's own, so that annotation is the signal.
    own = any("your account" in line for line in descriptions)
    labeled["risk"] = risk_of(
        name, example.get("warnings", []), example.get("has_value", False), own
    )
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
