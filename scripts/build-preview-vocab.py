#!/usr/bin/env python3
"""Rebuild the learned half of the transaction-preview model's vocabulary.

The fixed half -- padding, sequence markers, structural tags, slot references
-- lives in `crates/ekubo-wallet-preview/src/vocab.rs` and is not written here:
its indices carry meaning to the rendering code, so they must not move when a
corpus is regenerated. This writes only `model/vocab.txt`, whose entries the
model is free to renumber.

Sources, in order of preference:

  * the generated corpus, when one exists, which is the ground truth for what
    the model actually sees; and
  * the vendored ERC-7730 registry's own field labels, which is where the
    corpus words come from in the first place, and which lets a checkout build
    a usable vocabulary before any corpus has been generated.

A word is kept only if it survives the same shape rule the tokenizer applies,
so nothing can enter the vocabulary that the tokenizer would never emit.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import re
import sys

# A learned piece must begin with a letter or an underscore. This is the rule
# that keeps a digit out of the vocabulary: the Rust tokenizer lifts anything
# starting with a digit into a slot, so a digit-leading entry is one the model
# could emit but the tokenizer could never have taught it -- which is exactly
# the path from the weights to a fabricated value that slotization exists to
# close. `vocab_test.rs` asserts the same rule over the committed file.
WORD = re.compile(r"[a-z_][a-z0-9_]*")
LABEL_KEYS = ("label", "intent", "title", "description")

# Punctuation the renderer knows how to place. Everything else a decoded line
# contains is dropped rather than given an entry nothing was trained to use.
PUNCTUATION = list(",.;:()%-/")

# The words a summary is written from. The corpus supplies the nouns; these are
# the verbs and connectives that make them a sentence, listed here so a summary
# can use a word the decoded field labels happen never to contain.
PROSE = """
a all an and any approve approves at authorize authorizes back balance
between borrow
borrows bridge bridges by cancel cancels claim claims collateral collect
collects contract control convert converts delegate delegates deposit deposits
each every exchange exchanges extend extends for from gives grant grants in
increase increases into it its lend lends limit lock locks merge merges mint
mints more move moves native no none now of on one onto open opens operator or
six several three two four five
other over pay pays per plus pool
position positions provide provides receive receives redeem redeems remove
removes repay repays request requests revoke revokes reward rewards sell sells
ether gas call calls unknown unnamed unrecognized than that when while with
without
send sends set sets settle settles share shares spend spender stake stakes
supply supplies swap swaps take takes then this to transfer transfers unlimited
unlock unlocks unstake unstakes unwrap unwraps up using vote votes withdraw
withdraws wrap wraps yield your
""".split()


def shaped(word: str) -> bool:
    """Whether the tokenizer could ever emit this piece as a word."""
    if not word or word.startswith("<") or WORD.fullmatch(word) is None:
        return False
    # Belt and braces against a hex blob arriving as a word: the address
    # scanner already lifts these, and an entry like `a0b86991` in the
    # vocabulary would be a value the decoder could emit.
    return "0x" not in word and not is_long_hex(word)


def is_long_hex(word: str) -> bool:
    """Whether a word is a bare run of hex digits long enough to be a value."""
    return len(word) >= 8 and all(character in "0123456789abcdef" for character in word)


def registry_words(registry: pathlib.Path) -> set[str]:
    """Every word appearing in a vendored descriptor's display labels."""
    found: set[str] = set()

    def visit(node: object) -> None:
        if isinstance(node, dict):
            for key, value in node.items():
                if key in LABEL_KEYS:
                    found.update(text_words(value))
                visit(value)
        elif isinstance(node, list):
            for item in node:
                visit(item)

    for path in sorted(registry.rglob("*.json")):
        try:
            visit(json.loads(path.read_text(encoding="utf-8")))
        except (OSError, ValueError) as error:
            print(f"skipping {path}: {error}", file=sys.stderr)
    return found


def text_words(value: object) -> set[str]:
    """The words of a label, which the registry writes as a string or a map."""
    if isinstance(value, str):
        return {word.lower() for word in re.findall(r"[A-Za-z][A-Za-z0-9_]*", value)}
    if isinstance(value, dict):
        return set().union(*(text_words(item) for item in value.values()), set())
    return set()


def corpus_words(corpus: pathlib.Path) -> set[str]:
    """The words of a corpus, read from the two fields that hold pieces.

    Deliberately not a sweep of the whole record. An example also carries its
    slot *texts* -- the verbatim amounts and addresses lifted out of the
    decoded reading -- and harvesting words from those would put the digits of
    a real value back into the vocabulary as something the decoder can emit.
    The two fields read here are already-tokenized pieces, so anything numeric
    was lifted before it got this far.
    """
    found: set[str] = set()
    with corpus.open(encoding="utf-8") as lines:
        for line in lines:
            line = line.strip()
            if not line:
                continue
            try:
                example = json.loads(line)
            except ValueError:
                continue
            for field in ("input_pieces", "summary_pieces"):
                found.update(
                    piece.lower()
                    for piece in example.get(field, [])
                    if isinstance(piece, str)
                )
    return found


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--registry", type=pathlib.Path, required=True)
    parser.add_argument("--corpus", type=pathlib.Path)
    parser.add_argument("--out", type=pathlib.Path, required=True)
    parser.add_argument(
        "--max-words",
        type=int,
        default=4096,
        help="cap on learned entries; the embedding table is sized from this",
    )
    arguments = parser.parse_args()

    words = set(PROSE) | registry_words(arguments.registry)
    if arguments.corpus and arguments.corpus.exists():
        words |= corpus_words(arguments.corpus)
    kept = sorted(word for word in words if shaped(word))[: arguments.max_words]

    arguments.out.parent.mkdir(parents=True, exist_ok=True)
    arguments.out.write_text("\n".join(PUNCTUATION + kept) + "\n", encoding="utf-8")
    print(f"wrote {len(PUNCTUATION) + len(kept)} learned pieces to {arguments.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
