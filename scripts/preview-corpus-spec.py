#!/usr/bin/env python3
"""Enumerate every call the vendored ERC-7730 registry can interpret.

The corpus generator needs one thing this repository does not otherwise
expose: the list of (chain, contract, function signature) triples a descriptor
claims, together with the human-authored intent beside each. That is what this
writes -- a plain JSON spec the Rust generator reads to synthesize calls that
are guaranteed to match a descriptor, so every generated example exercises the
real interpretation path rather than the fallback.

Include resolution mirrors `clear_signing::resolve_includes`: an `includes`
path is relative to the including file, exactly as the registry publishes it,
and resolution is capped at the same depth. A file that fails to resolve is
reported and skipped, which costs coverage rather than producing a spec entry
the engine would not actually match.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import sys
from typing import Any

MAX_INCLUDE_DEPTH = 4


class Signature:
    """Strips parameter names from a registry format key.

    The registry writes formats the way a human reads them --
    `swap(address caller, (address src, address dst) desc)` -- but a selector
    is computed over types alone. `clear_signing::canonical_human_signature`
    does this in Rust for the engine; doing it again here is what lets the
    generator hand a signature straight to an ABI parser.

    Nothing depends on the two agreeing by inspection. The generator keeps only
    examples where the descriptor engine actually returned a reading, so a
    disagreement shows up as an entry that produced nothing -- which the
    generator counts and reports -- rather than as a silently wrong corpus.
    """

    def __init__(self, text: str) -> None:
        self.bytes = text
        self.at = 0

    def parse(self) -> str:
        """`name(type,type)`, or raise for anything this cannot read."""
        name = self.identifier()
        self.expect("(")
        types = self.type_list()
        self.expect(")")
        self.skip_space()
        if self.at != len(self.bytes):
            raise ValueError(f"trailing text in signature: {self.bytes!r}")
        return f"{name}({','.join(types)})"

    def skip_space(self) -> None:
        while self.at < len(self.bytes) and self.bytes[self.at].isspace():
            self.at += 1

    def expect(self, character: str) -> None:
        self.skip_space()
        if self.at >= len(self.bytes) or self.bytes[self.at] != character:
            raise ValueError(f"expected {character!r} in {self.bytes!r}")
        self.at += 1

    def identifier(self) -> str:
        self.skip_space()
        start = self.at
        while self.at < len(self.bytes) and (
            self.bytes[self.at].isalnum() or self.bytes[self.at] == "_"
        ):
            self.at += 1
        if self.at == start:
            raise ValueError(f"expected an identifier in {self.bytes!r}")
        return self.bytes[start:self.at]

    def type_list(self) -> list[str]:
        self.skip_space()
        if self.at < len(self.bytes) and self.bytes[self.at] == ")":
            return []
        types = [self.parameter()]
        while True:
            self.skip_space()
            if self.at >= len(self.bytes) or self.bytes[self.at] != ",":
                return types
            self.at += 1
            types.append(self.parameter())

    def parameter(self) -> str:
        """One parameter: its type, with any array suffixes, name discarded."""
        self.skip_space()
        if self.at < len(self.bytes) and self.bytes[self.at] == "(":
            self.at += 1
            inner = self.type_list()
            self.expect(")")
            written = f"({','.join(inner)})"
        else:
            written = self.identifier()
        written += self.array_suffixes()
        self.skip_space()
        # Whatever follows the type is the parameter name, which has no effect
        # on the selector or the encoding.
        if self.at < len(self.bytes) and (
            self.bytes[self.at].isalpha() or self.bytes[self.at] == "_"
        ):
            self.identifier()
            written += self.array_suffixes()
        return written

    def array_suffixes(self) -> str:
        written = ""
        while True:
            self.skip_space()
            if self.at >= len(self.bytes) or self.bytes[self.at] != "[":
                return written
            start = self.at
            self.at += 1
            while self.at < len(self.bytes) and self.bytes[self.at].isdigit():
                self.at += 1
            self.expect("]")
            written += self.bytes[start:self.at].replace(" ", "")


def merge(base: dict[str, Any], overlay: dict[str, Any]) -> dict[str, Any]:
    """Overlay one descriptor onto another, as the engine merges an include."""
    merged = dict(base)
    for key, value in overlay.items():
        existing = merged.get(key)
        if isinstance(existing, dict) and isinstance(value, dict):
            merged[key] = merge(existing, value)
        else:
            merged[key] = value
    return merged


def resolve(path: pathlib.Path, root: pathlib.Path, depth: int) -> dict[str, Any]:
    """Parse a descriptor with its `includes` chain applied."""
    document = json.loads(path.read_text(encoding="utf-8"))
    include = document.pop("includes", None)
    if include is None or depth >= MAX_INCLUDE_DEPTH:
        return document
    included = (path.parent / include).resolve()
    # Containment is checked against the vendored tree's root, not against
    # `registry/`: the published paths reach `../../ercs/…`, which is a sibling
    # of `registry/` and a legitimate target. Anything outside the tree is not.
    if not included.is_relative_to(root.resolve()) or not included.exists():
        raise ValueError(f"include {include!r} does not resolve inside the vendored tree")
    return merge(resolve(included, root, depth + 1), document)


def deployments(document: dict[str, Any]) -> list[dict[str, Any]]:
    """The (chain, address) pairs a calldata descriptor is deployed at."""
    contract = document.get("context", {}).get("contract", {})
    return [
        deployment
        for deployment in contract.get("deployments", [])
        if isinstance(deployment.get("chainId"), int)
        and isinstance(deployment.get("address"), str)
    ]


def field_specs(fields: list[Any]) -> list[dict[str, Any]]:
    """Flatten a format's fields to the label/format/path triples we label on."""
    flattened: list[dict[str, Any]] = []
    for field in fields:
        if not isinstance(field, dict):
            continue
        if isinstance(field.get("fields"), list):
            flattened.extend(field_specs(field["fields"]))
            continue
        flattened.append(
            {
                "label": field.get("label"),
                "format": field.get("format"),
                "path": field.get("path"),
            }
        )
    return flattened


def entries(path: pathlib.Path, root: pathlib.Path) -> list[dict[str, Any]]:
    """Every spec entry one descriptor file contributes."""
    document = resolve(path, root, 0)
    formats = document.get("display", {}).get("formats", {})
    if not isinstance(formats, dict):
        return []
    found = []
    for deployment in deployments(document):
        for signature, definition in formats.items():
            if not isinstance(definition, dict):
                continue
            try:
                canonical = Signature(signature).parse()
            except ValueError as error:
                print(f"skipping format {signature!r}: {error}", file=sys.stderr)
                continue
            found.append(
                {
                    "descriptor": str(path.relative_to(root)),
                    "protocol": path.parent.name,
                    "chain_id": deployment["chainId"],
                    "address": deployment["address"],
                    "signature": signature,
                    "canonical": canonical,
                    "intent": definition.get("intent"),
                    "fields": field_specs(definition.get("fields", [])),
                }
            )
    return found


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--clearsign",
        type=pathlib.Path,
        required=True,
        help="the vendored tree root, holding both registry/ and ercs/",
    )
    parser.add_argument("--out", type=pathlib.Path, required=True)
    arguments = parser.parse_args()

    spec: list[dict[str, Any]] = []
    skipped = 0
    for path in sorted((arguments.clearsign / "registry").rglob("calldata-*.json")):
        try:
            spec.extend(entries(path, arguments.clearsign))
        except (OSError, ValueError, TypeError) as error:
            print(f"skipping {path}: {error}", file=sys.stderr)
            skipped += 1

    arguments.out.parent.mkdir(parents=True, exist_ok=True)
    arguments.out.write_text(json.dumps(spec, indent=1) + "\n", encoding="utf-8")
    protocols = {entry["protocol"] for entry in spec}
    print(
        f"wrote {len(spec)} call specs across {len(protocols)} protocols "
        f"to {arguments.out} ({skipped} descriptors skipped)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
