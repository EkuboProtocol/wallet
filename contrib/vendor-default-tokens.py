#!/usr/bin/env python3
"""Refresh the vendored curated token list that ships inside the binary.

The wallet never fetches a token list at runtime: the default tokens are
compiled in, and this script is the only step that reaches the network. It is
run deliberately, and its output is committed, so the names a release will
display as trusted are reviewable in a diff before they ship — the same reason
`clearsign/` is vendored rather than downloaded by `build.rs`.

That matters more here than it looks. A confirmed token is exactly what lets
the wallet render a symbol instead of a bare address at approval time, so the
contents of this file decide which addresses a reviewer sees the word "USDC"
next to. Downloading it during the build would make that set whatever the
network returned on build day, unreviewed and unpinned.

What it drops, and why:

  * logo URLs, which this wallet has no way to display;
  * `visibility_priority` and `sort_order`, which are interface ranking hints;
  * every non-EVM row — the Starknet entries carry felt addresses that are not
    20-byte EVM addresses, and `parse_token_list` would skip them anyway.

What it keeps is renamed to the field names `parse_token_list` already
accepts, so the embedded list is parsed by exactly the same hardened code path
as a list the owner imports by hand.

Usage:

    contrib/vendor-default-tokens.py            # refresh from the default URL
    contrib/vendor-default-tokens.py --check    # verify the vendored copy is current
"""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import sys
import urllib.request

SOURCE_URL = (
    "https://raw.githubusercontent.com/EkuboProtocol/default-tokens/"
    "refs/heads/main/curated-tokens.json"
)

VENDORED = (
    pathlib.Path(__file__).resolve().parent.parent
    / "crates"
    / "ekubo-wallet-core"
    / "default-tokens.json"
)

# The name recorded as the source of every seeded row. It reaches the token
# review and search screens, so it reads as a provenance claim rather than a
# file name.
LIST_NAME = "Ekubo curated defaults"


def is_evm_address(value: str) -> bool:
    """Whether `value` is a 20-byte hex address this wallet can represent."""
    if not value.startswith("0x") or len(value) != 42:
        return False
    try:
        int(value[2:], 16)
    except ValueError:
        return False
    return True


def chain_id_of(entry: dict) -> int | None:
    """Read a chain ID written as a number, a decimal string, or 0x-hex.

    Starknet rows spell their chain as `0x534e5f4d41494e` — ASCII "SN_MAIN"
    rather than a number — which parses as hex perfectly well. Those rows are
    excluded by their address, not by this, so nothing here has to know which
    ecosystems exist.
    """
    raw = entry.get("chain_id", entry.get("chainId"))
    if isinstance(raw, int):
        return raw
    if isinstance(raw, str):
        text = raw.strip()
        try:
            return int(text, 16) if text.lower().startswith("0x") else int(text)
        except ValueError:
            return None
    return None


def normalize(upstream: bytes) -> dict:
    """Turn the upstream list into the vendored shape."""
    document = json.loads(upstream)
    entries = document["tokens"] if isinstance(document, dict) else document

    tokens = []
    skipped_non_evm = 0
    for entry in entries:
        address = entry.get("token_address", entry.get("address", ""))
        if not is_evm_address(address):
            skipped_non_evm += 1
            continue
        chain_id = chain_id_of(entry)
        if chain_id is None or chain_id <= 0:
            skipped_non_evm += 1
            continue
        symbol = (entry.get("token_symbol") or entry.get("symbol") or "").strip()
        if not symbol:
            # An empty symbol is refused by the store anyway; dropping it here
            # keeps the vendored file to rows that can actually be seeded.
            continue
        name = (entry.get("token_name") or entry.get("name") or "").strip()
        decimals = entry.get("token_decimals", entry.get("decimals"))
        if not isinstance(decimals, int) or not 0 <= decimals <= 255:
            continue
        tokens.append(
            {
                "chain_id": chain_id,
                # Lowercased because the `tokens` table stores and CHECKs the
                # lowercase form, so the vendored bytes match what is inserted.
                "address": address.lower(),
                "symbol": symbol,
                "name": name or None,
                "decimals": decimals,
            }
        )

    # Sorted so a refresh produces a diff of what actually changed rather than
    # a reordering of everything.
    tokens.sort(key=lambda token: (token["chain_id"], token["address"]))

    duplicates = len(tokens) - len({(t["chain_id"], t["address"]) for t in tokens})
    if duplicates:
        raise SystemExit(f"upstream list holds {duplicates} duplicate (chain, address) pairs")

    return {
        "name": LIST_NAME,
        # Provenance, not configuration: nothing reads these at runtime. The
        # digest pins the exact upstream bytes this snapshot was cut from, so
        # a refresh that changes nothing is visibly a no-op. There is no
        # timestamp here on purpose — it would churn the diff on every run
        # and record nothing the digest does not already say.
        "source_url": SOURCE_URL,
        "source_sha256": hashlib.sha256(upstream).hexdigest(),
        "skipped_non_evm": skipped_non_evm,
        "tokens": tokens,
    }


def render(document: dict) -> str:
    return json.dumps(document, indent=2, ensure_ascii=False) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", default=SOURCE_URL, help="token list to vendor")
    parser.add_argument(
        "--check",
        action="store_true",
        help="fail if the vendored copy differs from the upstream list",
    )
    arguments = parser.parse_args()

    with urllib.request.urlopen(arguments.url, timeout=60) as response:
        upstream = response.read()

    document = normalize(upstream)
    rendered = render(document)

    if arguments.check:
        current = VENDORED.read_text(encoding="utf-8") if VENDORED.exists() else ""
        if current != rendered:
            print(
                f"{VENDORED} is stale; run contrib/vendor-default-tokens.py",
                file=sys.stderr,
            )
            return 1
        print(f"{VENDORED} is current ({len(document['tokens'])} tokens)")
        return 0

    VENDORED.write_text(rendered, encoding="utf-8")
    print(
        f"wrote {VENDORED}: {len(document['tokens'])} EVM tokens, "
        f"{document['skipped_non_evm']} non-EVM rows dropped"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
