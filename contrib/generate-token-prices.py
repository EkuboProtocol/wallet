#!/usr/bin/env python3
"""Vendor the approximate token values the wallet ships with.

The Portfolio tab sorts by what a holding is roughly worth and holds back the
dust, which needs a number per token. Nothing in this wallet watches a market:
these are a snapshot, taken once here, compiled into the binary, and written
into a token's row the first time that token is confirmed. The owner can
correct any of them on the token's own row, and their number is never
overwritten by this one.

That is why every value is rounded to three significant figures. A price with
fifteen digits of precision claims to be current; three digits says what it is
— an order of magnitude and a bit, good enough to sort holdings and to tell a
dollar from a thousand, and never good enough to be mistaken for a quote.

Regenerate with:

    python3 contrib/generate-token-prices.py

Reads https://prod-api.ekubo.org/tokens and writes
crates/ekubo-wallet-core/token-prices.json. Pass --check to verify the
vendored file matches what the script would write, without writing it.
"""

from __future__ import annotations

import argparse
import json
import math
import sys
import urllib.request
from pathlib import Path

SOURCE = "https://prod-api.ekubo.org/tokens"
ROOT = Path(__file__).resolve().parent.parent
REGISTRY = ROOT / "crates" / "ekubo-wallet-core" / "networks.json"
VENDORED = ROOT / "crates" / "ekubo-wallet-core" / "token-prices.json"
NATIVE_ADDRESS = "0x" + "0" * 40
SIGNIFICANT_FIGURES = 3


def three_significant_figures(value: float) -> float:
    """Round to three significant figures, so the number cannot read as a quote."""
    if not math.isfinite(value) or value <= 0.0:
        raise ValueError(f"not a price: {value}")
    digits = -int(math.floor(math.log10(abs(value)))) + (SIGNIFICANT_FIGURES - 1)
    return round(value, digits)


def fetch(url: str) -> list[dict]:
    # The API refuses the default urllib agent string outright.
    request = urllib.request.Request(
        url,
        headers={
            "accept": "application/json",
            "user-agent": "ekubo-wallet-token-price-vendor",
        },
    )
    with urllib.request.urlopen(request, timeout=60) as response:
        payload = json.load(response)
    if not isinstance(payload, list):
        raise SystemExit(f"{url} did not answer with a list of tokens")
    return payload


def registry_chains() -> dict[int, str | None]:
    """Every chain the wallet knows, with the symbol of its native currency.

    Prices for chains this wallet cannot be configured for are dropped: they
    would be bytes in every binary that nothing can ever look up.
    """
    registry = json.loads(REGISTRY.read_text())
    chains = {}
    for chain in registry["chains"]:
        native = chain.get("native_currency") or {}
        chains[int(chain["chain_id"])] = native.get("symbol")
    return chains


def build(feed: list[dict]) -> dict:
    chains = registry_chains()
    tokens: dict[tuple[int, str], dict] = {}
    for entry in feed:
        price = entry.get("usd_price")
        if not isinstance(price, (int, float)) or price <= 0:
            continue
        try:
            chain_id = int(str(entry["chain_id"]), 16)
        except (KeyError, ValueError):
            continue
        if chain_id not in chains:
            continue
        address = str(entry.get("address", "")).lower()
        if not address.startswith("0x") or len(address) != 42:
            continue
        tokens[(chain_id, address)] = {
            "chain_id": chain_id,
            "address": address,
            "symbol": str(entry.get("symbol", "")),
            "usd_price": three_significant_figures(float(price)),
        }

    # A chain's own currency is the balance every other row on that chain needs
    # in order to move, and most chains' feed entry for it carries no price of
    # its own. The same asset is priced somewhere — ETH on mainnet is the ETH
    # an L2 charges gas in — so the symbol carries the value across, from the
    # symbol in this wallet's own network registry rather than from anything a
    # token list claims. The result is written out here rather than inferred at
    # run time, so what ships is exactly what can be read in this file.
    priced_by_symbol: dict[str, float] = {}
    for token in sorted(
        tokens.values(),
        # A native entry first, then the lowest chain ID, so the choice is
        # deterministic and prefers the asset in its own right.
        key=lambda token: (token["address"] != NATIVE_ADDRESS, token["chain_id"]),
    ):
        priced_by_symbol.setdefault(token["symbol"], token["usd_price"])

    natives = []
    for chain_id, symbol in sorted(chains.items()):
        if symbol is None:
            continue
        price = tokens.get((chain_id, NATIVE_ADDRESS), {}).get(
            "usd_price"
        ) or priced_by_symbol.get(symbol)
        if price is None:
            continue
        natives.append({"chain_id": chain_id, "symbol": symbol, "usd_price": price})

    return {
        "source": SOURCE,
        "note": (
            "A snapshot, not a feed. Values are US dollars per whole token, "
            "rounded to three significant figures, and are used only to order "
            "the Portfolio tab and to decide which balances it holds back as "
            "dust. Regenerate with contrib/generate-token-prices.py."
        ),
        "tokens": [
            tokens[key] for key in sorted(tokens, key=lambda key: (key[0], key[1]))
        ],
        "natives": natives,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="fail if the vendored file is not what this script would write",
    )
    arguments = parser.parse_args()

    document = json.dumps(build(fetch(SOURCE)), indent=2, sort_keys=False) + "\n"
    if arguments.check:
        if not VENDORED.exists() or VENDORED.read_text() != document:
            print(
                f"{VENDORED} is stale; rerun contrib/generate-token-prices.py",
                file=sys.stderr,
            )
            return 1
        return 0
    VENDORED.write_text(document)
    print(f"wrote {VENDORED}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
