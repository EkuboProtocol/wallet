#!/usr/bin/env python3
"""Build a deterministic, block-compressed offline index from ethereum-lists/4bytes."""

import argparse
import hashlib
import json
import re
import struct
import tarfile
import zlib
from pathlib import Path

REVISION = "2b8a705fe27833b59aac2a2af5d14e0144e1e56e"
ROOT = Path(__file__).resolve().parents[1]
DEST = ROOT / "crates/ekubo-wallet-core/fourbyte"
BLOCK_SELECTORS = 128


def read_source(archive):
    signatures = {}
    license_text = None
    with tarfile.open(archive, "r|gz") as source:
        for member in source:
            parts = member.name.split("/")
            if not member.isfile() or len(parts) < 2:
                continue
            if parts[1:] == ["LICENSE"]:
                license_text = source.extractfile(member).read()
            elif len(parts) == 3 and parts[1] == "signatures":
                if not re.fullmatch("[0-9a-f]{8}", parts[2]):
                    raise ValueError("unexpected selector filename")
                value = source.extractfile(member).read()
                # Canonical type parsing and selector validation also happen
                # at lookup; this filter excludes display control characters.
                candidates = sorted(set(value.strip().decode("ascii").split(";")))
                candidates = [
                    s for s in candidates
                    if re.fullmatch(
                        r"[A-Za-z_$][A-Za-z0-9_$]*\([A-Za-z0-9_,\[\]()]*\)",
                        s.replace(" ", ""),
                    )
                ]
                if candidates:
                    signatures[int(parts[2], 16)] = ";".join(candidates).encode()
    if license_text is None:
        raise ValueError("source license missing")
    return sorted(signatures.items()), license_text


def encode_block(rows):
    strings = bytearray()
    table = bytearray(struct.pack("<I", len(rows)))
    for selector, text in rows:
        table.extend(struct.pack("<III", selector, len(strings), len(text)))
        strings.extend(text)
    raw = bytes(table + strings)
    if len(raw) > 262144:
        raise ValueError("block exceeds runtime decompression limit")
    return zlib.compress(raw, level=9)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", type=Path, help=f"codeload tar.gz at {REVISION}")
    args = parser.parse_args()
    source_hash = hashlib.sha256(args.archive.read_bytes()).hexdigest()
    if source_hash != "d2105c611f8b36bfcc1b794917917640a69a587fe0e69a4567a8c0fb5971ccf4":
        raise ValueError("archive does not match the pinned snapshot")
    rows, license_text = read_source(args.archive)
    blocks = bytearray()
    index = bytearray()
    for start in range(0, len(rows), BLOCK_SELECTORS):
        block = encode_block(rows[start : start + BLOCK_SELECTORS])
        index.extend(struct.pack("<III", rows[start][0], len(blocks), len(block)))
        blocks.extend(block)
    output = b"EK4BYTE1" + struct.pack("<I", len(index) // 12) + index + blocks
    DEST.mkdir(exist_ok=True)
    (DEST / "signatures.bin").write_bytes(output)
    (DEST / "LICENSE").write_bytes(license_text)
    metadata = {
        "repository": "https://github.com/ethereum-lists/4bytes",
        "revision": REVISION,
        "license": "MIT",
        "source_archive_sha256": source_hash,
        "selectors": len(rows),
        "signatures": sum(text.count(b";") + 1 for _, text in rows),
        "blocks": len(index) // 12,
        "bytes": len(output),
        "sha256": hashlib.sha256(output).hexdigest(),
        "zlib": zlib.ZLIB_RUNTIME_VERSION,
    }
    (DEST / "snapshot.json").write_text(json.dumps(metadata, indent=2) + "\n")
    print(json.dumps(metadata))


if __name__ == "__main__":
    main()
