#!/usr/bin/env python3
"""Write target-filtered Cargo locks for OSV-Scanner.

Cargo.lock records target-specific dependencies for every platform at once.
Scanning it directly reports packages that no shipped binary can link, such
as the macOS/Windows tray implementation's GTK dependency on Linux. Cargo's
own filtered resolve graph is authoritative for reachability, so this script
emits one minimal lockfile for each release target. OSV-Scanner remains the
engine that evaluates both vulnerabilities and licenses.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


TARGETS = (
    "aarch64-apple-darwin",
    "x86_64-pc-windows-msvc",
    "x86_64-unknown-linux-gnu",
)


def quoted(value: str) -> str:
    return json.dumps(value, ensure_ascii=False)


def filtered_lock(target: str) -> str:
    metadata = json.loads(
        subprocess.check_output(
            [
                "cargo",
                "metadata",
                "--locked",
                "--format-version",
                "1",
                "--filter-platform",
                target,
            ],
            text=True,
        )
    )
    selected_ids = {node["id"] for node in metadata["resolve"]["nodes"]}
    workspace_ids = set(metadata["workspace_members"])
    lines = ["version = 4", ""]
    for package in metadata["packages"]:
        if package["id"] not in selected_ids or package["id"] in workspace_ids:
            continue
        lines.extend(
            [
                "[[package]]",
                f'name = {quoted(package["name"])}',
                f'version = {quoted(package["version"])}',
            ]
        )
        if package.get("source"):
            lines.append(f'source = {quoted(package["source"])}')
        lines.append("")
    return "\n".join(lines)


def main() -> None:
    if len(sys.argv) != 2:
        raise SystemExit("usage: generate-osv-lockfiles.py OUTPUT_DIRECTORY")
    output = Path(sys.argv[1])
    output.mkdir(parents=True, exist_ok=True)
    for target in TARGETS:
        (output / f"Cargo.{target}.lock").write_text(
            filtered_lock(target), encoding="utf-8"
        )


if __name__ == "__main__":
    main()
