#!/usr/bin/env python3
"""Smoke-test an MCP bridge extracted from a native package."""

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path


def fail(message: str) -> None:
    raise SystemExit(f"packaged MCP bridge verification failed: {message}")


def main() -> None:
    if len(sys.argv) != 3:
        fail("usage: verify-mcp-bridge.py <binary> <expected-version>")

    binary = Path(sys.argv[1]).resolve()
    expected_version = sys.argv[2]
    if not binary.is_file():
        fail(f"{binary} is not a file")

    frames = [
        {
            "jsonrpc": "2.0",
            "id": "package-initialize",
            "method": "initialize",
            "params": {"protocolVersion": "2025-11-25"},
        },
        {
            "jsonrpc": "2.0",
            "id": "package-tools",
            "method": "tools/list",
            "params": {},
        },
    ]
    stdin = "".join(f"{json.dumps(frame, separators=(',', ':'))}\n" for frame in frames)

    with tempfile.TemporaryDirectory(prefix="ekubo-packaged-bridge-") as data_dir:
        environment = os.environ.copy()
        environment["EKUBO_WALLET_HOME"] = data_dir
        try:
            completed = subprocess.run(
                [binary, "--client", "codex"],
                input=stdin,
                text=True,
                capture_output=True,
                timeout=15,
                env=environment,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            fail(f"could not execute {binary}: {error}")

    if completed.returncode != 0:
        fail(
            f"{binary} exited with {completed.returncode}: "
            f"{completed.stderr.strip() or '(no diagnostic)'}"
        )
    try:
        responses = [json.loads(line) for line in completed.stdout.splitlines()]
    except json.JSONDecodeError as error:
        fail(f"{binary} emitted invalid MCP JSON: {error}")
    if len(responses) != 2:
        fail(f"{binary} emitted {len(responses)} MCP frames instead of 2")

    initialized, tools = responses
    result = initialized.get("result", {})
    server = result.get("serverInfo", {})
    if initialized.get("id") != "package-initialize":
        fail("initialize response did not preserve its request ID")
    if server.get("name") != "ekubo-wallet-mcp-bridge":
        fail("initialize response has the wrong server name")
    if server.get("version") != expected_version:
        fail(
            f"initialize response reports version {server.get('version')!r}, "
            f"expected {expected_version!r}"
        )
    if result.get("capabilities", {}).get("tools", {}).get("listChanged") is not True:
        fail("initialize response does not advertise tools.listChanged")
    if tools != {
        "jsonrpc": "2.0",
        "id": "package-tools",
        "result": {"tools": []},
    }:
        fail("offline tools/list response is not the deterministic empty catalog")


if __name__ == "__main__":
    main()
