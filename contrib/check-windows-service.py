#!/usr/bin/env python3
"""Explicit native diagnostic milestone against the real core and client crates.

No synthetic crate or migration fixture: this compiles real dependencies and
cannot substitute for the full product matrix or installed-owner acceptance.
"""

import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]


def main():
    if sys.platform != "win32":
        raise SystemExit("Run native Windows diagnostics on Windows.")
    env = dict(os.environ, RUST_MIN_STACK="67108864", CARGO_PROFILE_DEV_DEBUG="0",
               CARGO_PROFILE_TEST_DEBUG="0")
    subprocess.run(["cargo", "check", "--locked", "-p", "ekubo-wallet-core",
                    "-p", "ekubo-wallet-client", "-p", "ekubo-wallet-service", "--all-targets"],
                   cwd=ROOT, env=env, check=True)
    subprocess.run(["cargo", "test", "--locked", "-p", "ekubo-wallet-core",
                    "--lib", "windows_"], cwd=ROOT, env=env, check=True)
    subprocess.run(["cargo", "test", "--locked", "-p", "ekubo-wallet-service",
                    "--lib", "owner_stream_"], cwd=ROOT, env=env, check=True)


if __name__ == "__main__":
    main()
