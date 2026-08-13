#!/usr/bin/env python3
"""Give the Claude Desktop plugin the wallet's own version.

The plugin in integrations/claude-desktop is published from the same commit as
the native wallet, on the same release, and Claude Desktop shows its manifest
version to the person installing it. Nothing at runtime negotiates on that
number -- the bridge is a fixed-protocol proxy to the loopback server -- so a
mismatch breaks nothing except the reader's ability to tell which wallet an
installed extension came with. That is exactly the kind of defect a written
instruction does not prevent: the version was already a release behind before
the bundle had ever shipped.

So the version has one source, the root Cargo.toml, and this rewrites the four
places that repeat it: the Claude plugin manifest, the npm package, and both
copies npm keeps in the lockfile. The lockfile is included because npm itself does not
mind a stale root version -- `npm ci` installs happily either way -- so the
only thing that would ever correct one is this, and the plugin's own test.

Usage: contrib/sync-claude-desktop-version.py [--check] [--expect VERSION]

--check exits nonzero when any copy is stale instead of rewriting it.
--expect additionally requires the wallet's own version to equal VERSION,
which release CI uses to hold the tag being built to the same number.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:  # Python 3.9/3.10 on older macOS installations.
    tomllib = None

ROOT = Path(__file__).resolve().parent.parent
BUNDLE = ROOT / "integrations" / "claude-desktop"

PLUGIN_MANIFEST = BUNDLE / ".claude-plugin" / "plugin.json"
PACKAGE = BUNDLE / "package.json"
LOCKFILE = BUNDLE / "package-lock.json"


def wallet_version() -> str:
    """The version the packaged desktop application is built with."""
    manifest = ROOT / "Cargo.toml"
    if tomllib is not None:
        with manifest.open("rb") as handle:
            return tomllib.load(handle)["package"]["version"]
    package = manifest.read_text().split("[package]", 1)[1].split("\n[", 1)[0]
    match = re.search(r'^version = "([^"]+)"$', package, re.MULTILINE)
    if match is None:
        raise SystemExit("Cargo.toml has no package version")
    return match.group(1)


VERSION = wallet_version()


def replace_version(text: str, indent: int, *, region: tuple[int, int] | None = None) -> str:
    """Rewrite the `"version"` line at `indent` spaces, in `region` if given.

    Edited as text rather than re-serialized JSON: the plugin manifest hand-formats
    its keyword array onto one line and npm formats the lockfile its own way,
    and neither survives a round trip through json.dumps. Exactly one line must
    match, so a file that grows a second `"version"` at the same depth fails
    here rather than being half-rewritten.
    """
    start, end = region if region else (0, len(text))
    pattern = re.compile(rf'^{" " * indent}"version": "[^"]*"', re.MULTILINE)
    matches = pattern.findall(text, start, end)
    if len(matches) != 1:
        raise SystemExit(
            f"expected exactly one version at indent {indent}, found {len(matches)}"
        )
    replacement = f'{" " * indent}"version": "{VERSION}"'
    return text[:start] + pattern.sub(replacement, text[start:end], count=1) + text[end:]


def root_package_region(lockfile: str) -> tuple[int, int]:
    """The bounds of the lockfile's own `packages[""]` entry.

    Its version sits at the same depth as every dependency's, so the anchor has
    to be the block rather than the indentation.
    """
    opening = '\n    "": {'
    start = lockfile.find(opening)
    if start < 0:
        raise SystemExit(f"{LOCKFILE.name} has no root package entry")
    end = lockfile.find("\n    },", start)
    if end < 0:
        raise SystemExit(f"{LOCKFILE.name} root package entry is unterminated")
    return start, end


def rewritten() -> dict[Path, str]:
    """Every file's wanted contents, whether or not it already has them."""
    plugin_manifest = PLUGIN_MANIFEST.read_text()
    package = PACKAGE.read_text()
    lockfile = LOCKFILE.read_text()
    lockfile = replace_version(lockfile, 2)
    lockfile = replace_version(lockfile, 6, region=root_package_region(lockfile))
    return {
        PLUGIN_MANIFEST: replace_version(plugin_manifest, 2),
        PACKAGE: replace_version(package, 2),
        LOCKFILE: lockfile,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="report stale copies without rewriting them",
    )
    parser.add_argument(
        "--expect",
        metavar="VERSION",
        help="also require the wallet version to be VERSION",
    )
    arguments = parser.parse_args()

    if arguments.expect and arguments.expect != VERSION:
        print(
            f"the wallet is version {VERSION}, not {arguments.expect}; "
            "the tag and Cargo.toml must name the same release",
            file=sys.stderr,
        )
        return 1

    stale = [
        path for path, wanted in rewritten().items() if path.read_text() != wanted
    ]

    if arguments.check:
        if stale:
            for path in stale:
                print(
                    f"{path.relative_to(ROOT)} does not carry wallet version {VERSION}",
                    file=sys.stderr,
                )
            print(
                "run contrib/sync-claude-desktop-version.py to update them",
                file=sys.stderr,
            )
            return 1
        return 0

    for path, wanted in rewritten().items():
        if path.read_text() != wanted:
            path.write_text(wanted)
            print(f"{path.relative_to(ROOT)} -> {VERSION}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
