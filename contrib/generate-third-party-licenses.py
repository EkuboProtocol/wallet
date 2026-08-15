#!/usr/bin/env python3
"""Generate THIRD_PARTY_LICENSES.md from cargo metadata.

Runs `cargo metadata` against the workspace lockfile, traverses normal and
build dependencies from this workspace's roots, lists every third-party
package that can end up in a shipped binary (all platforms), groups packages
by license expression, and appends the full text of each referenced license.
License texts are read from the package's own source directory when it ships
one, so per-crate copyright notices are preserved; packages without a shipped
license file fall back to a single canonical text per license family.

Usage: contrib/generate-third-party-licenses.py [--check]

--check exits nonzero when THIRD_PARTY_LICENSES.md is stale instead of
rewriting it. License policy is enforced separately by OSV-Scanner in CI; this
script only maintains the complete attribution document bundled with the app.
"""

import json
import re
import subprocess
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUTPUT = ROOT / "THIRD_PARTY_LICENSES.md"

LICENSE_FILE_PATTERNS = (
    "LICENSE*",
    "LICENCE*",
    "COPYING*",
    "NOTICE*",
    "license*",
)

CANONICAL_FALLBACKS = {
    "MIT": "MIT License: https://opensource.org/license/mit",
    "Apache-2.0": "Apache License 2.0: https://www.apache.org/licenses/LICENSE-2.0",
    "BSD-2-Clause": "BSD 2-Clause License: https://opensource.org/license/bsd-2-clause",
    "BSD-3-Clause": "BSD 3-Clause License: https://opensource.org/license/bsd-3-clause",
    "ISC": "ISC License: https://opensource.org/license/isc-license-txt",
    "Zlib": "zlib License: https://opensource.org/license/zlib",
    "MPL-2.0": "Mozilla Public License 2.0: https://www.mozilla.org/en-US/MPL/2.0/",
    "Unicode-3.0": "Unicode License v3: https://www.unicode.org/license.txt",
    "CC0-1.0": "CC0 1.0 Universal: https://creativecommons.org/publicdomain/zero/1.0/legalcode",
    "Unlicense": "The Unlicense: https://unlicense.org/UNLICENSE",
    "0BSD": "Zero-Clause BSD: https://opensource.org/license/0bsd",
    "BSL-1.0": "Boost Software License 1.0: https://www.boost.org/LICENSE_1_0.txt",
}

def metadata():
    result = subprocess.run(
        ["cargo", "metadata", "--format-version", "1", "--locked"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    return json.loads(result.stdout)


def license_files_for(package):
    manifest_dir = Path(package["manifest_path"]).parent

    candidates = []
    declared = None
    if package.get("license_file"):
        declared = manifest_dir / package["license_file"]
        if declared.is_file():
            candidates.append(declared)
    for pattern in LICENSE_FILE_PATTERNS:
        candidates.extend(manifest_dir.glob(pattern))
    # Deterministic order: shortest name first, then alphabetical. A
    # declared file that the glob also matched only appears once -- `set`
    # first -- so it does not get a tiebreak advantage from being listed
    # twice.
    candidates = sorted(
        (path for path in set(candidates) if path.is_file()),
        key=lambda path: (len(path.name), path.name),
    )
    if not candidates:
        return []
    # `OR` in the expression means any one text satisfies it (a dual-licensed
    # crate needs only its shorter file), but `AND` means every named license
    # is a separate, independent obligation -- `ring`'s `Apache-2.0 AND ISC`
    # and `unicode-ident`'s `... AND Unicode-3.0` each ship one file per
    # family. Picking only one file for those silently drops a required
    # text, so `AND` takes every file the crate ships instead of one. That
    # can include a file which is not itself license text -- ring's
    # shortest, `LICENSE`, only points at the other two -- but shipping an
    # extra paragraph is a far smaller fault than omitting a required one,
    # and the alternative is guessing which files are "real" from their
    # contents, which is itself as likely to guess wrong.
    if " AND " in normalized_expression(package):
        return candidates
    # No `AND`: one file is enough. Prefer the crate's own declared file --
    # it is the crate's own claim about which text applies -- over whichever
    # the glob's shortest-name tiebreak happened to find.
    if declared is not None and declared in candidates:
        return [declared]
    return candidates[:1]


def normalized_expression(package):
    expression = package.get("license") or "(license file only)"
    return re.sub(r"\s+", " ", expression.replace("/", " OR ")).strip()


def reachable_packages(data):
    """Return packages reachable through non-dev edges from workspace roots.

    Git workspace dependencies such as Zed cause `cargo metadata` to describe
    many sibling packages which this application never links. Listing every
    metadata package both obscures the actual audit and can incorrectly assign
    an unrelated sibling crate's license to the wallet.
    """
    nodes = {node["id"]: node for node in data["resolve"]["nodes"]}
    reachable = set()
    pending = list(data["workspace_members"])
    while pending:
        package_id = pending.pop()
        if package_id in reachable:
            continue
        reachable.add(package_id)
        node = nodes.get(package_id)
        if node is None:
            continue
        for dependency in node["deps"]:
            kinds = dependency.get("dep_kinds") or [{"kind": None}]
            if any(kind.get("kind") != "dev" for kind in kinds):
                pending.append(dependency["pkg"])
    return [
        package
        for package in data["packages"]
        if package["id"] in reachable
    ]


def main():
    check = "--check" in sys.argv[1:]
    data = metadata()
    workspace = set(data["workspace_members"])
    packages = [
        package for package in reachable_packages(data) if package["id"] not in workspace
    ]
    packages.sort(key=lambda package: (package["name"], package["version"]))

    by_license = defaultdict(list)
    for package in packages:
        by_license[normalized_expression(package)].append(package)

    lines = [
        "# Third-Party Licenses",
        "",
        "Ekubo Wallet is © Ekubo, Inc. It is distributed with the third-party",
        "Rust packages listed",
        "below (all supported platforms combined). Each package is listed with",
        "its license expression; the full text of each package-shipped license",
        "file follows in the appendix. Regenerate this document with",
        "`contrib/generate-third-party-licenses.py`.",
        "",
    ]

    for expression in sorted(by_license):
        lines.append(f"## {expression}")
        lines.append("")
        for package in by_license[expression]:
            source = package.get("repository") or package.get("homepage") or ""
            suffix = f" — {source}" if source else ""
            authors = ", ".join(package.get("authors") or [])
            author_suffix = f" — {authors}" if authors else ""
            lines.append(
                f"- {package['name']} {package['version']}{author_suffix}{suffix}"
            )
        lines.append("")

    lines.append("# Appendix: License Texts")
    lines.append("")

    seen_texts = {}
    missing = []
    for package in packages:
        files = license_files_for(package)
        if not files:
            missing.append(package)
        for path in files:
            try:
                text = path.read_text(encoding="utf-8", errors="replace").strip()
            except OSError:
                continue
            key = re.sub(r"\s+", " ", text)
            seen_texts.setdefault(key, (text, []))[1].append(
                f"{package['name']} {package['version']}"
            )
    if missing:
        lines.append("## Packages without a shipped license file")
        lines.append("")
        for package in missing:
            fallback = None
            for identifier in re.split(r"\s+(?:OR|AND|WITH)\s+", normalized_expression(package)):
                fallback = CANONICAL_FALLBACKS.get(identifier.strip("()"))
                if fallback:
                    break
            reference = fallback or "see the package repository for the license text"
            lines.append(
                f"- {package['name']} {package['version']}: "
                f"{normalized_expression(package)} — {reference}"
            )
        lines.append("")

    for text, holders in sorted(seen_texts.values(), key=lambda item: item[1][0]):
        lines.append(f"## License text for: {', '.join(holders)}")
        lines.append("")
        lines.append("```text")
        lines.append(
            "\n".join(line.rstrip() for line in text.replace("```", "` ` `").splitlines())
        )
        lines.append("```")
        lines.append("")

    document = "\n".join(lines).rstrip() + "\n"
    if check:
        current = OUTPUT.read_text(encoding="utf-8") if OUTPUT.exists() else ""
        if current != document:
            print("THIRD_PARTY_LICENSES.md is stale; regenerate it", file=sys.stderr)
            return 1
        return 0
    OUTPUT.write_text(document, encoding="utf-8")
    print(f"wrote {OUTPUT} ({len(packages)} packages)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
