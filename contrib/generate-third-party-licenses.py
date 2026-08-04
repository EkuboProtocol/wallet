#!/usr/bin/env python3
"""Generate THIRD_PARTY_LICENSES.md from cargo metadata.

Runs `cargo metadata` against the workspace lockfile, lists every third-party
package that can end up in a shipped binary (all platforms), groups packages
by license expression, and appends the full text of each referenced license.
License texts are read from the package's own source directory when it ships
one, so per-crate copyright notices are preserved; packages without a shipped
license file fall back to a single canonical text per license family.

Usage: contrib/generate-third-party-licenses.py [--check]

--check exits nonzero when THIRD_PARTY_LICENSES.md is stale instead of
rewriting it. tests/shipped_assets.rs separately asserts the shipped document
covers every package in Cargo.lock.
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


def license_file_for(package):
    manifest_dir = Path(package["manifest_path"]).parent
    if package.get("license_file"):
        candidate = manifest_dir / package["license_file"]
        if candidate.is_file():
            return candidate
    candidates = []
    for pattern in LICENSE_FILE_PATTERNS:
        candidates.extend(manifest_dir.glob(pattern))
    # Prefer MIT/Apache-specific names deterministically, then shortest name.
    candidates = sorted(set(candidates), key=lambda path: (len(path.name), path.name))
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    return None


def normalized_expression(package):
    expression = package.get("license") or "(license file only)"
    return re.sub(r"\s+", " ", expression.replace("/", " OR ")).strip()


def main():
    check = "--check" in sys.argv[1:]
    data = metadata()
    workspace = set(data["workspace_members"])
    packages = [
        package for package in data["packages"] if package["id"] not in workspace
    ]
    packages.sort(key=lambda package: (package["name"], package["version"]))

    by_license = defaultdict(list)
    for package in packages:
        by_license[normalized_expression(package)].append(package)

    lines = [
        "# Third-Party Licenses",
        "",
        "Ekubo Wallet is distributed with the third-party Rust packages listed",
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
    for package in packages:
        path = license_file_for(package)
        if path is None:
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace").strip()
        except OSError:
            continue
        key = re.sub(r"\s+", " ", text)
        seen_texts.setdefault(key, (text, []))[1].append(
            f"{package['name']} {package['version']}"
        )

    missing = [
        package
        for package in packages
        if license_file_for(package) is None
    ]
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
        lines.append(text.replace("```", "` ` `"))
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
