#!/usr/bin/env python3
"""Reject mutable GitHub Actions references in privileged workflows."""

import pathlib
import re
import sys

SHA = re.compile(r"^[0-9a-f]{40}$")
USES = re.compile(r"^\s*-?\s*uses:\s*([^\s#]+)")

failures = []
for workflow in [
    pathlib.Path(".github/workflows/release.yml"),
    pathlib.Path(".github/workflows/release-policy.yml"),
]:
    for number, line in enumerate(workflow.read_text().splitlines(), 1):
        match = USES.match(line)
        if not match or match.group(1).startswith("./"):
            continue
        reference = match.group(1).rsplit("@", 1)[-1]
        if not SHA.fullmatch(reference):
            failures.append(f"{workflow}:{number}: mutable action reference {match.group(1)}")

if failures:
    print("\n".join(failures), file=sys.stderr)
    sys.exit(1)
