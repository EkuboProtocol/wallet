#!/usr/bin/env python3
"""Run native platform tests without the wallet/desktop dependency graph.

Production source and adjacent tests are included by path, never copied or
reimplemented. Full workspace CI remains required for integration coverage.
"""

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import tomllib

ROOT = Path(__file__).resolve().parents[1]
CORE = ROOT / "crates" / "ekubo-wallet-core"
NAME = "ekubo-wallet-native-check"
MODULES = (
    "windows_service_identity",
    "windows_service_manager",
    "windows_security",
    "windows_service_config",
    "windows_service_storage",
    "service_profile_lock",
    "custody_envelope",
    "custody_staging",
    "database_staging",
    "service_custody",
    "windows_service_custody",
    "windows_owner_pipe",
)
DEPENDENCIES = ("anyhow", "chacha20poly1305", "fs2", "hex", "rand", "serde",
                "serde_json", "sha2", "subtle", "tempfile", "tokio", "uuid", "windows", "zeroize")


def read_toml(path):
    with path.open("rb") as source:
        return tomllib.load(source)


def toml_value(value):
    if isinstance(value, dict):
        fields = (f"{json.dumps(key)} = {toml_value(item)}" for key, item in value.items())
        return "{ " + ", ".join(fields) + " }"
    return json.dumps(value, ensure_ascii=False)


def locked_dependencies(manifest, lock):
    core = next(package for package in lock["package"] if package["name"] == "ekubo-wallet-core")
    declarations = dict(manifest["dependencies"])
    declarations.update(manifest["target"]['cfg(target_os = "windows")']["dependencies"])
    result = {}
    for name in DEPENDENCIES:
        reference = next(item.split() for item in core["dependencies"] if item.split()[0] == name)
        packages = [
            package for package in lock["package"]
            if package["name"] == name and (len(reference) == 1 or package["version"] == reference[1])
        ]
        if len(packages) != 1:
            raise ValueError(f"ambiguous locked dependency: {name}")
        declared = declarations[name]
        specification = dict(declared) if isinstance(declared, dict) else {}
        specification["version"] = "=" + packages[0]["version"]
        result[name] = specification
    return result


def write_manifest(directory, lock):
    manifest = read_toml(CORE / "Cargo.toml")
    lines = ["[package]", f'name = "{NAME}"', 'version = "0.0.0"',
             'edition = "2024"', "publish = false", "[workspace]", "[dependencies]"]
    for name, specification in locked_dependencies(manifest, lock).items():
        lines.append(f"{name} = {toml_value(specification)}")
    for group, settings in read_toml(ROOT / "Cargo.toml")["workspace"]["lints"].items():
        lines.append(f"[lints.{group}]")
        lines.extend(f"{name} = {toml_value(value)}" for name, value in settings.items())
    (directory / "Cargo.toml").write_text("\n".join(lines) + "\n", encoding="utf-8")
    (directory / "clippy.toml").write_bytes((CORE / "clippy.toml").read_bytes())


def fingerprint(package):
    return tuple(package.get(key) for key in ("name", "version", "source", "checksum"))


def verify_lock(directory, original):
    approved = {fingerprint(package) for package in original["package"]}
    for package in read_toml(directory / "Cargo.lock")["package"]:
        if package["name"] == NAME and package["version"] == "0.0.0" and "source" not in package:
            continue
        if fingerprint(package) not in approved:
            raise ValueError(f"native check resolved a dependency outside Cargo.lock: {package['name']}")


def prepare(output_root):
    directory = Path(tempfile.mkdtemp(prefix="ekubo-native-", dir=output_root))
    lock = read_toml(ROOT / "Cargo.lock")
    write_manifest(directory, lock)
    (directory / "Cargo.lock").write_bytes((ROOT / "Cargo.lock").read_bytes())
    (directory / "src").mkdir()
    source = ['#![cfg(target_os = "windows")]']
    for module in MODULES:
        path = (CORE / "src" / f"{module}.rs").resolve(strict=True)
        # This adapter's crate-private callers live in the full core storage,
        # presence, and migration modules, which this harness excludes.
        if module in ("windows_service_custody", "database_staging"):
            source.append("#[allow(dead_code)]")
        source.extend([f"#[path = {json.dumps(path.as_posix(), ensure_ascii=False)}]", f"pub mod {module};"])
    (directory / "src" / "lib.rs").write_text("\n".join(source) + "\n", encoding="utf-8")
    # Cargo may prune unrelated workspace packages and add this harness entry.
    # Reuse the existing lock, then reject any version/source/checksum change
    # before compiling or executing code. Subsequent commands use --locked.
    subprocess.run(["cargo", "metadata", "--format-version=1"], cwd=directory,
                   check=True, stdout=subprocess.DEVNULL)
    verify_lock(directory, lock)
    return directory


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-root", type=Path, required=True)
    parser.add_argument("--prepare-only", action="store_true")
    args = parser.parse_args()
    if sys.platform != "win32" and not args.prepare_only:
        parser.error("native tests must run on Windows; use --prepare-only to inspect the harness")
    directory = prepare(args.output_root.resolve(strict=True))
    print(f"Native test harness: {directory}", flush=True)
    if args.prepare_only:
        return
    env = dict(os.environ, CARGO_TARGET_DIR=str(directory / "target"), RUST_MIN_STACK="67108864")
    subprocess.run(["cargo", "clippy", "--locked", "--all-targets", "--", "-D", "warnings"],
                   cwd=directory, env=env, check=True)
    subprocess.run(["cargo", "test", "--locked"], cwd=directory, env=env, check=True)


if __name__ == "__main__":
    main()
