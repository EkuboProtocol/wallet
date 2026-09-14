#!/usr/bin/env python3
"""Validate cross-file v2 packaging contracts without compiling or installing."""

import ast
from pathlib import Path
import re
import tomllib
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]


def check_windows_auth_payload():
    with (ROOT / "crates/windows-owner-auth/Cargo.toml").open("rb") as source:
        helper = tomllib.load(source)["bin"][0]["name"] + ".exe"
    assert helper == "ekubo-wallet-v2-owner-auth.exe"
    for relative in ("contrib/windows-v2.nsi", ".github/workflows/build-release-artifacts.yml",
                     ".github/workflows/release.yml", "contrib/smoke-v2-nsis.ps1"):
        assert helper in (ROOT / relative).read_text(encoding="utf-8"), relative
    for relative in ("contrib/windows-v2.nsi", ".github/workflows/release.yml",
                     "contrib/install-windows-v2.ps1", "contrib/recover-windows-v2.ps1"):
        assert "register-windows-v2-auth.ps1" in (ROOT / relative).read_text(encoding="utf-8"), relative


def main():
    check_windows_auth_payload()
    assert (ROOT / 'contrib/arch-v2.install').is_file()
    assert (ROOT / 'contrib/arch-ci/Dockerfile').is_file()
    with (ROOT / "Cargo.toml").open("rb") as source:
        manifest = tomllib.load(source)
    assert manifest["workspace"]["package"]["version"].split(".")[0] == "2"
    metadata = manifest["package"]["metadata"]["packager"]
    assert metadata["identifier"] == "org.ekubo.wallet.v2"
    assert metadata["product-name"] == "Ekubo Wallet 2"
    assert manifest["bin"][0]["name"] == "ekubo-wallet-v2"
    with (ROOT / "crates/mcp-bridge/Cargo.toml").open("rb") as source:
        assert tomllib.load(source)["bin"][0]["name"] == "ekubo-wallet-v2-mcp-bridge"
    with (ROOT / "crates/ekubo-wallet-service/Cargo.toml").open("rb") as source:
        service = tomllib.load(source)
        names = {binary["name"] for binary in service.get("bin", [])}
    if service["package"].get("autobins", True) and (ROOT / "crates/ekubo-wallet-service/src/main.rs").is_file():
        names.add(service["package"]["name"])
    assert {"ekubo-wallet-service", "ekubo-wallet-v2-enroll"} <= names
    assets = ROOT / "contrib/linux-service"
    for name in ("install-profile", "ekubo-wallet-v2@.service", "ekubo-wallet-v2-provision@.service",
                 "ekubo-wallet-v2.sysusers", "ekubo-wallet-v2.tmpfiles",
                 "org.ekubo.Wallet2.Owner.conf", "org.ekubo.Wallet2.Provision.conf"):
        assert (assets / name).is_file(), name
    policy = ET.parse(ROOT / "contrib/polkit/com.ekubo.wallet.v2.policy")
    assert all(".v2." in action.attrib["id"] for action in policy.findall("action"))
    for path in (ROOT / ".github/workflows").glob("*.yml"):
        text = path.read_text(encoding="utf-8")
        assert "migration-fixture" not in text, path
        assert "check-windows-provisioning-scm" not in text, path
        for relative in re.findall(r"(?:contrib|scripts)/[\w./-]+\.(?:py|ps1|sh)", text):
            assert (ROOT / relative).is_file(), (path, relative)
    for path in (ROOT / "contrib").glob("*.py"):
        ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    print("V2 package identities, native payload interfaces, workflow references and Python syntax validated.")


if __name__ == "__main__":
    main()
