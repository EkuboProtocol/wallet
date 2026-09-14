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


def check_arch_release():
    release = (ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8")
    assert "input/unsigned-linux-x86_64/*.pkg.tar.zst" in release
    assert "dist/*.deb dist/*.pkg.tar.zst" in release
    assert "test \"${#assets[@]}\" -eq 10" in release
    assert "pkg.tar.zst" in release
    assert "arch_bundles=(dist/*.pkg.tar.zst)" in release
    assert '"linux-x86_64-arch"' in release
    assert 'format:"pacman"' in release
    builder = (ROOT / "contrib/build-v2-packages.py").read_text(encoding="utf-8")
    assert "'vulkan-icd-loader'" in builder
    assert "'libglvnd'" in builder
    assert 'makensis", "/VERSION"' in builder
    assert '"3.12"' in builder
    install = (ROOT / "contrib/arch-v2.install").read_text(encoding="utf-8")
    assert "pre_upgrade()" in install
    assert "ekubo-wallet-v2-provision@*.service" in install
    assert "Complete or recover v2 enrollment before installing this package." in install
    readme = (ROOT / "contrib/linux-service/README.md").read_text(encoding="utf-8")
    assert "signed" in readme and "GitHub release" in readme
    assert "sudo pacman -U ./ekubo-wallet-v2-*.pkg.tar.zst" not in readme


def main():
    check_windows_auth_payload()
    check_arch_release()
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
