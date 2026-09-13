#!/usr/bin/env python3
"""Assemble protected DEB/NSIS installers from already-built production binaries.

Never builds Rust or installs a package. macOS uses cargo-packager directly.
"""

import argparse
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import tomllib

ROOT = Path(__file__).resolve().parents[1]
BINARIES = ("ekubo-wallet-v2", "ekubo-wallet-v2-mcp-bridge",
            "ekubo-wallet-service", "ekubo-wallet-v2-enroll")


def copy(source, root, destination, mode=0o644):
    target = root / destination
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, target)
    target.chmod(mode)


def deb(version, output):
    with tempfile.TemporaryDirectory(prefix="wallet-v2-package-") as temporary:
        work = Path(temporary)
        root = work / "root"
        for binary in BINARIES:
            directory = "usr/bin" if binary in BINARIES[:2] else "usr/lib/ekubo-wallet-v2"
            copy(output / binary, root, f"{directory}/{binary}", 0o755)
        assets = ROOT / "contrib/linux-service"
        copy(assets / "install-profile", root, "usr/lib/ekubo-wallet-v2/install-profile", 0o755)
        copy(assets / "org.ekubo.Wallet2.Owner.service.in", root,
             "usr/lib/ekubo-wallet-v2/org.ekubo.Wallet2.Owner.service.in")
        copy(assets / "README.md", root, "usr/share/doc/ekubo-wallet-v2/README.md")
        for source in assets.glob("*.service"):
            copy(source, root, f"usr/lib/systemd/system/{source.name}")
        for source in assets.glob("*.conf"):
            copy(source, root, f"usr/share/dbus-1/system.d/{source.name}")
        for suffix in ("sysusers", "tmpfiles"):
            copy(assets / f"ekubo-wallet-v2.{suffix}", root,
                 f"usr/lib/{suffix}.d/ekubo-wallet-v2.conf")
        copy(ROOT / "contrib/polkit/com.ekubo.wallet.v2.policy", root,
             "usr/share/polkit-1/actions/com.ekubo.wallet.v2.policy")
        copy(ROOT / "assets/app-icon-512.png", root,
             "usr/share/icons/hicolor/512x512/apps/ekubo-wallet-v2.png")
        copy(ROOT / "contrib/package-v2.desktop", root,
             "usr/share/applications/ekubo-wallet-v2.desktop")
        shutil.copytree(ROOT / "schemas", root / "usr/share/ekubo-wallet-v2/schemas")
        for name in ("preinst", "postinst", "prerm", "postrm"):
            copy(ROOT / f"contrib/deb-v2-{name}", root, f"DEBIAN/{name}", 0o755)
        (work / "debian").mkdir()
        (work / "debian/control").write_text("Source: ekubo-wallet-v2\n\nPackage: ekubo-wallet-v2\nArchitecture: amd64\n", encoding="utf-8")
        result = subprocess.check_output([
            "dpkg-shlibdeps", "-O",
            *(f"-e{output / binary}" for binary in BINARIES),
        ], cwd=work, text=True)
        dependencies = next(line.removeprefix("shlibs:Depends=") for line in result.splitlines()
                            if line.startswith("shlibs:Depends="))
        control = (f"Package: ekubo-wallet-v2\nVersion: {version}\nArchitecture: amd64\n"
                   "Maintainer: Ekubo, Inc. <support@ekubo.org>\n"
                   f"Depends: {dependencies}, python3, polkitd, pkexec, dbus, systemd\n"
                   "Description: Ekubo Wallet 2 protected-service desktop wallet\n")
        (root / "DEBIAN/control").write_text(control, encoding="utf-8")
        subprocess.run(["dpkg-deb", "--root-owner-group", "--build", str(root),
                        str(output / f"ekubo-wallet-v2_{version}_amd64.deb")], check=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("format", choices=("deb", "nsis"))
    args = parser.parse_args()
    with (ROOT / "Cargo.toml").open("rb") as source:
        version = tomllib.load(source)["workspace"]["package"]["version"]
    if not re.fullmatch(r"2\.\d+\.\d+", version):
        raise ValueError("native installer requires a stable v2 workspace version")
    output = ROOT / "target/release"
    suffix = ".exe" if args.format == "nsis" else ""
    binaries = BINARIES + (("ekubo-wallet-v2-owner-auth",) if args.format == "nsis" else ())
    for binary in binaries:
        if not (output / (binary + suffix)).is_file():
            raise FileNotFoundError(binary + suffix)
    if args.format == "deb":
        deb(version, output)
    else:
        subprocess.run(["makensis", f"/DVERSION={version}", str(ROOT / "contrib/windows-v2.nsi")],
                       cwd=ROOT, check=True)


if __name__ == "__main__":
    main()
