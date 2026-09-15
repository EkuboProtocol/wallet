#!/usr/bin/env python3
"""Assemble protected DEB/Arch/NSIS installers from already-built production binaries.

Never builds Rust or installs a package. macOS uses cargo-packager directly.
"""

import argparse
import hashlib
import os
from pathlib import Path
import re
import shutil
import subprocess
import tarfile
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


def stage_linux_payload(output, root):
    """The sole file/path/mode manifest for both native Linux package formats."""
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
    for name in ("LICENSE", "THIRD_PARTY_LICENSES.md"):
        copy(ROOT / name, root, f"usr/share/licenses/ekubo-wallet-v2/{name}")


def deb(version, output):
    with tempfile.TemporaryDirectory(prefix="wallet-v2-package-") as temporary:
        work = Path(temporary)
        root = work / "root"
        stage_linux_payload(output, root)
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
                   f"Depends: {dependencies}, python3, polkitd, pkexec, dbus, systemd, gnome-keyring\n"
                   "Description: Ekubo Wallet 2 protected-service desktop wallet\n")
        (root / "DEBIAN/control").write_text(control, encoding="utf-8")
        subprocess.run(["dpkg-deb", "--root-owner-group", "--build", str(root),
                        str(output / f"ekubo-wallet-v2_{version}_amd64.deb")], check=True)


def stage_arch_build(version, output, work):
    """Write conventional makepkg inputs; makepkg owns all pacman metadata."""
    root = work / "payload"
    stage_linux_payload(output, root)
    # Arch-only exception to the DEB/Arch payload parity above: libalpm
    # discards install-scriptlet exit status, so the upgrade guard must be a
    # PreTransaction hook under usr/share/libalpm/hooks. DEB needs no hook
    # because its preinst maintainer script can abort, so the DEB payload is
    # unaffected and stage_linux_payload stays the single common manifest.
    copy(ROOT / "contrib/arch-v2-pretransaction.hook", root,
         "usr/share/libalpm/hooks/ekubo-wallet-v2-pretransaction.hook")

    def normalize(info):
        info.uid = info.gid = 0
        info.uname = info.gname = "root"
        info.mtime = int(os.environ.get("SOURCE_DATE_EPOCH", "0"))
        # Directory permissions must not inherit a restrictive builder umask.
        if info.isdir():
            info.mode = 0o755
        return info

    archive = work / "payload.tar"
    with tarfile.open(archive, "w", format=tarfile.GNU_FORMAT) as bundle:
        bundle.add(root / "usr", arcname="usr", filter=normalize)
    with archive.open("rb") as source:
        digest = hashlib.file_digest(source, "sha256").hexdigest()
    copy(ROOT / "contrib/arch-v2.install", work, "arch-v2.install")
    (work / "PKGBUILD").write_text(f"""# Generated from the shared v2 Linux release payload; no Rust build.
pkgname=ekubo-wallet-v2
pkgver={version}
pkgrel=1
pkgdesc='Ekubo Wallet 2 protected-service desktop wallet'
arch=('x86_64')
url='https://ekubo.org'
license=('LicenseRef-FSL-1.1-MIT')
# Runtime libraries for the Ubuntu-built ELF payload, plus service enrollment.
# gnome-keyring is a hard dependency: the Secret Service provider for owner
# credentials and legacy-wallet migration must always be present.
depends=('alsa-lib' 'fontconfig' 'glib2' 'glibc' 'gcc-libs' 'gnome-keyring'
         'libx11' 'libxcb' 'libxkbcommon' 'libxkbcommon-x11' 'wayland' 'openssl'
         'zlib' 'xdotool' 'libsecret' 'dbus' 'polkit' 'systemd' 'python'
         'vulkan-icd-loader' 'libglvnd')
options=('!strip' '!debug')
install=arch-v2.install
source=('payload.tar')
noextract=('payload.tar')
sha256sums=('{digest}')
PKGEXT='.pkg.tar.zst'
PKGDEST="$startdir"

package() {{
    bsdtar -xf "$srcdir/payload.tar" -C "$pkgdir"
}}
""", encoding="utf-8")


def arch(version, output):
    if os.geteuid() == 0:
        raise PermissionError("run the Arch builder as a non-root user with makepkg installed")
    with tempfile.TemporaryDirectory(prefix="wallet-v2-arch-") as temporary:
        work = Path(temporary)
        stage_arch_build(version, output, work)
        subprocess.run(["makepkg", "--nodeps", "--force", "--noconfirm"], cwd=work, check=True)
        name = f"ekubo-wallet-v2-{version}-1-x86_64.pkg.tar.zst"
        shutil.copyfile(work / name, output / name)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("format", choices=("deb", "arch", "nsis"))
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
    elif args.format == "arch":
        arch(version, output)
    else:
        pinned = subprocess.check_output(["makensis", "/VERSION"], cwd=ROOT, text=True)
        if "3.12" not in pinned:
            raise RuntimeError(
                f"pinned NSIS 3.12.0 required, makensis reported: {pinned.strip()}")
        subprocess.run(["makensis", f"/DVERSION={version}", str(ROOT / "contrib/windows-v2.nsi")],
                       cwd=ROOT, check=True)


if __name__ == "__main__":
    main()
