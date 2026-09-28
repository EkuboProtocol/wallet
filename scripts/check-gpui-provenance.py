#!/usr/bin/env python3
"""Check that the locked GPUI crates are the upstream source they claim to be.

The `gpui-pre-*` crates are snapshots of Zed that the gpui-component
maintainers publish to crates.io; Zed does not publish them. This downloads
every locked `gpui-pre-*` and gpui-component crate from static.crates.io,
checks it against its Cargo.lock checksum, and compares it file by file with
the upstream commit recorded in `package.metadata.gpui-revisions`:

- `gpui-pre-*` against Zed. Exactly three mechanical rewrites are accepted.
  Each is reproduced here from Zed's file and must match byte for byte.
- `gpui-pre-reqwest` against zed-industries/reqwest at the commit its
  description names, which must be an ancestor of the commit Zed pins.
- gpui-component's crates against gpui-component at its release commit.

It also checks that the vendored `crates/gpui-tokio` is Zed's `gpui_tokio`
under a provenance header.

Every published file must match its source. Source files that a crate does not
ship are ignored, because an omitted file cannot put code into the build. The
Cargo-generated manifests are not compared. Their dependency edges are reviewed
in the Cargo.lock diff.
"""

import hashlib
import io
import json
import pathlib
import posixpath
import re
import subprocess
import sys
import tarfile
import tempfile
import tomllib
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parent.parent
ZED = "https://github.com/zed-industries/zed"
ZED_REQWEST = "https://github.com/zed-industries/reqwest"
GPUI_COMPONENT = "https://github.com/longbridge/gpui-component"
# Files that cargo writes into every package rather than copying from source.
GENERATED = {"Cargo.toml", "Cargo.toml.orig", "Cargo.lock", ".cargo_vcs_info.json", ".cargo_ok"}
# gpui-pre-macros adds this module to route macro output through a `gpui-kit`
# facade. It returns its input unchanged unless a crate named `gpui-kit` is in
# the graph, which `main` rejects. When the hash changes, re-read the module
# before updating it.
FACADE = "src/gpui_pre_facade_paths.rs"
FACADE_SHA256 = "9bf38963e6349a081996993f46b610a3bcf690fb06f9840ed7cf8221c8820b8b"
VENDORED_GPUI = "vendor/gpui/"
ENTRY_POINT = re.compile(r"pub fn (\w+)\((.*)\) -> TokenStream \{\n")


def header(short, reason):
    return f"// Modified for gpui-pre (snapshot of zed@{short}): {reason}\n"


def rewrite_action(source, short):
    """gpui's `actions!` derives `$crate::Action` rather than `gpui::Action`."""
    reason = "the `actions!` derive paths are crate-relative."
    return header(short, reason) + source.replace(
        "::std::fmt::Debug, gpui::Action)]", "::std::fmt::Debug, $crate::Action)]"
    )


def rewrite_apple_build(source, short):
    """gpui_apple's build script reads gpui's sources from `vendor/gpui`."""
    reason = "the gpui sources it reads are vendored under `vendor/gpui`."
    return header(short, reason) + source.replace('.join("../gpui")', '.join("vendor/gpui")')


def rewrite_macros(source, short):
    """Each proc-macro entry point passes its output through the facade."""
    reason = "the proc-macro entry points resolve gpui through a facade."
    output = [header(short, reason), "mod gpui_pre_facade_paths;\n"]
    attributes = []
    for line in source.splitlines(keepends=True):
        entry = ENTRY_POINT.fullmatch(line)
        if entry and any(a.startswith("#[proc_macro") for a in attributes):
            name, parameters = entry.groups()
            arguments = ", ".join(p.split(":")[0].strip() for p in parameters.split(","))
            conditions = "".join(a for a in attributes if a.startswith("#[cfg("))
            line += (
                f"    gpui_pre_facade_paths::rewrite(__gpui_pre_{name}({arguments}))\n}}\n\n"
                f"{conditions}fn __gpui_pre_{name}({parameters}) -> TokenStream {{\n"
            )
        attributes = [*attributes, line] if line.startswith(("#[", "///")) else []
        output.append(line)
    return "".join(output)


# The only files a gpui-pre crate may change, by library name and path.
REWRITES = {
    "gpui": {"src/action.rs": rewrite_action},
    "gpui_apple": {"build.rs": rewrite_apple_build},
    "gpui_macros": {"src/gpui_macros.rs": rewrite_macros},
}


def git(directory, *arguments, check=True):
    result = subprocess.run(["git", "-C", str(directory), *arguments], capture_output=True, text=True)
    if check and result.returncode:
        sys.exit(f"git {' '.join(arguments)}: {result.stderr.strip()}")
    return result


def fetch(url, revision, directory, history=False):
    """Fetch `revision` without file contents; checkout fetches only what it needs."""
    directory.mkdir()
    git(directory, "init", "-q")
    depth = [] if history else ["--depth=1"]
    git(directory, "fetch", "-q", *depth, "--filter=blob:none", url, revision)
    return directory


def checkout(directory, revision, patterns):
    git(directory, "sparse-checkout", "set", "--no-cone", *patterns)
    git(directory, "checkout", "-q", "--detach", revision)


class Crate:
    def __init__(self, package):
        self.name, self.version = package["name"], package["version"]
        self.label = f"{self.name} {self.version}"
        url = f"https://static.crates.io/crates/{self.name}/{self.name}-{self.version}.crate"
        with urllib.request.urlopen(url, timeout=120) as response:
            data = response.read()
        if hashlib.sha256(data).hexdigest() != package["checksum"]:
            sys.exit(f"{self.label}: the download does not match the Cargo.lock checksum")
        self.files = {}
        with tarfile.open(fileobj=io.BytesIO(data)) as archive:
            for member in archive.getmembers():
                if member.isfile():
                    self.files[member.name.split("/", 1)[1]] = archive.extractfile(member).read()
                elif not member.isdir():
                    sys.exit(f"{self.label}: {member.name} is not a regular file")
        self.manifest = tomllib.loads(self.files["Cargo.toml"].decode())
        self.description = self.manifest["package"].get("description", "")

    def compare(self, source, locate, rewrites=None):
        """Report every shipped file that differs from `source` after `rewrites`."""
        problems = []
        rewrites = rewrites or {}
        shipped = sorted(p for p in self.files if p not in GENERATED)
        for path in shipped:
            origin = source / locate(path)
            if not origin.is_file():
                problems.append(f"{self.label}: {path} is not in the upstream source")
                continue
            expected = origin.read_bytes()
            if path in rewrites:
                expected = rewrites[path](expected.decode()).encode()
            if self.files[path] != expected:
                problems.append(f"{self.label}: {path} differs from upstream {locate(path)}")
        if not problems:
            print(f"{self.label}: {len(shipped)} files match ({len(rewrites)} rewritten)")
        return problems


def zed_crate_directories(zed):
    """Zed's workspace members and the crates they depend on by path.

    Test fixtures elsewhere in the tree reuse library names such as `gpui`.
    """
    workspace = tomllib.loads((zed / "Cargo.toml").read_text())["workspace"]
    members = set(workspace["members"])
    directories = set(members)
    for member in members:
        dependencies = tomllib.loads((zed / member / "Cargo.toml").read_text()).get("dependencies", {})
        for dependency in dependencies.values():
            if isinstance(dependency, dict) and "path" in dependency:
                directories.add(posixpath.normpath(f"{member}/{dependency['path']}"))
    return directories


def zed_libraries(zed):
    """Map each library name among Zed's crates to its crate directories."""
    found = {}
    for directory in zed_crate_directories(zed):
        manifest = tomllib.loads((zed / directory / "Cargo.toml").read_text())
        names = {manifest["package"]["name"].replace("-", "_"), manifest.get("lib", {}).get("name")}
        for name in names - {None}:
            found.setdefault(name, set()).add(directory)
    return found


def zed_locator(directory, gpui):
    def locate(path):
        if path.startswith(VENDORED_GPUI):
            return f"{gpui}/{path.removeprefix(VENDORED_GPUI)}"
        return f"{directory}/{path}"

    return locate


def check_zed_snapshot(crate, zed, directory, gpui, revision):
    library = crate.manifest["lib"]["name"]
    short = revision[:7]
    problems = []
    if f"snapshot of zed@{short})" not in crate.description:
        problems.append(f"{crate.label}: the description does not name zed@{short}")
    files = crate.files
    if library == "gpui_macros" and FACADE in files:
        if hashlib.sha256(files.pop(FACADE)).hexdigest() != FACADE_SHA256:
            problems.append(f"{crate.label}: {FACADE} is not the reviewed facade module")
    rewrites = {
        path: lambda source, rewrite=rewrite: rewrite(source, short)
        for path, rewrite in REWRITES.get(library, {}).items()
    }
    return problems + crate.compare(zed, zed_locator(directory, gpui), rewrites)


def check_zed(temporary, revision, crates):
    """Compare every gpui-pre snapshot crate with its Zed crate at `revision`."""
    zed = fetch(ZED, revision, temporary / "zed")
    base = ["Cargo.toml", "/LICENSE-*", "/crates/gpui_tokio/"]
    checkout(zed, "FETCH_HEAD", base)
    libraries = zed_libraries(zed)
    directories = {c.name: libraries.get(c.manifest["lib"]["name"], set()) for c in crates}
    ambiguous = [f"{name}: no single Zed crate matches" for name, d in directories.items() if len(d) != 1]
    if ambiguous or len(libraries.get("gpui", ())) != 1:
        return zed, ambiguous or ["Zed has no single gpui crate"]
    directories = {name: min(d) for name, d in directories.items()}
    gpui = min(libraries["gpui"])
    checkout(zed, "FETCH_HEAD", [*base, f"/{gpui}/", *(f"/{d}/" for d in directories.values())])
    problems = []
    for crate in crates:
        problems += check_zed_snapshot(crate, zed, directories[crate.name], gpui, revision)
    return zed, problems


def check_reqwest(temporary, zed, revision, crate):
    """Compare gpui-pre-reqwest with Zed's reqwest fork at `revision`."""
    pinned = tomllib.loads((zed / "Cargo.toml").read_text())["workspace"]["dependencies"]["reqwest"]
    if pinned.get("git") != f"{ZED_REQWEST}.git":
        return [f"Zed no longer takes reqwest from {ZED_REQWEST}"]
    described = re.search(r"zed-industries/\w+@([0-9a-f]{7,40})$", crate.description)
    if not described or not revision.startswith(described.group(1)):
        return [f"{crate.label}: the description does not name zed-industries/reqwest@{revision[:7]}"]
    repository = fetch(ZED_REQWEST, pinned["rev"], temporary / "reqwest", history=True)
    if git(repository, "merge-base", "--is-ancestor", revision, "FETCH_HEAD", check=False).returncode:
        return [f"{crate.label}: {revision} is not an ancestor of Zed's reqwest pin {pinned['rev']}"]
    checkout(repository, revision, ["/*"])
    return crate.compare(repository, lambda path: path)


def component_locator(crate, base):
    """Cargo ships a readme from outside the package at the package root."""
    readme = tomllib.loads(crate.files["Cargo.toml.orig"].decode())["package"].get("readme")
    moved = {}
    if isinstance(readme, str):
        moved[posixpath.basename(readme)] = posixpath.normpath(f"{base}/{readme}")
    return lambda path: moved.get(path, f"{base}/{path}"), [f"/{base}/", *(f"/{p}" for p in moved.values())]


def check_component(temporary, revision, crates):
    """Compare gpui-component's crates with the repository at `revision`."""
    # Package licenses are symlinks to the repository's.
    problems, locators, patterns = [], {}, ["/LICENSE*"]
    for crate in crates:
        vcs = json.loads(crate.files.get(".cargo_vcs_info.json", b"{}")).get("git", {})
        if vcs.get("sha1") != revision or vcs.get("dirty"):
            problems.append(f"{crate.label}: not published from a clean gpui-component@{revision}")
            continue
        base = json.loads(crate.files[".cargo_vcs_info.json"])["path_in_vcs"]
        locators[crate.name], paths = component_locator(crate, base)
        patterns += paths
    if problems:
        return problems
    repository = fetch(GPUI_COMPONENT, revision, temporary / "gpui-component")
    checkout(repository, "FETCH_HEAD", patterns)
    for crate in crates:
        problems += crate.compare(repository, locators[crate.name])
    return problems


def check_vendored_tokio(zed, revision, crate=ROOT / "crates/gpui-tokio"):
    """crates/gpui-tokio is Zed's gpui_tokio under a `//!` provenance header."""
    lines = (crate / "src/lib.rs").read_text().splitlines(keepends=True)
    split = next((i for i, line in enumerate(lines) if not line.startswith("//!")), len(lines))
    problems = []
    if revision not in "".join(lines[:split]):
        problems.append(f"crates/gpui-tokio: the header does not name zed@{revision}")
    body = "".join(lines[split + 1 :]) if lines[split : split + 1] == ["\n"] else None
    if body != (zed / "crates/gpui_tokio/src/gpui_tokio.rs").read_text():
        problems.append("crates/gpui-tokio: src/lib.rs differs from Zed's gpui_tokio.rs below its header")
    if (crate / "LICENSE-APACHE").read_bytes() != (zed / "crates/gpui_tokio/LICENSE-APACHE").read_bytes():
        problems.append("crates/gpui-tokio: LICENSE-APACHE differs from Zed's")
    if not problems:
        print("crates/gpui-tokio: matches Zed's gpui_tokio below its header")
    return problems


def main():
    revisions = tomllib.loads((ROOT / "Cargo.toml").read_text())["package"]["metadata"]["gpui-revisions"]
    lock = tomllib.loads((ROOT / "Cargo.lock").read_text())["package"]
    if any(p["name"] == "gpui-kit" for p in lock):
        sys.exit("gpui-kit is locked, which activates the gpui-pre-macros facade; review it first")
    locked = [
        Crate(p) for p in lock if p["name"].startswith("gpui") and p.get("source", "").startswith("registry+")
    ]
    reqwest = [c for c in locked if c.name == "gpui-pre-reqwest"]
    snapshots = [c for c in locked if c.name.startswith("gpui-pre") and c not in reqwest]
    component = [c for c in locked if not c.name.startswith("gpui-pre")]
    with tempfile.TemporaryDirectory() as temporary:
        temporary = pathlib.Path(temporary)
        zed, problems = check_zed(temporary, revisions["zed"], snapshots)
        problems += check_vendored_tokio(zed, revisions["zed"])
        for crate in reqwest:
            problems += check_reqwest(temporary, zed, revisions["zed-reqwest"], crate)
        problems += check_component(temporary, revisions["gpui-component"], component)
    if problems:
        print("\n".join(problems), file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
