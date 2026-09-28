"""Offline cases for the GPUI provenance check: every tampering must fail it."""

import pathlib
import runpy
import tempfile
import unittest

CHECK = runpy.run_path(str(pathlib.Path(__file__).with_name("check-gpui-provenance.py")))
REVISION = "1a28cff4b409169bac058bca40dfbfeb7621d19b"
DESCRIPTION = "Zed's `gpui_apple` crate (gpui-pre snapshot of zed@1a28cff)"
BUILD = 'fn find() -> PathBuf {\n    dir.join("../gpui")\n}\n'


def crate(library, files, description=DESCRIPTION):
    """A downloaded crate, built without the network."""
    published = CHECK["Crate"].__new__(CHECK["Crate"])
    published.name = published.label = library
    published.files = {"Cargo.toml": b"", **files}
    published.manifest = {"lib": {"name": library}}
    published.description = description
    return published


class ProvenanceTest(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.zed = pathlib.Path(directory.name)
        self.write("crates/gpui/src/scene.rs", "struct Scene;\n")
        self.write("crates/gpui_apple/build.rs", BUILD)
        self.write("crates/gpui_apple/src/lib.rs", "mod metal;\n")

    def write(self, path, text):
        (self.zed / path).parent.mkdir(parents=True, exist_ok=True)
        (self.zed / path).write_text(text)

    def check_apple(self, files, description=DESCRIPTION):
        published = crate("gpui_apple", files, description)
        return CHECK["check_zed_snapshot"](published, self.zed, "crates/gpui_apple", "crates/gpui", REVISION)

    def apple_files(self):
        return {
            "build.rs": CHECK["rewrite_apple_build"](BUILD, REVISION[:7]).encode(),
            "src/lib.rs": b"mod metal;\n",
            "vendor/gpui/src/scene.rs": b"struct Scene;\n",
        }

    def test_the_allowed_rewrite_and_vendored_gpui_pass(self):
        self.assertEqual(self.check_apple(self.apple_files()), [])

    def test_a_changed_file_fails(self):
        files = self.apple_files() | {"src/lib.rs": b"mod metal;\nmod exfiltrate;\n"}
        self.assertEqual(self.check_apple(files), ["gpui_apple: src/lib.rs differs from upstream crates/gpui_apple/src/lib.rs"])

    def test_a_change_beside_an_allowed_rewrite_fails(self):
        files = self.apple_files()
        files["build.rs"] += b"fn main() { run_payload() }\n"
        self.assertEqual(self.check_apple(files), ["gpui_apple: build.rs differs from upstream crates/gpui_apple/build.rs"])

    def test_a_changed_vendored_gpui_file_fails(self):
        files = self.apple_files() | {"vendor/gpui/src/scene.rs": b"struct Scene(u8);\n"}
        self.assertEqual(
            self.check_apple(files),
            ["gpui_apple: vendor/gpui/src/scene.rs differs from upstream crates/gpui/src/scene.rs"],
        )

    def test_an_added_file_fails(self):
        files = self.apple_files() | {"src/payload.rs": b"fn run_payload() {}\n"}
        self.assertEqual(self.check_apple(files), ["gpui_apple: src/payload.rs is not in the upstream source"])

    def test_a_snapshot_of_another_revision_fails(self):
        problems = self.check_apple(self.apple_files(), DESCRIPTION.replace("1a28cff", "52b2927"))
        self.assertEqual(problems, ["gpui_apple: the description does not name zed@1a28cff"])

    def test_a_changed_facade_module_fails(self):
        self.write("crates/gpui_macros/src/lib.rs", "")
        published = crate("gpui_macros", {CHECK["FACADE"]: b"fn rewrite() { run_payload() }\n", "src/lib.rs": b""})
        problems = CHECK["check_zed_snapshot"](published, self.zed, "crates/gpui_macros", "crates/gpui", REVISION)
        self.assertEqual(problems, [f"gpui_macros: {CHECK['FACADE']} is not the reviewed facade module"])

    def test_the_action_rewrite_touches_only_the_actions_macro(self):
        source = (
            "#[derive(::std::fmt::Debug, gpui::Action)]\n"
            "#[derive(Clone, Debug, PartialEq, Deserialize, JsonSchema, gpui::Action)]\n"
        )
        rewritten = CHECK["rewrite_action"](source, "1a28cff").splitlines()
        self.assertEqual(rewritten[1:], ["#[derive(::std::fmt::Debug, $crate::Action)]", source.splitlines()[1]])

    def test_the_macro_rewrite_wraps_each_entry_point_and_keeps_its_cfg(self):
        source = (
            '#[cfg(feature = "inspector")]\n'
            "#[proc_macro_attribute]\n"
            "pub fn reflect(args: TokenStream, input: TokenStream) -> TokenStream {\n"
            "    reflection::reflect(args, input)\n"
            "}\n"
            "pub fn helper(input: TokenStream) -> TokenStream {\n"
        )
        expected = (
            "// Modified for gpui-pre (snapshot of zed@1a28cff): the proc-macro entry points resolve gpui through a facade.\n"
            "mod gpui_pre_facade_paths;\n"
            '#[cfg(feature = "inspector")]\n'
            "#[proc_macro_attribute]\n"
            "pub fn reflect(args: TokenStream, input: TokenStream) -> TokenStream {\n"
            "    gpui_pre_facade_paths::rewrite(__gpui_pre_reflect(args, input))\n"
            "}\n"
            "\n"
            '#[cfg(feature = "inspector")]\n'
            "fn __gpui_pre_reflect(args: TokenStream, input: TokenStream) -> TokenStream {\n"
            "    reflection::reflect(args, input)\n"
            "}\n"
            "pub fn helper(input: TokenStream) -> TokenStream {\n"
        )
        self.assertEqual(CHECK["rewrite_macros"](source, "1a28cff"), expected)

    def test_the_vendored_tokio_must_be_zeds_below_its_header(self):
        self.write("crates/gpui_tokio/src/gpui_tokio.rs", "pub fn init() {}\n")
        self.write("crates/gpui_tokio/LICENSE-APACHE", "Apache\n")
        vendored = self.zed / "vendored"
        (vendored / "src").mkdir(parents=True)
        (vendored / "LICENSE-APACHE").write_text("Apache\n")
        check = CHECK["check_vendored_tokio"]
        (vendored / "src/lib.rs").write_text(f"//! Copied from zed@{REVISION}.\n\npub fn init() {{}}\n")
        self.assertEqual(check(self.zed, REVISION, vendored), [])
        (vendored / "src/lib.rs").write_text(f"//! Copied from zed@{REVISION}.\n\npub fn init() {{ spawn() }}\n")
        self.assertEqual(
            check(self.zed, REVISION, vendored),
            ["crates/gpui-tokio: src/lib.rs differs from Zed's gpui_tokio.rs below its header"],
        )


if __name__ == "__main__":
    unittest.main()
