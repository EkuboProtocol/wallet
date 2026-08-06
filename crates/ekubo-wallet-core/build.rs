//! Embeds every vendored clear-signing file into the binary.
//!
//! The generated `CLEARSIGN_FILES` table carries the complete `clearsign/`
//! tree — the upstream ERC-7730 registry snapshot plus the Ekubo descriptors
//! — so descriptor interpretation never touches the filesystem or network at
//! runtime, and a release artifact carries exactly what was reviewed at
//! vendoring time.

use std::{env, fmt::Write as _, fs, path::Path};

fn main() {
    println!("cargo:rerun-if-changed=clearsign");
    let manifest = env::var("CARGO_MANIFEST_DIR").expect("cargo sets CARGO_MANIFEST_DIR");
    let root = Path::new(&manifest).join("clearsign");
    let mut files = Vec::new();
    collect(&root, &root, &mut files);
    files.sort();
    assert!(
        files.len() > 300,
        "clearsign/ holds only {} descriptor files; the vendored registry is missing",
        files.len()
    );
    let mut generated = String::from(
        "/// Every vendored clear-signing file: (path relative to clearsign/, contents).\n\
         pub static CLEARSIGN_FILES: &[(&str, &str)] = &[\n",
    );
    for relative in &files {
        let _ = writeln!(
            generated,
            "    ({relative:?}, include_str!(concat!(env!(\"CARGO_MANIFEST_DIR\"), \"/clearsign/{relative}\"))),"
        );
    }
    generated.push_str("];\n");
    let out =
        Path::new(&env::var("OUT_DIR").expect("cargo sets OUT_DIR")).join("clearsign_embedded.rs");
    fs::write(out, generated).expect("write generated clearsign table");
}

fn collect(root: &Path, directory: &Path, files: &mut Vec<String>) {
    for entry in fs::read_dir(directory).expect("read clearsign directory") {
        let entry = entry.expect("directory entry");
        let path = entry.path();
        // `file_type` describes the entry itself rather than whatever it points
        // at, so a link is refused here instead of being followed. `is_dir` and
        // `include_str!` both resolve links, and between them a single symlink
        // would put bytes from outside this tree into the artifact under a path
        // that still looks vendored.
        let file_type = entry.file_type().expect("directory entry type");
        assert!(
            !file_type.is_symlink(),
            "clearsign/{} is a symlink; the vendored tree holds only regular \
             files and directories so that what ships is what was reviewed",
            path.strip_prefix(root).unwrap_or(&path).display()
        );
        if file_type.is_dir() {
            collect(root, &path, files);
        } else if path
            .extension()
            .is_some_and(|extension| extension == "json")
        {
            let relative = path.strip_prefix(root).expect("path under clearsign root");
            // A name that is not UTF-8 cannot be written into the generated
            // `include_str!` path, so the build would fail either way. Failing
            // here says which file and why; the `to_str().expect(...)` it
            // replaces said "descriptor paths are UTF-8" and left whoever hit
            // it to work out that the message was about a filename.
            let Some(relative) = relative.to_str() else {
                panic!(
                    "clearsign/{} is not valid UTF-8; every vendored descriptor \
                     path is embedded as a string, so it has to be nameable as one",
                    relative.display()
                );
            };
            files.push(relative.replace('\\', "/"));
        }
    }
}
