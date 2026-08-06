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
        let path = entry.expect("directory entry").path();
        if path.is_dir() {
            collect(root, &path, files);
        } else if path
            .extension()
            .is_some_and(|extension| extension == "json")
        {
            let relative = path
                .strip_prefix(root)
                .expect("path under clearsign root")
                .to_str()
                .expect("descriptor paths are UTF-8")
                .replace('\\', "/");
            files.push(relative);
        }
    }
}
