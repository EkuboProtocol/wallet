//! Embeds every vendored clear-signing file into the binary.
//!
//! The generated `CLEARSIGN_FILES` table carries the complete `clearsign/`
//! tree — the upstream ERC-7730 registry snapshot plus the Ekubo descriptors
//! — so descriptor interpretation never touches the filesystem or network at
//! runtime, and a release artifact carries exactly what was reviewed at
//! vendoring time.
//!
//! Files are read once and staged under `OUT_DIR`, so rustc embeds the bytes
//! this script collected rather than resolving the vendored paths again.

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

    let out_dir = env::var("OUT_DIR").expect("cargo sets OUT_DIR");
    let staged_root = Path::new(&out_dir).join("clearsign");
    // A stale staging tree would keep shipping a descriptor deleted upstream,
    // so it is rebuilt rather than merged into.
    if staged_root.exists() {
        fs::remove_dir_all(&staged_root).expect("clear the staged clearsign tree");
    }

    let mut generated = String::from(
        "/// Every vendored clear-signing file: (path relative to clearsign/, contents).\n\
         pub static CLEARSIGN_FILES: &[(&str, &str)] = &[\n",
    );
    for relative in &files {
        let contents = fs::read_to_string(root.join(relative))
            .unwrap_or_else(|error| panic!("clearsign/{relative} could not be read: {error}"));
        let staged = staged_root.join(relative);
        fs::create_dir_all(staged.parent().expect("a staged file has a parent"))
            .expect("create the staged clearsign directory");
        fs::write(&staged, &contents).expect("stage a vendored clearsign file");
        // Both halves of this line are the same filename, so both are written
        // as Rust string literals rather than one of them being pasted into
        // the middle of one. A descriptor named `weird".json` — legal on unix,
        // and the only thing standing between a committed tree entry and this
        // build script is review — would otherwise close the `concat!`
        // argument and continue as source. The table key was already escaped;
        // the staged path beside it was not, which is the same value formatted
        // two ways on one line.
        let staged_suffix = format!("/clearsign/{relative}");
        let _ = writeln!(
            generated,
            "    ({relative:?}, include_str!(concat!(env!(\"OUT_DIR\"), {staged_suffix:?}))),"
        );
    }
    generated.push_str("];\n");
    let out = Path::new(&out_dir).join("clearsign_embedded.rs");
    fs::write(out, generated).expect("write generated clearsign table");
}

fn collect(root: &Path, directory: &Path, files: &mut Vec<String>) {
    for entry in fs::read_dir(directory).expect("read clearsign directory") {
        let entry = entry.expect("directory entry");
        let path = entry.path();
        // `file_type` describes the entry itself rather than whatever it points
        // at, so a link is refused here instead of being followed. `is_dir`
        // resolves links, and one symlink here would walk the traversal out of
        // the vendored tree.
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
