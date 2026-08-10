//! Embeds every vendored clear-signing file into the binary.
//!
//! The generated `CLEARSIGN_FILES` table carries the complete `clearsign/`
//! tree — the upstream ERC-7730 registry snapshot plus the Ekubo descriptors
//! — so descriptor interpretation never touches the filesystem or network at
//! runtime, and a release artifact carries exactly what was reviewed at
//! vendoring time.
//!
//! # Why the files are staged instead of included in place
//!
//! This script used to emit `include_str!` expressions naming paths under
//! `CARGO_MANIFEST_DIR`, which meant two readers resolved each path: this
//! script, which checked that the entry was a regular file and not a symlink,
//! and rustc some time later, which checked nothing. Only the second one
//! decided what shipped. Anything able to write to the checkout between the
//! two — a concurrent job on a shared build host, a script racing the build —
//! could replace a checked file, or a directory above it, with a symlink and
//! put bytes from outside the reviewed tree into the artifact under a path
//! that still reads as vendored. A clear-signing descriptor is not inert
//! there: it is what the approval screen shows a person about the call they
//! are agreeing to.
//!
//! So this script now reads the bytes itself and stages them under `OUT_DIR`,
//! and the generated `include_str!` names the staged copy. The path rustc
//! resolves is one this script just wrote, so what is checked and what ships
//! are the same bytes rather than the same pathname. The reads are themselves
//! bracketed by [`read_vendored`], which refuses a symlink anywhere on the way
//! down and refuses a file that changed underneath it.

use std::{
    env,
    fmt::Write as _,
    fs::{self, Metadata},
    path::Path,
};

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
        let contents = read_vendored(&root, relative);
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

/// Read one vendored file, refusing anything that is not a regular file
/// reached through real directories, and refusing a file that moved while it
/// was being read.
///
/// Every component is checked with `symlink_metadata`, which describes the
/// entry rather than what it points at: a symlink for a parent directory is as
/// good as one for the file, since the read resolves the whole path. The
/// before-and-after comparison is what makes the check and the read describe
/// the same file — without it this would be the same two-resolutions problem
/// one lookup further down.
fn read_vendored(root: &Path, relative: &str) -> String {
    let mut walked = root.to_path_buf();
    check_real_directory(&walked, relative);
    let mut components: Vec<&str> = relative.split('/').collect();
    let name = components.pop().expect("a relative path names a file");
    for component in components {
        walked.push(component);
        check_real_directory(&walked, relative);
    }
    walked.push(name);

    let before = fs::symlink_metadata(&walked)
        .unwrap_or_else(|error| panic!("clearsign/{relative} could not be read: {error}"));
    assert!(
        before.file_type().is_file(),
        "clearsign/{relative} is not a regular file; the vendored tree holds only regular files \
         and directories so that what ships is what was reviewed"
    );
    let contents = fs::read_to_string(&walked)
        .unwrap_or_else(|error| panic!("clearsign/{relative} could not be read: {error}"));
    let after = fs::symlink_metadata(&walked)
        .unwrap_or_else(|error| panic!("clearsign/{relative} could not be re-read: {error}"));
    assert!(
        after.file_type().is_file() && same_file(&before, &after),
        "clearsign/{relative} changed while the build was reading it; refusing to embed bytes \
         nobody reviewed"
    );
    contents
}

fn check_real_directory(path: &Path, relative: &str) {
    let metadata = fs::symlink_metadata(path).unwrap_or_else(|error| {
        panic!("the directory holding clearsign/{relative} could not be read: {error}")
    });
    assert!(
        metadata.file_type().is_dir(),
        "{} is not a real directory; a symlink on the way to clearsign/{relative} would embed \
         bytes from outside the reviewed tree",
        path.display()
    );
}

/// Whether two readings of one pathname describe the same file. The inode
/// pair is the answer where it exists; elsewhere, length and modification time
/// are what there is.
fn same_file(before: &Metadata, after: &Metadata) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        if before.dev() != after.dev() || before.ino() != after.ino() {
            return false;
        }
    }
    before.len() == after.len() && before.modified().ok() == after.modified().ok()
}

fn collect(root: &Path, directory: &Path, files: &mut Vec<String>) {
    for entry in fs::read_dir(directory).expect("read clearsign directory") {
        let entry = entry.expect("directory entry");
        let path = entry.path();
        // `file_type` describes the entry itself rather than whatever it points
        // at, so a link is refused here instead of being followed. `is_dir`
        // resolves links, and one symlink here would walk the traversal out of
        // the vendored tree. This is the first of two refusals: `read_vendored`
        // checks again, on the path it is about to read.
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
