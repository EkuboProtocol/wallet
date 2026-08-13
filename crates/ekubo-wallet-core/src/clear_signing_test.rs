//! Tests for [`super`].
//!
//! Out of line so the audit corpus is production code: V12 bills measured
//! bytes and excludes `*_test.rs` by default. A `#[path]` child module has
//! exactly the privacy access an inline one does, so nothing these can reach
//! changes, and the test paths are the ones they always were.

use super::*;

#[test]
fn every_vendored_descriptor_resolves_and_parses() {
    let registry = registry();
    // The one known upstream defect: swell's burn format carries no
    // intent, which the engine requires. Anything beyond that fails.
    let unexpected: Vec<_> = registry
        .failures
        .iter()
        .filter(|(path, _)| *path != "registry/swell/calldata-swell.json")
        .collect();
    assert!(
        unexpected.is_empty(),
        "vendored descriptors failed to parse: {unexpected:?}"
    );
    assert!(
        registry.calldata.len() > 50,
        "only {} calldata descriptors loaded",
        registry.calldata.len()
    );
    assert!(
        registry.eip712.len() > 100,
        "only {} eip712 descriptors loaded",
        registry.eip712.len()
    );
}

#[tokio::test]
async fn the_vendored_vetoken_descriptor_interprets_a_stake() {
    let (chain, address, calldata) = stake_fixture();
    let reading = interpret(
        chain,
        CallEnvelope {
            from: Address::repeat_byte(0x11),
            to: address,
        },
        &Bytes::from(calldata),
        U256::ZERO,
        &TokenMetadataMap::new(),
    )
    .await
    .expect("descriptor matches");
    assert!(!reading.intent.is_empty());
    assert!(!reading.fields.is_empty());
}

#[tokio::test]
async fn a_forged_symbol_cannot_stand_in_for_a_token_address() {
    // Run 6251, finding 186992. A stored symbol is text the wallet did not
    // author: it arrives from a token list, and a fresh database seeds
    // thousands of rows from an aggregated upstream feed without asking the
    // owner about each one. `approval_summary::token_label` answers that by
    // keeping only the characters real symbols use, refusing anything still
    // containing `0x`, and printing the resolved address beside the symbol.
    // This bridge answered with the raw string, so a descriptor could render
    // an attacker's token under a label naming the genuine one's address.
    let attacker = Address::repeat_byte(0x11);
    let genuine = Address::repeat_byte(0x22);
    let map = TokenMetadataMap::from([(
        attacker,
        crate::approval_summary::TokenMetadata {
            symbol: Some(format!("USDC ({genuine:#x})")),
            decimals: Some(6),
        },
    )]);
    let provider = MapProvider(&map);
    let forged = provider.resolve_token(1, &format!("{attacker:#x}")).await;
    assert!(
        forged.is_none(),
        "a symbol that can be read as an address must not name a token: {forged:?}"
    );

    // An ordinary symbol still resolves, and carries the address it belongs to
    // rather than leaving it in the calldata the descriptor exists to replace.
    let honest = TokenMetadataMap::from([(
        attacker,
        crate::approval_summary::TokenMetadata {
            symbol: Some("USDC".into()),
            decimals: Some(6),
        },
    )]);
    let resolved = MapProvider(&honest)
        .resolve_token(1, &format!("{attacker:#x}"))
        .await
        .expect("a real symbol resolves");
    assert_eq!(resolved.decimals, 6);
    assert!(resolved.symbol.starts_with("USDC ("), "{resolved:?}");
    assert!(
        resolved.symbol.contains(&format!("{attacker:#x}")),
        "{resolved:?}"
    );
}

mod vendored_embedding_tests {
    //! What ships as a vendored descriptor is what was reviewed as one.

    use super::super::CLEARSIGN_FILES;
    use std::{collections::BTreeMap, fs, path::PathBuf};

    fn vendored_root() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("clearsign")
    }

    fn walk(
        root: &std::path::Path,
        directory: &std::path::Path,
        found: &mut BTreeMap<String, String>,
    ) {
        for entry in fs::read_dir(directory).expect("the vendored tree is readable") {
            let path = entry.expect("directory entry").path();
            if path.is_dir() {
                walk(root, &path, found);
            } else if path
                .extension()
                .is_some_and(|extension| extension == "json")
            {
                let relative = path
                    .strip_prefix(root)
                    .expect("under the vendored root")
                    .to_str()
                    .expect("a UTF-8 name")
                    .replace('\\', "/");
                found.insert(relative, fs::read_to_string(&path).expect("readable"));
            }
        }
    }

    /// The build now copies each file into `OUT_DIR` and embeds the copy, so
    /// the copy is a thing that can be wrong. This is what says it is not:
    /// every vendored path is embedded, nothing else is, and each one carries
    /// the bytes on disk.
    #[test]
    fn the_embedded_table_is_exactly_the_vendored_tree() {
        let root = vendored_root();
        let mut on_disk = BTreeMap::new();
        walk(&root, &root, &mut on_disk);
        let embedded: BTreeMap<String, String> = CLEARSIGN_FILES
            .iter()
            .map(|(path, contents)| ((*path).to_string(), (*contents).to_string()))
            .collect();
        assert!(on_disk.len() > 300, "the vendored registry is missing");
        assert_eq!(
            on_disk.keys().collect::<Vec<_>>(),
            embedded.keys().collect::<Vec<_>>(),
            "the embedded table and the vendored tree name different files"
        );
        for (path, contents) in &on_disk {
            assert_eq!(
                embedded.get(path),
                Some(contents),
                "clearsign/{path} was embedded with different bytes than it holds"
            );
        }
    }

    /// The defect this replaced: the build checked a pathname and then handed
    /// the same pathname to rustc, which checked nothing and decided what
    /// shipped. Anything able to write to the checkout in between could swap
    /// the file, or a directory above it, for a symlink and put unreviewed
    /// bytes on the approval screen.
    ///
    /// Pinned in the source because a race is not a thing a fixture can hold
    /// still: what is checkable is that no path in the mutable checkout is
    /// ever resolved a second time, by anyone.
    #[test]
    fn no_vendored_path_is_resolved_by_a_second_reader() {
        let build = fs::read_to_string(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("build.rs"))
            .expect("build.rs is readable");
        let generated: Vec<&str> = build
            .lines()
            .filter(|line| line.contains("include_str!(concat!"))
            .collect();
        assert!(!generated.is_empty(), "the build must still embed the tree");
        for line in generated {
            assert!(
                line.contains("env!(\\\"OUT_DIR\\\")"),
                "an embedded file must come from the staged copy this build wrote: {line}"
            );
            assert!(
                !line.contains("CARGO_MANIFEST_DIR"),
                "embedding a path in the mutable checkout hands rustc a lookup nothing checked: \
                 {line}"
            );
        }
    }

    /// A filename reaches the generated source twice — as the table's key and
    /// as the staged path the `include_str!` names — and only the key was ever
    /// written as a Rust string literal. The other was pasted into the middle
    /// of one, so `weird".json` closed the literal and everything after it
    /// became source the build script did not intend and nobody reviewed. Unix
    /// permits the quote, and a committed tree entry is the threat this file
    /// already defends against everywhere else.
    ///
    /// Pinned in the source because the checkout holds no such file and adding
    /// one to exercise it would commit the attack. What is checkable is that
    /// every value interpolated into the generated line is formatted with
    /// `{:?}`, which escapes quotes, backslashes, and control characters.
    #[test]
    fn every_filename_in_the_generated_source_is_written_as_a_literal() {
        let build = fs::read_to_string(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("build.rs"))
            .expect("build.rs is readable");
        let generated: Vec<&str> = build
            .lines()
            .filter(|line| line.contains("include_str!(concat!"))
            .collect();
        assert!(!generated.is_empty(), "the build must still embed the tree");
        for line in generated {
            for placeholder in interpolations(line) {
                assert!(
                    placeholder.ends_with(":?"),
                    "`{{{placeholder}}}` is pasted into the generated source unescaped; a \
                     filename holding a quote would stop being a filename there: {line}"
                );
            }
        }
    }

    /// The `{…}` placeholders of one format string, without their braces.
    /// `{{` and `}}` are escaped braces rather than a placeholder.
    fn interpolations(line: &str) -> Vec<String> {
        let mut found = Vec::new();
        let mut rest = line;
        while let Some(open) = rest.find('{') {
            rest = &rest[open + 1..];
            if let Some(stripped) = rest.strip_prefix('{') {
                rest = stripped;
                continue;
            }
            let Some(close) = rest.find('}') else { break };
            found.push(rest[..close].to_owned());
            rest = &rest[close + 1..];
        }
        found
    }
}

mod token_reference_recording_tests {
    use super::*;

    /// Repeated callbacks do not become repeated metadata reads.
    #[tokio::test]
    async fn recording_deduplicates_repeated_addresses() {
        let recorder = RecordingProvider::default();

        let repeated = format!("{:#x}", Address::repeat_byte(0x11));
        for _ in 0..1_000 {
            let _ = recorder.resolve_token(1, &repeated).await;
        }
        assert_eq!(
            recorder.0.lock().unwrap().len(),
            1,
            "a set records one address once"
        );
    }

    /// Unparseable addresses are ignored rather than recorded, which is the
    /// behaviour that was already there and must survive the change to a set.
    #[tokio::test]
    async fn an_unparseable_address_records_nothing() {
        let recorder = RecordingProvider::default();
        let _ = recorder.resolve_token(1, "not-an-address").await;
        assert!(recorder.0.lock().unwrap().is_empty());
    }
}
