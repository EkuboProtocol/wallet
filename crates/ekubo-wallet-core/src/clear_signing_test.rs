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
        &crate::approval_summary::OwnAccounts::new(),
    )
    .await
    .expect("descriptor matches");
    assert!(!reading.intent.is_empty());
    assert!(!reading.fields.is_empty());
}

#[tokio::test]
async fn descriptor_interpretation_requires_exact_canonical_calldata() {
    let (chain, address, mut calldata) = stake_fixture();
    calldata.push(0);
    let reading = interpret(
        chain,
        CallEnvelope {
            from: Address::repeat_byte(0x11),
            to: address,
        },
        &Bytes::from(calldata),
        U256::ZERO,
        &TokenMetadataMap::new(),
        &crate::approval_summary::OwnAccounts::new(),
    )
    .await;
    assert!(
        reading.is_none(),
        "trailing bytes must disable the descriptor"
    );
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
    let own = crate::approval_summary::OwnAccounts::new();
    let provider = MapProvider {
        metadata: &map,
        own: &own,
    };
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
    let resolved = MapProvider {
        metadata: &honest,
        own: &own,
    }
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

/// The engine asks for a token by its lowercase address, and the label it
/// gets back carries that address in EIP-55 case. The repeated-digit fixtures
/// above cannot tell the two apart; the EIP's reference vector can.
#[tokio::test]
async fn a_resolved_token_label_carries_the_checksummed_address() {
    let checksummed = "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed";
    let token: Address = checksummed.parse().unwrap();
    let map = TokenMetadataMap::from([(
        token,
        crate::approval_summary::TokenMetadata {
            symbol: Some("USDC".into()),
            decimals: Some(6),
        },
    )]);
    let own = crate::approval_summary::OwnAccounts::new();
    let resolved = MapProvider {
        metadata: &map,
        own: &own,
    }
    .resolve_token(1, &format!("{token:#x}"))
    .await
    .expect("a real symbol resolves");
    assert_eq!(resolved.symbol, format!("USDC ({checksummed})"));
    assert_eq!(resolved.name, resolved.symbol);
}

#[tokio::test]
async fn a_negative_tick_reads_as_a_negative_number() {
    // The engine's `raw` formatter prints a signed word through
    // `BigUint::from_bytes_be`, so a tick of -140 rendered as
    // 2^256 - 140 — a number no reviewer can read as a position bound.
    let (chain, address, calldata) = negative_tick_fixture();
    let reading = interpret(
        chain,
        CallEnvelope {
            from: Address::repeat_byte(0x11),
            to: address,
        },
        &Bytes::from(calldata),
        U256::ZERO,
        &TokenMetadataMap::new(),
        &crate::approval_summary::OwnAccounts::new(),
    )
    .await
    .expect("descriptor matches");
    assert!(
        reading
            .fields
            .iter()
            .any(|field| field == "Lower tick: -140"),
        "the negative tick is not rendered as a negative number: {:?}",
        reading.fields
    );
    let unsigned = I256::unchecked_from(-140).into_raw().to_string();
    assert!(
        !reading.fields.iter().any(|field| field.contains(&unsigned)),
        "a field still carries the unsigned reading of -140: {:?}",
        reading.fields
    );
}

/// The one formatter that renders a two's-complement word with its sign.
/// Every other numeric format in the pinned engine — `raw`, `amount`,
/// `tokenAmount`, and an absent format, which falls back to `raw` — prints
/// the unsigned word, so `-140` becomes 2^256 - 140.
const SIGNED_SAFE_FORMAT: &str = "number";

/// Upstream descriptors ship verbatim, defects included, so that what was
/// reviewed is what runs. These fields display a signed staking reward
/// through an unsigned formatter; the list exists so the next one cannot
/// arrive unnoticed, and each entry must still be reachable.
const UPSTREAM_UNSIGNED_SIGNED_FIELDS: &[(&str, &str)] = &[
    (
        "registry/p2p/calldata-NativeTokenVault.json",
        "#.harvestParams.reward",
    ),
    (
        "registry/serenita/calldata-EthVault.json",
        "#.harvestParams.reward",
    ),
];

#[test]
fn every_signed_parameter_is_displayed_by_a_signed_formatter() {
    let by_path: BTreeMap<&str, &str> = CLEARSIGN_FILES.iter().copied().collect();
    let mut offenders = Vec::new();
    let mut excused = BTreeSet::new();
    for (path, contents) in CLEARSIGN_FILES {
        let standalone = path.starts_with("registry/")
            && path
                .rsplit('/')
                .next()
                .is_some_and(|name| name.starts_with("calldata-"));
        if !standalone {
            continue;
        }
        // A file that does not resolve is already covered by
        // `every_vendored_descriptor_resolves_and_parses`.
        let Ok((_, resolved)) = resolve_vendored(path, contents, &by_path) else {
            continue;
        };
        let document: serde_json::Value =
            serde_json::from_str(&resolved).expect("a resolved descriptor is JSON");
        let Some(formats) = document
            .pointer("/display/formats")
            .and_then(serde_json::Value::as_object)
        else {
            continue;
        };
        for (signature, format) in formats {
            let signed = signed_parameter_names(signature);
            if signed.is_empty() {
                continue;
            }
            let mut fields = Vec::new();
            collect_fields(format.get("fields"), &document, &mut fields);
            for (field_path, field_format) in fields {
                let leaf = field_path.rsplit('.').next().unwrap_or(field_path);
                if !signed.contains(leaf) || field_format == Some(SIGNED_SAFE_FORMAT) {
                    continue;
                }
                if let Some(known) = UPSTREAM_UNSIGNED_SIGNED_FIELDS
                    .iter()
                    .find(|(file, field)| file == path && *field == field_path)
                {
                    excused.insert(*known);
                    continue;
                }
                offenders.push(format!(
                    "{path}: {signature} renders signed field {field_path} \
                     as {field_format:?}"
                ));
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "signed parameters displayed by an unsigned formatter, which prints \
         -140 as 2^256 - 140; use {SIGNED_SAFE_FORMAT:?}: {offenders:#?}"
    );
    let listed: BTreeSet<_> = UPSTREAM_UNSIGNED_SIGNED_FIELDS.iter().copied().collect();
    assert_eq!(
        excused, listed,
        "the upstream exception list no longer matches the corpus"
    );
}

/// Parameter names the ERC-7730 signature spelling declares as signed
/// integers. The registry spells formats with names — including inside
/// tuples — so a field path's last segment names its parameter.
fn signed_parameter_names(signature: &str) -> BTreeSet<&str> {
    let bytes = signature.as_bytes();
    let mut names = BTreeSet::new();
    for start in 0..bytes.len() {
        if !signature[start..].starts_with("int") {
            continue;
        }
        // `uint256` ends in `int256`: an identifier character before `int`
        // means this is the tail of a longer word, signed or not.
        if start > 0 && (bytes[start - 1].is_ascii_alphanumeric() || bytes[start - 1] == b'_') {
            continue;
        }
        let mut cursor = start + "int".len();
        // Width digits and any array suffix sit between the type and the name.
        while cursor < bytes.len()
            && (bytes[cursor].is_ascii_digit() || bytes[cursor] == b'[' || bytes[cursor] == b']')
        {
            cursor += 1;
        }
        if cursor >= bytes.len() || bytes[cursor] != b' ' {
            continue;
        }
        cursor += 1;
        let name = cursor;
        while cursor < bytes.len()
            && (bytes[cursor].is_ascii_alphanumeric() || bytes[cursor] == b'_')
        {
            cursor += 1;
        }
        if cursor > name {
            names.insert(&signature[name..cursor]);
        }
    }
    names
}

/// Every displayed field of one format, as (path, format), following the
/// nesting the engine follows: sub-field lists, and `$ref` definitions that
/// carry the format the field itself omits.
fn collect_fields<'a>(
    fields: Option<&'a serde_json::Value>,
    document: &'a serde_json::Value,
    out: &mut Vec<(&'a str, Option<&'a str>)>,
) {
    let Some(items) = fields.and_then(serde_json::Value::as_array) else {
        return;
    };
    for item in items {
        collect_fields(item.get("fields"), document, out);
        let Some(path) = item.get("path").and_then(serde_json::Value::as_str) else {
            continue;
        };
        let format = item
            .get("format")
            .and_then(serde_json::Value::as_str)
            .or_else(|| defined_format(item, document));
        out.push((path, format));
    }
}

fn defined_format<'a>(
    field: &serde_json::Value,
    document: &'a serde_json::Value,
) -> Option<&'a str> {
    let name = field
        .get("$ref")?
        .as_str()?
        .strip_prefix("$.display.definitions.")?;
    document
        .pointer(&format!("/display/definitions/{name}"))?
        .get("format")?
        .as_str()
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
