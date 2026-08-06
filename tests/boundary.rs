//! Tripwires on the audit boundary.
//!
//! The security kernel lives in `crates/ekubo-wallet-core`; the binary crate
//! supplies presentation. These tests fail the build when a change crosses
//! the lines an auditor relies on, so the boundary cannot erode silently.

use std::{fs, path::PathBuf};

fn repository_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// The MCP server must never gain an approval capability: no reference to
/// the terminal presenter, the TUI, or the interactive-proof constructor.
#[test]
fn mcp_server_cannot_reach_an_approval_surface() {
    let mcp = fs::read_to_string(repository_root().join("src/mcp.rs")).unwrap();
    for forbidden in [
        "TerminalApprovalUi",
        "approve_tui",
        "crate::tui",
        "from_terminal",
        "InteractiveProof",
        "ReviewPresenter",
    ] {
        assert!(
            !mcp.contains(forbidden),
            "src/mcp.rs references {forbidden}; the MCP server must never reach an approval \
             surface"
        );
    }
}

/// Exactly one production call site can mint an interactive-terminal proof —
/// the CLI review command. Every human override in the process descends from
/// it, so an auditor enumerates override origins by reading one line.
#[test]
fn interactive_proof_has_exactly_one_production_origin() {
    let mut call_sites = Vec::new();
    let mut directories = vec![
        repository_root().join("src"),
        repository_root().join("crates/ekubo-wallet-core/src"),
    ];
    while let Some(directory) = directories.pop() {
        for entry in fs::read_dir(&directory).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                directories.push(path);
                continue;
            }
            if path.extension().is_none_or(|extension| extension != "rs") {
                continue;
            }
            let source = fs::read_to_string(&path).unwrap();
            for (number, line) in source.lines().enumerate() {
                if line.contains("from_terminal()")
                    && !line.trim_start().starts_with("//")
                    && !line.contains("pub fn from_terminal")
                {
                    call_sites.push(format!("{}:{}", path.display(), number + 1));
                }
            }
        }
    }
    assert_eq!(
        call_sites.len(),
        1,
        "expected exactly one InteractiveProof::from_terminal call site, found: {call_sites:?}"
    );
    assert!(
        call_sites[0].contains("src/cli.rs"),
        "the one proof origin must be the CLI review command: {call_sites:?}"
    );
}

/// The security kernel carries no presentation or MCP dependencies: nothing
/// in the audited crate can draw a terminal or serve a tool.
#[test]
fn core_crate_has_no_presentation_dependencies() {
    let manifest =
        fs::read_to_string(repository_root().join("crates/ekubo-wallet-core/Cargo.toml")).unwrap();
    for forbidden in ["ratatui", "inquire", "crossterm", "rmcp", "clap"] {
        assert!(
            !manifest.contains(forbidden),
            "ekubo-wallet-core depends on {forbidden}; presentation stays outside the audit \
             boundary"
        );
    }
}
