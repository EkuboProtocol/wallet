use super::*;

const TOKEN: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

#[test]
fn codex_uses_documented_static_http_headers_and_preserves_unknowns() {
    let output = merge_codex(
        "model = \"gpt\"\n[other]\nvalue = 7\n",
        "http://127.0.0.1:50000/mcp",
        TOKEN,
        true,
    )
    .unwrap();
    let parsed = output.parse::<DocumentMut>().unwrap();
    assert_eq!(parsed["model"].as_str(), Some("gpt"));
    assert_eq!(parsed["other"]["value"].as_integer(), Some(7));
    assert_eq!(
        parsed["mcp_servers"][LOCAL_SERVER_NAME]["url"].as_str(),
        Some("http://127.0.0.1:50000/mcp")
    );
    assert_eq!(
        parsed["mcp_servers"][LOCAL_SERVER_NAME]["http_headers"]["Authorization"].as_str(),
        Some("Bearer AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
    );
}

#[test]
fn every_json_shape_preserves_unrelated_servers() {
    for (root, shape) in [
        ("mcpServers", JsonShape::Url),
        ("mcpServers", JsonShape::HttpUrl),
        ("mcp", JsonShape::Remote),
    ] {
        let before =
            format!(r#"{{"keep":true,"{root}":{{"unrelated":{{"url":"https://example.com"}}}}}}"#);
        let output = merge_json(
            &before,
            root,
            shape,
            "http://127.0.0.1:50000/mcp",
            TOKEN,
            false,
        )
        .unwrap();
        let parsed: Value = serde_json::from_str(&output).unwrap();
        assert_eq!(parsed["keep"], true);
        assert_eq!(parsed[root]["unrelated"]["url"], "https://example.com");
        assert!(
            parsed[root][LOCAL_SERVER_NAME]["headers"]["Authorization"]
                .as_str()
                .unwrap()
                .starts_with("Bearer ")
        );
    }
}

#[test]
fn a_failed_install_restores_the_timestamped_backup() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("mcp.json");
    fs::write(&path, "{\"keep\":true}\n").unwrap();
    let preview = ConfigPreview {
        path: path.clone(),
        before: "{\"keep\":true}\n".into(),
        after: "{".into(),
        diff: "redacted test diff".into(),
    };
    assert!(preview.install().is_err());
    assert_eq!(fs::read_to_string(&path).unwrap(), "{\"keep\":true}\n");
    let backups = fs::read_dir(directory.path())
        .unwrap()
        .filter_map(std::result::Result::ok)
        .filter(|entry| entry.file_name().to_string_lossy().contains(".backup-"))
        .count();
    assert_eq!(backups, 1);
}
