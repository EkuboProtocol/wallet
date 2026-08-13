use super::*;

#[cfg(target_os = "macos")]
#[test]
fn macos_launch_agent_escapes_xml_metacharacters() {
    assert_eq!(
        xml_escape(r#"/Applications/A&B<"wallet">'s"#),
        "/Applications/A&amp;B&lt;&quot;wallet&quot;&gt;&apos;s"
    );
}

#[test]
fn linux_desktop_exec_escapes_command_metacharacters() {
    assert_eq!(
        desktop_exec_escape(r#"/opt/$wallet/`bin`/a\"b"#),
        r#"/opt/\$wallet/\`bin\`/a\\\"b"#
    );
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
#[test]
fn disabling_is_idempotent_and_removes_only_the_exact_file() {
    let directory = tempfile::tempdir().unwrap();
    let target = directory.path().join("org.ekubo.wallet.test");
    let unrelated = directory.path().join("keep");
    std::fs::write(&target, "wallet").unwrap();
    std::fs::write(&unrelated, "other").unwrap();

    remove_exact_file(&target).unwrap();
    remove_exact_file(&target).unwrap();

    assert!(!target.exists());
    assert_eq!(std::fs::read_to_string(unrelated).unwrap(), "other");
}
