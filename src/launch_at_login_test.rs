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
        // The input's backslash becomes two and its quote gains another, so
        // all three must remain in the quoted Desktop Entry Exec argument.
        r#"/opt/\$wallet/\`bin\`/a\\\"b"#
    );
}
