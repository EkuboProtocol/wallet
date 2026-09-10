use super::*;
use windows::Win32::{
    Foundation::{HLOCAL, LocalFree},
    Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
    },
};

struct Descriptor(PSECURITY_DESCRIPTOR);
impl Drop for Descriptor {
    fn drop(&mut self) {
        let _ = unsafe { LocalFree(Some(HLOCAL(self.0.0))) };
    }
}

fn validate_sddl(sddl: &str) -> Result<()> {
    let sddl = wide(sddl);
    let mut descriptor = PSECURITY_DESCRIPTOR::default();
    unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            PCWSTR(sddl.as_ptr()),
            SDDL_REVISION_1,
            &raw mut descriptor,
            None,
        )
    }?;
    let descriptor = Descriptor(descriptor);
    unsafe { validate_descriptor(descriptor.0, &["S-1-5-18".into(), "S-1-5-32-544".into()]) }
}

#[test]
fn native_descriptor_checks_readers_writers_and_inheritance() {
    assert!(validate_sddl("O:SYD:(A;;KA;;;SY)(A;;KR;;;BU)").is_ok());
    assert!(validate_sddl("O:BAD:(A;;KA;;;BA)(A;CIIO;KA;;;CO)(A;;KR;;;BU)").is_ok());
    assert!(validate_sddl("O:SYD:(A;;KW;;;BU)").is_err());
    assert!(validate_sddl("O:SYD:(D;;KW;;;BU)(A;;KA;;;BU)").is_err());
    assert!(validate_sddl("O:BUD:(A;;KR;;;BU)").is_err());
    assert!(validate_sddl("O:SYD:NO_ACCESS_CONTROL").is_err());
    assert!(validate_sddl("O:SYD:").is_ok());
}
