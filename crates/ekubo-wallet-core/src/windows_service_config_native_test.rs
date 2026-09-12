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

#[test]
fn native_creator_owner_placeholder_does_not_grant_registry_write_access() {
    use windows::Win32::{
        Foundation::{CloseHandle, HANDLE},
        Security::{
            AccessCheck, DuplicateToken, GENERIC_MAPPING, PRIVILEGE_SET, SecurityIdentification,
            TOKEN_DUPLICATE, TOKEN_QUERY,
        },
        System::Threading::{GetCurrentProcess, OpenProcessToken},
    };
    struct Token(HANDLE);
    impl Drop for Token {
        fn drop(&mut self) {
            let _ = unsafe { CloseHandle(self.0) };
        }
    }
    let mut primary = HANDLE::default();
    unsafe {
        OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_QUERY | TOKEN_DUPLICATE,
            &raw mut primary,
        )
    }
    .unwrap();
    let primary = Token(primary);
    let mut token = HANDLE::default();
    unsafe { DuplicateToken(primary.0, SecurityIdentification, &raw mut token) }.unwrap();
    let token = Token(token);
    let user = current_process_identity().unwrap().user_sid().to_owned();
    for (trustee, expected) in [("CO", false), (user.as_str(), true)] {
        // The real token can write only when a concrete SID is granted access.
        // Use KEY_SET_VALUE: this does not exercise implicit owner WRITE_DAC.
        let sddl = wide(&format!("O:SYG:SYD:(A;CI;KA;;;{trustee})"));
        let mut descriptor = PSECURITY_DESCRIPTOR::default();
        unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                PCWSTR(sddl.as_ptr()),
                SDDL_REVISION_1,
                &raw mut descriptor,
                None,
            )
        }
        .unwrap();
        let descriptor = Descriptor(descriptor);
        let mapping = GENERIC_MAPPING {
            GenericRead: 0x0002_0019,
            GenericWrite: 0x0002_0006,
            GenericExecute: 0x0002_0019,
            GenericAll: 0x000f_003f,
        };
        let mut privileges = PRIVILEGE_SET::default();
        let mut length = u32::try_from(size_of::<PRIVILEGE_SET>()).unwrap();
        let mut granted = 0;
        let mut allowed = windows::core::BOOL::default();
        unsafe {
            AccessCheck(
                descriptor.0,
                token.0,
                2,
                &raw const mapping,
                Some(&raw mut privileges),
                &raw mut length,
                &raw mut granted,
                &raw mut allowed,
            )
        }
        .unwrap();
        assert_eq!(allowed.as_bool(), expected);
        assert_eq!(granted & 2 != 0, expected);
    }
}

use windows::Win32::System::Registry::{
    HKEY_CURRENT_USER, KEY_ALL_ACCESS, REG_OPTION_NON_VOLATILE, REG_SZ, RegCreateKeyExW,
    RegDeleteTreeW, RegSetValueExW,
};

pub(super) struct RegistryFixture {
    name: Vec<u16>,
    pub(super) root: Key,
    pub(super) trusted: Vec<String>,
}

impl RegistryFixture {
    pub(super) fn new() -> Self {
        let name = wide(&format!(
            r"Software\EkuboWallet.NativeConfigTest-{}",
            uuid::Uuid::new_v4()
        ));
        let root = create_key(HKEY_CURRENT_USER, &name);
        let sid = current_process_identity().unwrap().user_sid().to_owned();
        Self {
            name,
            root,
            trusted: vec![sid, "S-1-5-18".into(), "S-1-5-32-544".into()],
        }
    }

    pub(super) fn create(&self, name: &str) -> Key {
        create_key(self.root.0, &wide(name))
    }

    fn read(&self) -> Result<Option<InstalledServiceIdentity>> {
        read_configuration_under(self.root.0, "S-1-5-21-1-2-3-1001", &self.trusted)
    }
}

impl Drop for RegistryFixture {
    fn drop(&mut self) {
        // Only this test's random HKCU tree is removed; no machine service or
        // real wallet registry entry is created, read, modified, or deleted.
        let _ = unsafe { RegDeleteTreeW(HKEY_CURRENT_USER, PCWSTR(self.name.as_ptr())) };
    }
}

fn create_key(parent: HKEY, name: &[u16]) -> Key {
    let mut key = HKEY::default();
    unsafe {
        RegCreateKeyExW(
            parent,
            PCWSTR(name.as_ptr()),
            None,
            None,
            REG_OPTION_NON_VOLATILE,
            KEY_ALL_ACCESS | KEY_WOW64_64KEY,
            None,
            &raw mut key,
            None,
        )
    }
    .ok()
    .unwrap();
    Key(key)
}

#[test]
fn native_absence_is_distinct_from_an_incomplete_owner_profile() {
    let registry = RegistryFixture::new();
    assert!(
        registry.read().is_err(),
        "a missing machine root is not an absent installation"
    );
    drop(registry.create("SOFTWARE"));
    assert!(registry.read().unwrap().is_none());
    drop(registry.create(r"SOFTWARE\EkuboWallet\Owners"));
    assert!(registry.read().unwrap().is_none());
    drop(registry.create(r"SOFTWARE\EkuboWallet\Owners\S-1-5-21-1-2-3-1001"));
    assert!(
        registry.read().is_err(),
        "a present owner key without Profile must not permit fallback"
    );
}

#[test]
fn native_invalid_profile_values_never_become_absent_installations() {
    let registry = RegistryFixture::new();
    let profile = registry.create(r"SOFTWARE\EkuboWallet\Owners\S-1-5-21-1-2-3-1001");
    let name = wide("Profile");
    for (kind, bytes) in [
        (REG_BINARY, b"not json".to_vec()),
        (REG_SZ, vec![0; 2]),
        (REG_BINARY, vec![0; MAX_CONFIG_BYTES + 1]),
    ] {
        unsafe { RegSetValueExW(profile.0, PCWSTR(name.as_ptr()), None, kind, Some(&bytes)) }
            .ok()
            .unwrap();
        assert!(
            registry.read().is_err(),
            "malformed metadata must not permit fallback"
        );
    }
}

#[test]
fn native_untrusted_ancestor_is_rejected_before_considering_missing_children() {
    let registry = RegistryFixture::new();
    drop(registry.create("SOFTWARE"));
    assert!(read_configuration_under(registry.root.0, "S-1-5-21-1-2-3-1001", &[]).is_err());
    assert!(registry.read().unwrap().is_none());
}

#[test]
fn native_incomplete_committed_identity_blocks_legacy_fallback() {
    let registry = RegistryFixture::new();
    drop(registry.create("SOFTWARE"));
    assert!(registry.read().unwrap().is_none());
    let key = registry.create(r"SOFTWARE\EkuboWallet\Committed\S-1-5-21-1-2-3-1001");
    assert!(registry.read().is_err());
    let name = wide("Profile");
    unsafe {
        RegSetValueExW(
            key.0,
            PCWSTR(name.as_ptr()),
            None,
            REG_BINARY,
            Some(b"invalid"),
        )
    }
    .ok()
    .unwrap();
    assert!(registry.read().is_err());
}

#[test]
fn native_pending_metadata_is_separate_from_active_discovery() {
    let registry = RegistryFixture::new();
    let owner = "S-1-5-21-1-2-3-1001";
    let profile = registry.create(r"SOFTWARE\EkuboWallet\Pending\S-1-5-21-1-2-3-1001");
    assert!(registry.read().unwrap().is_none());
    // An incomplete pending profile must not be usable even though the desktop
    // correctly remains in its pre-installation state.
    assert!(pending_configuration_under(registry.root.0, owner, &registry.trusted).is_err());
    let name = wide("Profile");
    unsafe {
        RegSetValueExW(
            profile.0,
            PCWSTR(name.as_ptr()),
            None,
            REG_BINARY,
            Some(b"invalid"),
        )
    }
    .ok()
    .unwrap();
    assert!(pending_configuration_under(registry.root.0, owner, &registry.trusted).is_err());
    assert!(registry.read().unwrap().is_none());
    drop(registry.create(r"SOFTWARE\EkuboWallet\Owners\S-1-5-21-1-2-3-1001"));
    assert!(registry.read().is_err());
    assert!(pending_configuration_under(registry.root.0, owner, &registry.trusted).is_err());
}
