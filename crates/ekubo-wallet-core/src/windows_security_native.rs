//! Decode OS-provided security descriptors for registry and file validation.
// Win32 descriptor APIs require pointer-backed structures; callers keep the
// complete descriptor buffer alive for the duration of this read.
#![allow(unsafe_code)]

use super::AccessEntry;
use crate::windows_service_identity::sid_string;
use anyhow::{Result, ensure};
use std::{ffi::c_void, mem::size_of};
use windows::{
    Win32::Security::{
        ACL_SIZE_INFORMATION, AclSizeInformation, GetAce, GetAclInformation,
        GetSecurityDescriptorDacl, GetSecurityDescriptorOwner, IsValidAcl,
        IsValidSecurityDescriptor, PSECURITY_DESCRIPTOR, PSID,
    },
    core::BOOL,
};

/// # Safety
/// The descriptor must be a complete OS-provided buffer and remain live.
pub(crate) unsafe fn read_descriptor(
    descriptor: PSECURITY_DESCRIPTOR,
) -> Result<(String, Vec<AccessEntry>)> {
    ensure!(
        unsafe { IsValidSecurityDescriptor(descriptor) }.as_bool(),
        "invalid security descriptor"
    );
    let mut owner = PSID::default();
    let mut defaulted = BOOL::default();
    unsafe { GetSecurityDescriptorOwner(descriptor, &raw mut owner, &raw mut defaulted) }?;
    ensure!(!owner.0.is_null(), "security descriptor has no owner");
    let owner = unsafe { sid_string(owner) }?;
    let mut present = BOOL::default();
    let mut acl = std::ptr::null_mut();
    unsafe {
        GetSecurityDescriptorDacl(
            descriptor,
            &raw mut present,
            &raw mut acl,
            &raw mut defaulted,
        )
    }?;
    ensure!(
        present.as_bool() && !acl.is_null(),
        "object has an unrestricted DACL"
    );
    ensure!(unsafe { IsValidAcl(acl) }.as_bool(), "invalid ACL");
    let mut information = ACL_SIZE_INFORMATION::default();
    unsafe {
        GetAclInformation(
            acl,
            (&raw mut information).cast(),
            u32::try_from(size_of::<ACL_SIZE_INFORMATION>())?,
            AclSizeInformation,
        )
    }?;
    ensure!(information.AceCount <= 4096, "ACL has too many entries");
    let mut entries = Vec::new();
    for index in 0..information.AceCount {
        let mut ace: *mut c_void = std::ptr::null_mut();
        unsafe { GetAce(acl, index, &raw mut ace) }?;
        entries.push(unsafe { read_ace(ace.cast()) }?);
    }
    Ok((owner, entries))
}

unsafe fn read_ace(ace: *const u8) -> Result<AccessEntry> {
    // GetAce and IsValidAcl establish a complete ACE header in an OS buffer.
    let header = unsafe { std::slice::from_raw_parts(ace, 4) };
    let length = usize::from(u16::from_le_bytes([header[2], header[3]]));
    ensure!(length >= 4, "invalid ACE length");
    if header[0] == 1 {
        return Ok(AccessEntry::Deny);
    }
    if header[0] != 0 || header[1] & !0x1f != 0 {
        return Ok(AccessEntry::Unsupported);
    }
    ensure!(length >= 16, "invalid allow ACE length");
    let bytes = unsafe { std::slice::from_raw_parts(ace, length) };
    ensure!(
        bytes[8] == 1 && bytes[9] <= 15 && 16 + usize::from(bytes[9]) * 4 == length,
        "invalid allow ACE SID"
    );
    let mask = u32::from_le_bytes(bytes[4..8].try_into()?);
    let sid = unsafe { sid_string(PSID(ace.add(8).cast_mut().cast())) }?;
    Ok(AccessEntry::Allow {
        sid,
        mask,
        inherit_only: header[1] & 8 != 0,
    })
}
