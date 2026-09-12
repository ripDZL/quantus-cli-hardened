//! Windows-specific ACL hardening for Quantus wallet and secret files.
//!
//! Wallet storage uses a protected DACL that grants full control only to the
//! current user and LocalSystem. Secret input files are validated from the
//! already-open file handle to avoid path/handle TOCTOU races.


use crate::error::{QuantusError, Result};
use std::{
    ffi::c_void,
    fs::File,
    io,
    os::windows::{
        ffi::OsStrExt,
        io::AsRawHandle,
    },
    path::Path,
    ptr::{null_mut},
    slice,
};
use windows_sys::Win32::{
    Foundation::{CloseHandle, LocalFree, HANDLE},
    Security::{
        Authorization::{
            ConvertSecurityDescriptorToStringSecurityDescriptorW, ConvertSidToStringSidW,
            ConvertStringSecurityDescriptorToSecurityDescriptorW, GetNamedSecurityInfoW,
            GetSecurityInfo, SDDL_REVISION_1, SE_FILE_OBJECT,
        },
        GetTokenInformation, SetFileSecurityW, DACL_SECURITY_INFORMATION,
        OWNER_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR,
        PSID, TOKEN_QUERY, TOKEN_USER, TokenUser,
    },
    System::Threading::{GetCurrentProcess, OpenProcessToken},
};

struct OwnedHandle(HANDLE);

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: this handle is returned by OpenProcessToken and owned here.
            unsafe {
                CloseHandle(self.0);
            }
        }
    }
}

struct LocalMem(*mut c_void);

impl Drop for LocalMem {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: buffers wrapped by LocalMem are allocated by Win32 APIs
            // whose contract requires LocalFree.
            unsafe {
                LocalFree(self.0);
            }
        }
    }
}

fn io_context(context: &str) -> io::Error {
    let source = io::Error::last_os_error();
    io::Error::new(source.kind(), format!("{context}: {source}"))
}

fn wide_path(path: &Path) -> Vec<u16> {
    path.as_os_str().encode_wide().chain(std::iter::once(0)).collect()
}

fn wide_string(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

fn sid_to_string(sid: PSID) -> io::Result<String> {
    if sid.is_null() {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "null SID"));
    }

    let mut ptr = null_mut();
    // SAFETY: sid points to a valid SID owned by a live token/security descriptor;
    // ConvertSidToStringSidW allocates ptr with LocalAlloc on success.
    if unsafe { ConvertSidToStringSidW(sid, &mut ptr) } == 0 {
        return Err(io_context("ConvertSidToStringSidW failed"));
    }
    let allocation = LocalMem(ptr.cast());

    let mut len = 0usize;
    // SAFETY: ptr is a NUL-terminated UTF-16 string returned by Win32.
    unsafe {
        while *ptr.add(len) != 0 {
            len += 1;
        }
    }
    // SAFETY: the preceding scan found the terminating NUL.
    let text = unsafe { String::from_utf16_lossy(slice::from_raw_parts(ptr, len)) };
    drop(allocation);
    Ok(text)
}

fn current_user_sid_string() -> io::Result<String> {
    let mut token: HANDLE = null_mut();
    // SAFETY: GetCurrentProcess returns the current process pseudo-handle and
    // token receives a new handle on success.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return Err(io_context("OpenProcessToken failed"));
    }
    let token = OwnedHandle(token);

    let mut needed = 0u32;
    // First call obtains the required buffer size. Failure is expected.
    unsafe {
        GetTokenInformation(token.0, TokenUser, null_mut(), 0, &mut needed);
    }
    if needed == 0 {
        return Err(io_context("GetTokenInformation size query failed"));
    }

    let mut buffer = vec![0u8; needed as usize];
    // SAFETY: buffer has the size requested by GetTokenInformation.
    if unsafe {
        GetTokenInformation(
            token.0,
            TokenUser,
            buffer.as_mut_ptr().cast(),
            needed,
            &mut needed,
        )
    } == 0
    {
        return Err(io_context("GetTokenInformation(TokenUser) failed"));
    }

    // TOKEN_USER may not be naturally aligned inside Vec<u8>; read_unaligned
    // avoids creating an unaligned reference.
    let token_user = unsafe { (buffer.as_ptr() as *const TOKEN_USER).read_unaligned() };
    sid_to_string(token_user.User.Sid)
}

fn owner_sid_for_path(path: &Path) -> io::Result<String> {
    let wide = wide_path(path);
    let mut owner: PSID = null_mut();
    let mut descriptor: PSECURITY_DESCRIPTOR = null_mut();

    // SAFETY: wide is NUL-terminated; output pointers are valid for the call.
    let status = unsafe {
        GetNamedSecurityInfoW(
            wide.as_ptr(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION,
            &mut owner,
            null_mut(),
            null_mut(),
            null_mut(),
            &mut descriptor,
        )
    };
    if status != 0 {
        return Err(io::Error::from_raw_os_error(status as i32));
    }
    let descriptor_mem = LocalMem(descriptor.cast());
    let owner = sid_to_string(owner)?;
    drop(descriptor_mem);
    Ok(owner)
}

fn descriptor_to_sddl(descriptor: PSECURITY_DESCRIPTOR) -> io::Result<String> {
    let mut ptr = null_mut();
    let mut len = 0u32;
    // SAFETY: descriptor is a live security descriptor returned by Win32.
    if unsafe {
        ConvertSecurityDescriptorToStringSecurityDescriptorW(
            descriptor,
            SDDL_REVISION_1,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut ptr,
            &mut len,
        )
    } == 0
    {
        return Err(io_context(
            "ConvertSecurityDescriptorToStringSecurityDescriptorW failed",
        ));
    }
    let text_mem = LocalMem(ptr.cast());
    // Win32 returns the character count excluding the terminating NUL.
    let text = unsafe { String::from_utf16_lossy(slice::from_raw_parts(ptr, len as usize)) };
    drop(text_mem);
    Ok(text)
}

fn security_sddl_for_file_handle(file: &File) -> io::Result<String> {
    let mut descriptor: PSECURITY_DESCRIPTOR = null_mut();
    let mut owner: PSID = null_mut();

    // SAFETY: AsRawHandle exposes the live file handle without transferring
    // ownership. GetSecurityInfo allocates descriptor with LocalAlloc.
    let status = unsafe {
        GetSecurityInfo(
            file.as_raw_handle() as HANDLE,
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut owner,
            null_mut(),
            null_mut(),
            null_mut(),
            &mut descriptor,
        )
    };
    if status != 0 {
        return Err(io::Error::from_raw_os_error(status as i32));
    }
    let descriptor_mem = LocalMem(descriptor.cast());
    let text = descriptor_to_sddl(descriptor)?;
    drop(descriptor_mem);
    Ok(text)
}

fn is_builtin_administrators_sid(sid: &str) -> bool {
    sid.eq_ignore_ascii_case("BA") || sid.eq_ignore_ascii_case("S-1-5-32-544")
}

fn owner_is_safe_to_resecure(owner_sid: &str, current_sid: &str) -> bool {
    owner_sid.eq_ignore_ascii_case(current_sid) || is_builtin_administrators_sid(owner_sid)
}

fn apply_protected_dacl(path: &Path, directory: bool) -> io::Result<()> {
    let current_sid = current_user_sid_string()?;
    let owner_sid = owner_sid_for_path(path)?;

    // Elevated Windows processes can create objects owned by
    // BUILTIN\\Administrators rather than the token user's SID. Accept only
    // that privileged Windows default (or the current user) as a starting
    // state. Arbitrary third-party ownership still fails closed.
    if !owner_is_safe_to_resecure(&owner_sid, &current_sid) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "refusing to secure '{}': object owner {owner_sid} is neither current user {current_sid} nor BUILTIN\\\\Administrators",
                path.display()
            ),
        ));
    }

    // Normalize ownership to the actual token user while applying a protected
    // DACL. No BUILTIN\\Administrators ACE is added: ordinary access is current
    // user + LocalSystem only.
    let security = if directory {
        format!("O:{current_sid}D:P(A;OICI;FA;;;{current_sid})(A;OICI;FA;;;SY)")
    } else {
        format!("O:{current_sid}D:P(A;;FA;;;{current_sid})(A;;FA;;;SY)")
    };
    let wide_security = wide_string(&security);

    let mut descriptor: PSECURITY_DESCRIPTOR = null_mut();
    let mut descriptor_size = 0u32;
    // SAFETY: wide_security is NUL-terminated and output descriptor is freed below.
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            wide_security.as_ptr(),
            SDDL_REVISION_1,
            &mut descriptor,
            &mut descriptor_size,
        )
    } == 0
    {
        return Err(io_context(
            "ConvertStringSecurityDescriptorToSecurityDescriptorW failed",
        ));
    }
    let descriptor_mem = LocalMem(descriptor.cast());
    let wide = wide_path(path);

    // Set owner and DACL together. PROTECTED_DACL prevents parent inheritance
    // from later reintroducing broader permissions.
    if unsafe {
        SetFileSecurityW(
            wide.as_ptr(),
            OWNER_SECURITY_INFORMATION
                | DACL_SECURITY_INFORMATION
                | PROTECTED_DACL_SECURITY_INFORMATION,
            descriptor,
        )
    } == 0
    {
        return Err(io_context("SetFileSecurityW failed"));
    }

    drop(descriptor_mem);

    let normalized_owner = owner_sid_for_path(path)?;
    if !normalized_owner.eq_ignore_ascii_case(&current_sid) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "secured '{}' but owner remained {normalized_owner} instead of current user {current_sid}",
                path.display()
            ),
        ));
    }

    Ok(())
}

pub(crate) fn harden_directory(path: &Path) -> io::Result<()> {
    apply_protected_dacl(path, true)
}

pub(crate) fn harden_file(path: &Path) -> io::Result<()> {
    apply_protected_dacl(path, false)
}

/// Migrate pre-existing wallet artifacts when the wallet manager starts.
/// Existing files predate the protected directory DACL, so relying only on
/// inheritance would leave them with their historical ACLs.
pub(crate) fn harden_wallet_directory_contents(path: &Path) -> io::Result<()> {
    for entry in std::fs::read_dir(path)? {
        let entry = entry?;
        let candidate = entry.path();
        let metadata = std::fs::symlink_metadata(&candidate)?;

        if metadata.file_type().is_symlink() {
            if candidate.extension().and_then(|v| v.to_str()) == Some("json") {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "refusing to secure wallet symlink/reparse entry '{}'",
                        candidate.display()
                    ),
                ));
            }
            continue;
        }

        if metadata.is_file() {
            let is_wallet = candidate.extension().and_then(|v| v.to_str()) == Some("json");
            let is_temp = candidate.extension().and_then(|v| v.to_str()) == Some("tmp");
            if is_wallet || is_temp {
                harden_file(&candidate)?;
            }
        }
    }
    Ok(())
}

fn parse_owner_from_sddl(sddl: &str) -> Option<&str> {
    let rest = sddl.strip_prefix("O:")?;
    let end = ["G:", "D:", "S:"]
        .iter()
        .filter_map(|marker| rest.find(marker))
        .min()
        .unwrap_or(rest.len());
    Some(&rest[..end])
}

fn trusted_secret_trustee(trustee: &str, current_sid: &str) -> bool {
    trustee.eq_ignore_ascii_case(current_sid)
        || matches!(
            trustee.to_ascii_uppercase().as_str(),
            // LocalSystem and Builtin Administrators are accepted for imported
            // secret files. An elevated administrator can read process memory
            // regardless, so rejecting BA provides no meaningful boundary.
            "SY" | "S-1-5-18" | "BA" | "S-1-5-32-544" | "OW" | "S-1-3-4"
        )
}

fn validate_sddl_dacl(sddl: &str, current_sid: &str) -> std::result::Result<(), String> {
    let dacl_start = sddl
        .find("D:")
        .ok_or_else(|| "security descriptor has no DACL".to_string())?;
    let dacl = &sddl[dacl_start + 2..];
    let dacl = dacl.split("S:").next().unwrap_or(dacl);

    if dacl.contains("NO_ACCESS_CONTROL") {
        return Err("file has a NULL DACL (effectively unrestricted access)".to_string());
    }

    let mut remainder = dacl;
    while let Some(open) = remainder.find('(') {
        let after_open = &remainder[open + 1..];
        let close = after_open
            .find(')')
            .ok_or_else(|| "malformed ACL entry".to_string())?;
        let ace = &after_open[..close];
        let fields: Vec<&str> = ace.split(';').collect();
        if fields.len() != 6 {
            return Err(format!(
                "complex or conditional ACL entry is not accepted for secret files: ({ace})"
            ));
        }

        let ace_type = fields[0].to_ascii_uppercase();
        let trustee = fields[5].trim();

        match ace_type.as_str() {
            // Simple and object-specific allow ACEs can expose the secret.
            "A" | "OA" => {
                if !trusted_secret_trustee(trustee, current_sid) {
                    return Err(format!(
                        "ACL grants access to untrusted security principal '{trustee}'"
                    ));
                }
            }
            // Deny ACEs do not broaden access.
            "D" | "OD" => {}
            _ => {
                return Err(format!(
                    "unsupported ACL entry type '{ace_type}' on secret file"
                ));
            }
        }

        remainder = &after_open[close + 1..];
    }

    Ok(())
}

pub(crate) fn validate_secret_file(file: &File, file_path: &str, kind: &str) -> Result<()> {
    let metadata = file.metadata().map_err(|e| {
        QuantusError::Generic(format!(
            "Failed to inspect {kind} file '{file_path}': {e}"
        ))
    })?;
    if !metadata.is_file() {
        return Err(QuantusError::Generic(format!(
            "🔒 Refusing to read {kind} file '{file_path}': it is not a regular file."
        )));
    }

    let current_sid = current_user_sid_string().map_err(|e| {
        QuantusError::Generic(format!(
            "Failed to identify the current Windows user while validating {kind} file '{file_path}': {e}"
        ))
    })?;
    let sddl = security_sddl_for_file_handle(file).map_err(|e| {
        QuantusError::Generic(format!(
            "Failed to inspect Windows ACL for {kind} file '{file_path}': {e}"
        ))
    })?;

    let owner = parse_owner_from_sddl(&sddl).ok_or_else(|| {
        QuantusError::Generic(format!(
            "🔒 Refusing to read {kind} file '{file_path}': Windows security descriptor has no owner."
        ))
    })?;
    // Elevated Windows processes commonly create files owned by the
    // BUILTIN\\Administrators group. Accept that privileged owner only when
    // the DACL below is also restricted to the trusted principals.
    if !owner.eq_ignore_ascii_case(&current_sid) && !is_builtin_administrators_sid(owner) {
        return Err(QuantusError::Generic(format!(
            "🔒 Refusing to read {kind} file '{file_path}': it is owned by '{owner}', not the current user or BUILTIN\\\\Administrators."
        )));
    }

    validate_sddl_dacl(&sddl, &current_sid).map_err(|reason| {
        QuantusError::Generic(format!(
            "🔒 Refusing to read {kind} file '{file_path}': {reason}. \
             Restrict the file ACL to your account, SYSTEM, and (if required) local Administrators."
        ))
    })
}

fn security_sddl_for_path(path: &Path) -> io::Result<String> {
    let wide = wide_path(path);
    let mut owner: PSID = null_mut();
    let mut dacl = null_mut();
    let mut descriptor: PSECURITY_DESCRIPTOR = null_mut();

    // SAFETY: wide is NUL-terminated; output pointers are valid for this call.
    let status = unsafe {
        GetNamedSecurityInfoW(
            wide.as_ptr(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut owner,
            null_mut(),
            &mut dacl,
            null_mut(),
            &mut descriptor,
        )
    };
    if status != 0 {
        return Err(io::Error::from_raw_os_error(status as i32));
    }

    let descriptor_mem = LocalMem(descriptor.cast());
    let text = descriptor_to_sddl(descriptor)?;
    drop(descriptor_mem);
    Ok(text)
}

fn validate_wallet_sddl(sddl: &str, current_sid: &str) -> std::result::Result<(), String> {
    let owner = parse_owner_from_sddl(sddl)
        .ok_or_else(|| "security descriptor has no owner".to_string())?;
    if !owner.eq_ignore_ascii_case(current_sid) {
        return Err(format!(
            "owner {owner} does not match current user {current_sid}"
        ));
    }

    let dacl_start = sddl
        .find("D:")
        .ok_or_else(|| "security descriptor has no DACL".to_string())?;
    let dacl = &sddl[dacl_start + 2..];
    let dacl = dacl.split("S:").next().unwrap_or(dacl);

    if dacl.contains("NO_ACCESS_CONTROL") {
        return Err("wallet path has a NULL DACL".to_string());
    }

    let ace_start = dacl.find('(').unwrap_or(dacl.len());
    let flags = &dacl[..ace_start];
    if !flags.to_ascii_uppercase().contains('P') {
        return Err("wallet DACL is not protected from inheritance".to_string());
    }

    let mut saw_user = false;
    let mut saw_system = false;
    let mut remainder = &dacl[ace_start..];

    while let Some(open) = remainder.find('(') {
        let after_open = &remainder[open + 1..];
        let close = after_open
            .find(')')
            .ok_or_else(|| "malformed ACL entry".to_string())?;
        let ace = &after_open[..close];
        let fields: Vec<&str> = ace.split(';').collect();
        if fields.len() != 6 {
            return Err(format!("complex ACL entry is not accepted: ({ace})"));
        }

        let ace_type = fields[0].to_ascii_uppercase();
        let trustee = fields[5].trim();

        if !matches!(ace_type.as_str(), "A" | "OA") {
            return Err(format!(
                "unexpected ACL entry type '{ace_type}' on wallet path"
            ));
        }

        if trustee.eq_ignore_ascii_case(current_sid) {
            saw_user = true;
        } else if matches!(
            trustee.to_ascii_uppercase().as_str(),
            "SY" | "S-1-5-18"
        ) {
            saw_system = true;
        } else {
            return Err(format!(
                "wallet ACL grants access to unexpected principal '{trustee}'"
            ));
        }

        remainder = &after_open[close + 1..];
    }

    if !saw_user {
        return Err("wallet ACL has no allow ACE for the current user".to_string());
    }
    if !saw_system {
        return Err("wallet ACL has no allow ACE for LocalSystem".to_string());
    }

    Ok(())
}

/// Read-only validation used by `quantus doctor`.
pub(crate) fn validate_wallet_path(path: &Path, directory: bool) -> io::Result<()> {
    use std::os::windows::fs::MetadataExt;

    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;

    let metadata = std::fs::symlink_metadata(path)?;
    if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "wallet path is a Windows reparse point",
        ));
    }

    if directory && !metadata.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "wallet path is not a directory",
        ));
    }
    if !directory && !metadata.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "wallet path is not a regular file",
        ));
    }

    let current_sid = current_user_sid_string()?;
    let sddl = security_sddl_for_path(path)?;
    validate_wallet_sddl(&sddl, &current_sid)
        .map_err(|reason| io::Error::new(io::ErrorKind::PermissionDenied, reason))
}

#[cfg(test)]
mod tests {

    #[test]
    fn wallet_acl_parser_accepts_only_protected_user_and_system_acl() {
        let current = "S-1-5-21-111-222-333-1001";
        let sddl = format!(
            "O:{current}D:P(A;;FA;;;{current})(A;;FA;;;SY)"
        );
        assert!(validate_wallet_sddl(&sddl, current).is_ok());
    }

    #[test]
    fn wallet_acl_parser_rejects_builtin_admins_access() {
        let current = "S-1-5-21-111-222-333-1001";
        let sddl = format!(
            "O:{current}D:P(A;;FA;;;{current})(A;;FA;;;SY)(A;;FA;;;BA)"
        );
        assert!(validate_wallet_sddl(&sddl, current).is_err());
    }

    #[test]
    fn wallet_acl_parser_rejects_inherited_dacl() {
        let current = "S-1-5-21-111-222-333-1001";
        let sddl = format!(
            "O:{current}D:(A;;FA;;;{current})(A;;FA;;;SY)"
        );
        assert!(validate_wallet_sddl(&sddl, current).is_err());
    }
    use super::*;

    #[test]
    fn secret_acl_parser_accepts_current_user_system_and_admins() {
        let current = "S-1-5-21-111-222-333-1001";
        let sddl = format!(
            "O:{current}D:PAI(A;;FA;;;{current})(A;;FA;;;SY)(A;;FR;;;BA)"
        );
        assert!(validate_sddl_dacl(&sddl, current).is_ok());
    }

    #[test]
    fn secret_acl_parser_rejects_everyone() {
        let current = "S-1-5-21-111-222-333-1001";
        let sddl = format!("O:{current}D:P(A;;FA;;;{current})(A;;FR;;;WD)");
        let err = validate_sddl_dacl(&sddl, current).unwrap_err();
        assert!(err.contains("untrusted"));
    }

    #[test]
    fn secret_acl_parser_rejects_authenticated_users() {
        let current = "S-1-5-21-111-222-333-1001";
        let sddl = format!("O:{current}D:P(A;;FA;;;{current})(A;;FR;;;AU)");
        assert!(validate_sddl_dacl(&sddl, current).is_err());
    }

    #[test]
    fn hardening_owner_policy_accepts_current_user_and_builtin_admins() {
        let current = "S-1-5-21-111-222-333-1001";
        assert!(owner_is_safe_to_resecure(current, current));
        assert!(owner_is_safe_to_resecure("BA", current));
        assert!(owner_is_safe_to_resecure("S-1-5-32-544", current));
        assert!(!owner_is_safe_to_resecure("S-1-5-21-999-888-777-1002", current));
    }

    #[test]
    fn harden_and_validate_real_temp_file() {
        let dir = tempfile::tempdir().expect("temp dir");
        harden_directory(dir.path()).expect("harden temp directory");

        let path = dir.path().join("secret.txt");
        std::fs::write(&path, b"secret").expect("write secret");
        harden_file(&path).expect("harden secret");
        let file = File::open(&path).expect("open secret");
        validate_secret_file(&file, path.to_str().unwrap(), "test secret")
            .expect("secure ACL should validate");
    }
}
