use std::{ffi::OsString, os::windows::ffi::OsStringExt, path::Path};
use tracing::{debug, info, instrument};
use windows::core::BOOL;
use windows::Win32::System::Threading::OpenProcessToken;
use windows::Win32::{
    Foundation::{CloseHandle, HANDLE, NTSTATUS},
    Security::{
        DuplicateToken, ImpersonateLoggedOnUser, RevertToSelf, SecurityImpersonation,
        TOKEN_DUPLICATE, TOKEN_QUERY,
    },
    System::{
        ProcessStatus::{EnumProcesses, K32GetProcessImageFileNameW},
        Threading::{OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ},
    },
};

use crate::error::{convert_windows_error, BrowserVoyageError, BrowserVoyageResult};

#[link(name = "ntdll")]
extern "system" {
    fn RtlAdjustPrivilege(
        privilege: i32,
        enable: BOOL,
        current_thread: BOOL,
        previous_value: *mut BOOL,
    ) -> NTSTATUS;
}

#[instrument]
fn enable_privilege() -> BrowserVoyageResult<()> {
    use windows::Wdk::System::SystemServices::SE_DEBUG_PRIVILEGE;
    let mut previous_value = BOOL(0);
    let status =
        unsafe { RtlAdjustPrivilege(SE_DEBUG_PRIVILEGE, BOOL(1), BOOL(0), &mut previous_value) };
    if status.0 != 0 {
        return Err(BrowserVoyageError::Windows(format!(
            "RtlAdjustPrivilege failed with status: 0x{:08X}",
            status.0
        )));
    }
    debug!("Debug privilege enabled");
    Ok(())
}

#[instrument(skip_all)]
fn get_process_pids() -> BrowserVoyageResult<Vec<u32>> {
    let mut cb_needed: u32 = 0;
    let mut a_processes: Vec<u32> = Vec::with_capacity(1024);

    unsafe {
        // Convert Windows error to BrowserVoyageError manually
        match EnumProcesses(a_processes.as_mut_ptr(), 1024 * 4, &mut cb_needed) {
            Ok(_) => {}
            Err(e) => return Err(convert_windows_error(e)),
        }
        a_processes.set_len((cb_needed / 4) as usize);
    };
    let c_processes = cb_needed / 4;

    let processes: Vec<u32> = a_processes
        .iter()
        .take(c_processes as usize)
        .copied()
        .collect();

    debug!("Found {} processes", processes.len());
    Ok(processes)
}

#[instrument]
fn get_process_name(pid: u32) -> BrowserVoyageResult<String> {
    unsafe {
        // Open the process with permissions to query information and read VM
        let process_handle: HANDLE =
            match OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid) {
                Ok(handle) => handle,
                Err(e) => return Err(convert_windows_error(e)),
            };

        if process_handle.is_invalid() {
            return Err(convert_windows_error(windows::core::Error::from_win32()));
        }
        let mut buffer = vec![0u16; 260]; // 260 is the max path length in Windows

        // Get the process image file name
        let length = K32GetProcessImageFileNameW(process_handle, &mut buffer) as usize;
        match CloseHandle(process_handle) {
            Ok(_) => {}
            Err(e) => return Err(convert_windows_error(e)),
        }

        // Convert the buffer to a Rust String and trim the null terminator
        let full_path = OsString::from_wide(&buffer[..length])
            .to_string_lossy()
            .into_owned();
        let executable_name = Path::new(&full_path)
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("")
            .to_string();
        Ok(executable_name)
    }
}

#[instrument]
fn get_system_process_pid() -> BrowserVoyageResult<u32> {
    let mut fallback_pid = None;

    for pid in get_process_pids()? {
        let process_name = get_process_name(pid).unwrap_or_default();

        if process_name == "lsass.exe" {
            debug!("Found lsass.exe with PID: {}", pid);
            return Ok(pid);
        } else if process_name == "winlogon.exe" {
            fallback_pid = Some(pid);
        }
    }
    if let Some(pid) = fallback_pid {
        debug!("Using winlogon.exe as fallback with PID: {}", pid);
        return Ok(pid);
    }

    Err(BrowserVoyageError::NoDataFound)
        .map_err(|e| e.with_info("Neither lsass.exe nor winlogon.exe found!"))
}

#[instrument]
fn get_process_handle(pid: u32) -> BrowserVoyageResult<HANDLE> {
    unsafe {
        // Open the process with PROCESS_QUERY_INFORMATION permission
        let process_handle = match OpenProcess(PROCESS_QUERY_INFORMATION, false, pid) {
            Ok(handle) => handle,
            Err(e) => return Err(convert_windows_error(e)),
        };

        // Check if the handle is valid
        if process_handle.is_invalid() {
            Err(convert_windows_error(windows::core::Error::from_win32()))
        } else {
            Ok(process_handle)
        }
    }
}

#[instrument(skip(handle))]
fn close_handle(handle: HANDLE) -> BrowserVoyageResult<()> {
    unsafe {
        match CloseHandle(handle) {
            Ok(_) => Ok(()),
            Err(e) => Err(convert_windows_error(e)),
        }
    }
}

#[instrument(skip(lsass_handle))]
fn get_system_token(lsass_handle: HANDLE) -> BrowserVoyageResult<HANDLE> {
    let mut token_handle = HANDLE::default();
    unsafe {
        match OpenProcessToken(
            lsass_handle,
            TOKEN_DUPLICATE | TOKEN_QUERY,
            &mut token_handle,
        ) {
            Ok(_) => {}
            Err(e) => return Err(convert_windows_error(e)),
        }
    }

    let mut duplicate_token = HANDLE::default();
    unsafe {
        match DuplicateToken(token_handle, SecurityImpersonation, &mut duplicate_token) {
            Ok(_) => {}
            Err(e) => return Err(convert_windows_error(e)),
        }

        match CloseHandle(token_handle) {
            Ok(_) => {}
            Err(e) => return Err(convert_windows_error(e)),
        }
    }

    Ok(duplicate_token)
}

#[instrument]
pub fn start_impersonate() -> BrowserVoyageResult<HANDLE> {
    enable_privilege()?;
    let pid = get_system_process_pid()?;
    let lsass_handle = get_process_handle(pid)?;
    let duplicated_token = get_system_token(lsass_handle)?;
    close_handle(lsass_handle)?;
    unsafe {
        match ImpersonateLoggedOnUser(duplicated_token) {
            Ok(_) => {}
            Err(e) => return Err(convert_windows_error(e)),
        }
    }
    debug!("Successfully started impersonation");
    Ok(duplicated_token)
}

#[instrument(skip(duplicated_token))]
pub fn stop_impersonate(duplicated_token: HANDLE) -> BrowserVoyageResult<()> {
    unsafe {
        match CloseHandle(duplicated_token) {
            Ok(_) => {}
            Err(e) => return Err(convert_windows_error(e)),
        }

        match RevertToSelf() {
            Ok(_) => {}
            Err(e) => return Err(convert_windows_error(e)),
        }
    }
    debug!("Successfully stopped impersonation");
    Ok(())
}

pub struct ImpersonationGuard {
    token: HANDLE,
}

impl ImpersonationGuard {
    pub fn new() -> BrowserVoyageResult<Self> {
        let token = start_impersonate()?;
        Ok(Self { token })
    }
}

impl Drop for ImpersonationGuard {
    fn drop(&mut self) {
        if let Err(e) = stop_impersonate(self.token) {
            tracing::error!("Failed to stop impersonation: {}", e);
        }
    }
}
