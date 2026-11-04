//! Anonymous, read-only child input. No private query in argv, files or environment.
use std::ffi::c_void;
use windows_sys::Win32::{
    Foundation::*, Security::SECURITY_ATTRIBUTES, System::Threading::GetCurrentProcess,
};
use zeroize::{Zeroize, Zeroizing};

const LIMIT: usize = 24 * 1024;
type Result<T> = std::result::Result<T, &'static str>;
#[link(name = "kernel32")]
unsafe extern "system" {
    fn CreateFileMappingW(
        file: HANDLE,
        attributes: *const SECURITY_ATTRIBUTES,
        protect: u32,
        high: u32,
        low: u32,
        name: *const u16,
    ) -> HANDLE;
    fn MapViewOfFile(
        mapping: HANDLE,
        access: u32,
        high: u32,
        low: u32,
        length: usize,
    ) -> *mut c_void;
    fn UnmapViewOfFile(view: *const c_void) -> i32;
}

pub(super) struct Input {
    section: HANDLE,
    pub child: HANDLE,
    view: *mut c_void,
    length: usize,
}
impl Drop for Input {
    fn drop(&mut self) {
        unsafe {
            if !self.view.is_null() {
                std::slice::from_raw_parts_mut(self.view.cast::<u8>(), self.length).zeroize();
                UnmapViewOfFile(self.view);
            }
            if !self.child.is_null() {
                CloseHandle(self.child);
            }
            if !self.section.is_null() {
                CloseHandle(self.section);
            }
        }
    }
}
impl Input {
    pub fn new(bytes: &[u8]) -> Result<Self> {
        if bytes.is_empty() || bytes.len() > LIMIT {
            return Err("request_limit");
        }
        let section = unsafe {
            CreateFileMappingW(
                INVALID_HANDLE_VALUE,
                std::ptr::null(),
                4,
                0,
                bytes.len() as u32,
                std::ptr::null(),
            )
        };
        if section.is_null() {
            return Err("user_probe_unavailable");
        }
        let mut input = Self {
            section,
            child: std::ptr::null_mut(),
            view: std::ptr::null_mut(),
            length: bytes.len(),
        };
        input.view = unsafe { MapViewOfFile(section, 2, 0, 0, bytes.len()) };
        if input.view.is_null() {
            return Err("user_probe_unavailable");
        }
        unsafe {
            std::ptr::copy_nonoverlapping(bytes.as_ptr(), input.view.cast::<u8>(), bytes.len());
        }
        if unsafe {
            DuplicateHandle(
                GetCurrentProcess(),
                section,
                GetCurrentProcess(),
                &mut input.child,
                4,
                1,
                0,
            )
        } == 0
        {
            return Err("user_probe_unavailable");
        }
        Ok(input)
    }
    pub fn descriptor(&self) -> String {
        format!("{}:{}", self.child as usize, self.length)
    }
}

pub(super) fn receive(descriptor: &str) -> Result<Zeroizing<Vec<u8>>> {
    if descriptor.len() > 40 {
        return Err("invalid_observer_input");
    }
    let (handle, length) = descriptor.split_once(':').ok_or("invalid_observer_input")?;
    let handle: usize = handle.parse().map_err(|_| "invalid_observer_input")?;
    let length: usize = length.parse().map_err(|_| "invalid_observer_input")?;
    if handle == 0
        || handle >= isize::MAX as usize
        || !(1..=LIMIT).contains(&length)
        || descriptor != format!("{handle}:{length}")
    {
        return Err("invalid_observer_input");
    }
    let mut flags = 0;
    if unsafe { GetHandleInformation(handle as HANDLE, &mut flags) } == 0
        || flags & HANDLE_FLAG_INHERIT == 0
    {
        return Err("invalid_observer_input");
    }
    let view = unsafe { MapViewOfFile(handle as HANDLE, 4, 0, 0, length) };
    if view.is_null() {
        return Err("invalid_observer_input");
    }
    let bytes =
        Zeroizing::new(unsafe { std::slice::from_raw_parts(view.cast::<u8>(), length) }.to_vec());
    unsafe {
        UnmapViewOfFile(view);
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn private_section_is_anonymous_read_only_bounded_and_has_no_data_in_descriptor() {
        let input = Input::new(b"synthetic private query").unwrap();
        assert!(!input.descriptor().contains("synthetic"));
        assert_eq!(
            receive(&input.descriptor()).unwrap().as_slice(),
            b"synthetic private query"
        );
        let writable = unsafe { MapViewOfFile(input.child, 2, 0, 0, input.length) };
        if !writable.is_null() {
            unsafe {
                UnmapViewOfFile(writable);
            }
        }
        assert!(writable.is_null());
        assert!(Input::new(&[]).is_err());
        assert!(Input::new(&vec![0; LIMIT + 1]).is_err());
    }
    #[test]
    fn invalid_or_noninherited_handles_never_provide_input() {
        for value in [
            "",
            "0:1",
            "1:0",
            "1:24577",
            "-1:1",
            "01:1",
            "data:image/png",
            "1:1:1",
        ] {
            assert!(receive(value).is_err());
        }
        let input = Input::new(b"synthetic").unwrap();
        assert!(receive(&format!("{}:9", input.section as usize)).is_err());
    }

    #[test]
    fn one_thousand_private_sections_release_views_and_handles() {
        use windows_sys::Win32::System::Threading::GetProcessHandleCount;
        let handles = || {
            let mut count = 0;
            assert_ne!(
                unsafe { GetProcessHandleCount(GetCurrentProcess(), &mut count) },
                0
            );
            count
        };
        let before = handles();
        for _ in 0..1000 {
            let input = Input::new(&[b'q'; 24 * 1024]).unwrap();
            let result = receive(&input.descriptor()).unwrap();
            assert_eq!(result.as_slice(), &[b'q'; 24 * 1024]);
        }
        assert!(handles() <= before + 2);
    }
}
