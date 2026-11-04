//! Package-manager records establish installation metadata, never execution.
use crate::*;

const MAX_PACKAGES: usize = 5000;

struct DpkgPage {
    packages: Vec<String>,
    saturated: bool,
}

fn scan_dpkg(
    bytes: &[u8],
    budget: &Budget<'_>,
    mut record: impl FnMut(&str, usize),
) -> Result<usize, &'static str> {
    if bytes.len() > 16 * 1024 * 1024 {
        return Err("package_index_limit");
    }
    let text = std::str::from_utf8(bytes).map_err(|_| "invalid_package_index")?;
    let mut package = None;
    let mut installed = false;
    let mut seen_status = false;
    let mut count = 0;
    for line in text.lines().chain(std::iter::once("")) {
        budget.check()?;
        if line.len() > 16 * 1024 {
            return Err("invalid_package_index");
        }
        if line.is_empty() {
            if installed {
                record(package.take().ok_or("invalid_package_index")?, count);
                count += 1;
            }
            package = None;
            installed = false;
            seen_status = false;
        } else if let Some(value) = line.strip_prefix("Package: ") {
            if package.is_some()
                || value.is_empty()
                || value.len() > 128
                || !value.bytes().all(|byte| {
                    byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"+.-".contains(&byte)
                })
            {
                return Err("invalid_package_index");
            }
            package = Some(value);
        } else if let Some(value) = line.strip_prefix("Status: ") {
            if seen_status {
                return Err("invalid_package_index");
            }
            seen_status = true;
            installed = value == "install ok installed";
        }
    }
    Ok(count)
}

fn dpkg_page(bytes: &[u8], budget: &Budget<'_>, sequence: u64) -> Result<DpkgPage, &'static str> {
    let mut packages = std::collections::BTreeSet::new();
    let count = scan_dpkg(bytes, budget, |package, index| {
        if index < MAX_PACKAGES {
            packages.insert(package.to_owned());
        }
    })?;
    let saturated = count > MAX_PACKAGES;
    if saturated {
        // Consecutive collections cover the complete index without retaining an
        // unbounded package list or permanently hiding records after the cap.
        let offset = ((sequence.saturating_sub(1) % count as u64) * MAX_PACKAGES as u64
            % count as u64) as usize;
        if offset != 0 {
            packages.clear();
            scan_dpkg(bytes, budget, |package, index| {
                if (index + count - offset) % count < MAX_PACKAGES {
                    packages.insert(package.to_owned());
                }
            })?;
        }
    }
    Ok(DpkgPage {
        packages: packages.into_iter().collect(),
        saturated,
    })
}

pub fn dpkg_status(bytes: &[u8], budget: &Budget<'_>) -> Result<Vec<String>, &'static str> {
    dpkg_page(bytes, budget, 1).map(|page| page.packages)
}

fn project_dpkg(snapshot: &mut Snapshot, packages: Result<DpkgPage, &'static str>) {
    let status = match packages {
        Ok(page) => {
            if project(snapshot, page.packages) && !page.saturated {
                CoverageStatus::Partial
            } else {
                CoverageStatus::Saturated
            }
        }
        Err("timeout" | "cancelled") => CoverageStatus::Timeout,
        Err("package_index_unavailable") => CoverageStatus::Unavailable,
        Err("package_index_limit") => CoverageStatus::Saturated,
        Err(_) => CoverageStatus::Partial,
    };
    coverage(snapshot, "installed-packages", status, false);
}

fn project(snapshot: &mut Snapshot, packages: impl IntoIterator<Item = String>) -> bool {
    let host = identity("host", &[&snapshot.scope]);
    if !snapshot.entities.iter().any(|e| e.id == host) {
        if snapshot.entities.len() >= MAX_ENTITIES {
            return false;
        }
        snapshot.entities.push(Entity {
            display: None,
            id: host.clone(),
            kind: EntityKind::Host,
        });
    }
    let mut field_budget = FieldBudget::new(snapshot);
    for package in packages {
        if !field_budget.insert(
            snapshot,
            &host,
            Source::Installation,
            BTreeMap::from([(Field::Package, vec![package])]),
        ) {
            return false;
        }
    }
    true
}

pub fn collect(snapshot: &mut Snapshot, budget: &Budget<'_>) {
    #[cfg(target_os = "linux")]
    {
        use std::{
            io::Read,
            os::unix::fs::{MetadataExt, OpenOptionsExt},
        };
        let packages = (|| {
            let mut file = std::fs::OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
                .open("/var/lib/dpkg/status")
                .map_err(|_| "package_index_unavailable")?;
            let metadata = file.metadata().map_err(|_| "package_index_unavailable")?;
            if !metadata.is_file() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
                return Err("invalid_package_index");
            }
            if metadata.len() > 16 * 1024 * 1024 {
                return Err("package_index_limit");
            }
            let mut bytes = vec![];
            let mut buffer = [0; 8192];
            loop {
                budget.check()?;
                let count = file
                    .read(&mut buffer)
                    .map_err(|_| "invalid_package_index")?;
                if count == 0 {
                    break;
                }
                if bytes.len() + count > 16 * 1024 * 1024 {
                    return Err("package_index_limit");
                }
                bytes.extend_from_slice(&buffer[..count]);
            }
            dpkg_page(&bytes, budget, snapshot.sequence)
        })();
        // Even a complete dpkg index does not cover portable or per-user installs.
        project_dpkg(snapshot, packages);
    }
    #[cfg(windows)]
    windows::collect(snapshot, budget);
    #[cfg(not(any(target_os = "linux", windows)))]
    {
        let _ = budget;
        coverage(
            snapshot,
            "installed-packages",
            CoverageStatus::Unavailable,
            false,
        );
    }
}

#[cfg(windows)]
mod windows {
    use super::*;
    use windows_sys::Win32::System::Registry::*;
    struct Key(HKEY);
    impl Drop for Key {
        fn drop(&mut self) {
            unsafe {
                RegCloseKey(self.0);
            }
        }
    }
    fn wide(value: &str) -> Vec<u16> {
        value.encode_utf16().chain(Some(0)).collect()
    }
    fn open(root: HKEY, path: &str, view: u32) -> Option<Key> {
        let mut key = std::ptr::null_mut();
        (unsafe { RegOpenKeyExW(root, wide(path).as_ptr(), 0, KEY_READ | view, &mut key) } == 0)
            .then_some(Key(key))
    }
    fn names(key: &Key, budget: &Budget<'_>) -> Vec<String> {
        let mut names = vec![];
        for index in 0..10_000 {
            if budget.check().is_err() {
                break;
            }
            let mut name = [0u16; 256];
            let mut length = name.len() as u32;
            let status = unsafe {
                RegEnumKeyExW(
                    key.0,
                    index,
                    name.as_mut_ptr(),
                    &mut length,
                    std::ptr::null(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                )
            };
            if status == 259 {
                break;
            }
            if status == 0 && length > 0 && (length as usize) < name.len() {
                if let Ok(value) = String::from_utf16(&name[..length as usize]) {
                    names.push(value);
                }
            }
        }
        names
    }
    fn name(key: &Key) -> Option<String> {
        let mut bytes = [0u16; 161];
        let mut length = (bytes.len() * 2) as u32;
        let mut kind = 0;
        if unsafe {
            RegQueryValueExW(
                key.0,
                wide("DisplayName").as_ptr(),
                std::ptr::null(),
                &mut kind,
                bytes.as_mut_ptr().cast(),
                &mut length,
            )
        } != 0
            || kind != REG_SZ
            || length % 2 != 0
            || length < 2
            || length as usize > bytes.len() * 2
        {
            return None;
        }
        let text = String::from_utf16(&bytes[..length as usize / 2]).ok()?;
        let text = text.strip_suffix('\0').unwrap_or(&text).trim();
        if text.is_empty() || text.len() > 160 || text.chars().any(char::is_control) {
            return None;
        }
        Some(text.to_ascii_lowercase())
    }
    fn uninstall(
        root: HKEY,
        path: &str,
        view: u32,
        packages: &mut std::collections::BTreeSet<String>,
        budget: &Budget<'_>,
    ) {
        let Some(parent) = open(root, path, view) else {
            return;
        };
        for child in names(&parent, budget) {
            if budget.check().is_err() || packages.len() >= 5000 {
                break;
            }
            if let Some(key) = open(parent.0, &child, view) {
                if let Some(name) = name(&key) {
                    packages.insert(name);
                }
            }
        }
    }
    pub(super) fn collect(snapshot: &mut Snapshot, budget: &Budget<'_>) {
        let mut packages = std::collections::BTreeSet::new();
        let machine_budget = budget.child(std::time::Duration::from_millis(500));
        let path = "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall";
        for view in [KEY_WOW64_64KEY, KEY_WOW64_32KEY] {
            uninstall(
                HKEY_LOCAL_MACHINE,
                path,
                view,
                &mut packages,
                &machine_budget,
            );
        }
        if let Some(users) = open(HKEY_USERS, "", 0) {
            for sid in names(&users, budget)
                .into_iter()
                .filter(|s| {
                    s.starts_with("S-1-")
                        && s.bytes()
                            .all(|b| b.is_ascii_digit() || b == b'-' || b == b'S')
                })
                .take(128)
            {
                for view in [KEY_WOW64_64KEY, KEY_WOW64_32KEY] {
                    uninstall(
                        users.0,
                        &format!("{sid}\\{path}"),
                        view,
                        &mut packages,
                        budget,
                    );
                }
            }
        }
        let status = if !project(snapshot, packages) {
            CoverageStatus::Saturated
        } else if budget.check().is_err() {
            CoverageStatus::Timeout
        } else {
            CoverageStatus::Partial
        };
        // Only loaded user hives are readable without altering user state.
        coverage(snapshot, "installed-packages", status, false);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn only_installed_package_records_are_projected_without_commands_or_descriptions() {
        let stop = AtomicBool::new(false);
        let budget = Budget::new(Duration::from_secs(1), &stop);
        let packages=dpkg_status(b"Package: ollama\nStatus: install ok installed\nDescription: private prompt metadata must stay local\n\nPackage: openclaw\nStatus: deinstall ok config-files\n\nPackage: hermes\nStatus: install ok unpacked\n",&budget).unwrap();
        assert_eq!(packages, vec!["ollama"]);
        let mut snapshot = empty("endpoint", 1, 100);
        assert!(project(&mut snapshot, packages));
        assert_eq!(snapshot.facts[0].source, Source::Installation);
        assert_eq!(snapshot.facts[0].fields[&Field::Package], vec!["ollama"]);
        assert!(
            !serde_json::to_string(&snapshot)
                .unwrap()
                .contains("private prompt")
        );
        validate_snapshot(&snapshot).unwrap();
        for bytes in [
            b"Package: ../image.png\nStatus: install ok installed".as_slice(),
            b"Package: ollama\nPackage: openclaw\nStatus: install ok installed",
            b"Package: ollama\nStatus: install ok installed\nStatus: deinstall ok config-files",
            b"Status: install ok installed",
            b"\x89PNG",
        ] {
            assert!(dpkg_status(bytes, &budget).is_err());
        }
        stop.store(true, Ordering::Release);
        assert_eq!(dpkg_status(b"Package: ollama", &budget), Err("cancelled"));
    }

    #[test]
    fn oversized_dpkg_index_keeps_bounded_positive_installation_metadata() {
        let stop = AtomicBool::new(false);
        let budget = Budget::new(Duration::from_secs(3), &stop);
        let mut bytes = b"Package: ollama\nStatus: install ok installed\n\n".to_vec();
        for index in 0..5001 {
            bytes.extend_from_slice(
                format!("Package: fixture-{index}\nStatus: install ok installed\n\n").as_bytes(),
            );
        }
        let packages =
            dpkg_status(&bytes, &budget).expect("index saturation must preserve positive packages");
        assert_eq!(packages.len(), 5000);
        assert!(packages.iter().any(|package| package == "ollama"));
        let mut snapshot = empty("endpoint", 1, 100);
        assert!(project(&mut snapshot, packages));
        validate_snapshot(&snapshot).unwrap();
    }
    #[test]
    fn package_windows_rotate_and_report_saturation_without_losing_old_sources() {
        let stop = AtomicBool::new(false);
        let budget = Budget::new(Duration::from_secs(3), &stop);
        let mut bytes = vec![];
        for index in 0..6001 {
            bytes.extend_from_slice(
                format!("Package: fixture-{index}\nStatus: install ok installed\n\n").as_bytes(),
            );
        }
        bytes.extend_from_slice(b"Package: ollama\nStatus: install ok installed\n\n");
        let first = dpkg_page(&bytes, &budget, 1).unwrap();
        assert!(first.saturated);
        assert_eq!(first.packages.len(), MAX_PACKAGES);
        assert!(!first.packages.iter().any(|value| value == "ollama"));
        let second = dpkg_page(&bytes, &budget, 2).unwrap();
        assert!(second.saturated);
        assert!(second.packages.iter().any(|value| value == "ollama"));
        let mut snapshot = empty("endpoint", 2, 100);
        project_dpkg(&mut snapshot, Ok(second));
        assert!(snapshot.facts.iter().any(|fact| {
            fact.fields[&Field::Package]
                .iter()
                .any(|value| value == "ollama")
        }));
        assert_eq!(snapshot.coverage[0].status, CoverageStatus::Saturated);
        assert!(!snapshot.coverage[0].complete);
        validate_snapshot(&snapshot).unwrap();
        let before = snapshot.facts.len();
        project_dpkg(&mut snapshot, Err("package_index_limit"));
        assert_eq!(snapshot.facts.len(), before);
        assert!(
            snapshot
                .coverage
                .iter()
                .all(|source| source.status == CoverageStatus::Saturated)
        );
    }
}
