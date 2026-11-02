//! Descriptor-relative storage for the system collector's trust anchor and ledger.
use crate::Result;
use std::{
    ffi::CString,
    fs::File,
    io::{Read, Write},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::{ffi::OsStrExt, fs::MetadataExt},
    },
    path::{Component, Path, PathBuf},
};

pub struct Directory(File, PathBuf);
impl Directory {
    pub fn create(path: &Path, mode: u32) -> Result<Self> {
        if !matches!(mode, 0o700 | 0o755) {
            return Err("invalid system discovery directory mode".into());
        }
        let parent = Self::open(path.parent().ok_or("missing system discovery parent")?)?;
        let name = path.file_name().and_then(|s| s.to_str()).ok_or("invalid system discovery directory")?;
        let leaf = Self::leaf(name)?;
        parent.current()?;
        if unsafe { libc::mkdirat(parent.0.as_raw_fd(), leaf.as_ptr(), mode) } != 0
            && std::io::Error::last_os_error().raw_os_error() != Some(libc::EEXIST) {
            return Err("system discovery directory cannot be created".into());
        }
        let result = Self::open(path)?;
        if result.0.metadata()?.mode() & 0o777 != mode {
            return Err("existing system discovery directory has unexpected permissions".into());
        }
        parent.current()?;
        Ok(result)
    }
    pub(crate) fn current(&self) -> Result<()> {
        self.protected()
    }
    fn protected(&self) -> Result<()> {
        let metadata = self.0.metadata()?;
        let current = std::fs::symlink_metadata(&self.1)?;
        if !metadata.is_dir() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
            return Err("system discovery directory is no longer protected".into());
        }
        if !current.is_dir() || current.dev() != metadata.dev() || current.ino() != metadata.ino() {
            return Err("system discovery directory was replaced".into());
        }
        Ok(())
    }
    pub fn open(path: &Path) -> Result<Self> {
        if !path.is_absolute() {
            return Err("system discovery directory must be absolute".into());
        }
        let raw = unsafe {
            libc::open(
                c"/".as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
            )
        };
        if raw < 0 {
            return Err("system discovery root unavailable".into());
        }
        let mut current = unsafe { File::from_raw_fd(raw) };
        for part in path.components() {
            let name = match part {
                Component::RootDir => continue,
                Component::Normal(name) => name,
                _ => return Err("invalid system discovery directory".into()),
            };
            let name = CString::new(name.as_bytes())?;
            let raw = unsafe {
                libc::openat(
                    current.as_raw_fd(),
                    name.as_ptr(),
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                )
            };
            if raw < 0 {
                return Err("system discovery directory unavailable".into());
            }
            let next = unsafe { File::from_raw_fd(raw) };
            let metadata = next.metadata()?;
            if !metadata.is_dir() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
                return Err("system discovery directory is not protected".into());
            }
            current = next;
        }
        Ok(Self(current, path.into()))
    }
    fn leaf(name: &str) -> Result<CString> {
        if name.is_empty()
            || name.len() > 80
            || matches!(name, "." | "..")
            || !name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
        {
            return Err("invalid system discovery filename".into());
        }
        Ok(CString::new(name)?)
    }
    pub fn read(&self, name: &str, limit: usize) -> Result<Vec<u8>> {
        self.protected()?;
        if limit == 0 || limit > 128 * 1024 {
            return Err("invalid system discovery read budget".into());
        }
        let name = Self::leaf(name)?;
        let raw = unsafe {
            libc::openat(
                self.0.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
            )
        };
        if raw < 0 {
            return Err("system discovery file unavailable".into());
        }
        let mut file = unsafe { File::from_raw_fd(raw) };
        let before = file.metadata()?;
        if !before.is_file()
            || before.uid() != 0
            || before.nlink() != 1
            || before.mode() & 0o077 != 0
            || before.len() > limit as u64
        {
            return Err("system discovery file is not protected".into());
        }
        let mut bytes = vec![];
        (&mut file).take(limit as u64 + 1).read_to_end(&mut bytes)?;
        let after = file.metadata()?;
        if bytes.len() > limit
            || bytes.len() as u64 != before.len()
            || after.len() != before.len()
            || after.mtime() != before.mtime()
            || after.mtime_nsec() != before.mtime_nsec()
            || after.nlink() != 1
        {
            return Err("system discovery file changed".into());
        }
        Ok(bytes)
    }
    pub fn read_optional(&self, name: &str, limit: usize) -> Result<Option<Vec<u8>>> {
        match self.read(name, limit) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(error) => {
                self.protected()?;
                let leaf = Self::leaf(name)?;
                let mut metadata = std::mem::MaybeUninit::<libc::stat>::uninit();
                let result = unsafe {
                    libc::fstatat(self.0.as_raw_fd(), leaf.as_ptr(), metadata.as_mut_ptr(), libc::AT_SYMLINK_NOFOLLOW)
                };
                if result < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::ENOENT) {
                    Ok(None)
                } else {
                    Err(error)
                }
            }
        }
    }
    pub fn write(&self, name: &str, bytes: &[u8]) -> Result<()> {
        self.protected()?;
        if bytes.len() > 128 * 1024 {
            return Err("system discovery ledger exceeds its budget".into());
        }
        let destination = Self::leaf(name)?;
        let temporary = Self::leaf(&format!("ledger-{}.tmp", uuid::Uuid::new_v4()))?;
        let raw = unsafe {
            libc::openat(
                self.0.as_raw_fd(),
                temporary.as_ptr(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o600,
            )
        };
        if raw < 0 {
            return Err("system discovery ledger cannot be created".into());
        }
        let mut file = unsafe { File::from_raw_fd(raw) };
        let result = (|| -> Result<()> {
            file.write_all(bytes)?;
            file.sync_all()?;
            if unsafe {
                libc::renameat(
                    self.0.as_raw_fd(),
                    temporary.as_ptr(),
                    self.0.as_raw_fd(),
                    destination.as_ptr(),
                )
            } != 0
            {
                return Err("system discovery ledger cannot be committed".into());
            }
            self.0.sync_all()?;
            Ok(())
        })();
        if result.is_err() {
            unsafe {
                libc::unlinkat(self.0.as_raw_fd(), temporary.as_ptr(), 0);
            }
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{PermissionsExt, symlink};
    #[test]
    #[ignore = "Required isolated root filesystem qualification"]
    fn protected_files_reject_symlinks_hardlinks_fifos_permissions_and_oversized_state() {
        assert_eq!(unsafe { libc::geteuid() }, 0, "isolated root is required");
        let home = tempfile::Builder::new()
            .prefix("milvago-discovery-fs-")
            .tempdir_in("/run")
            .unwrap();
        let directory = Directory::open(home.path()).unwrap();
        assert!(directory.read_optional("absent.json", 128).unwrap().is_none());
        directory.write("state.json", b"first").unwrap();
        directory.write("state.json", b"second").unwrap();
        assert_eq!(directory.read("state.json", 128).unwrap(), b"second");
        for name in ["../outside", "/absolute", ".", "..", "image/data.png"] {
            assert!(directory.write(name, b"x").is_err());
            assert!(directory.read(name, 128).is_err());
        }
        symlink(
            home.path().join("state.json"),
            home.path().join("link.json"),
        )
        .unwrap();
        assert!(directory.read("link.json", 128).is_err());
        assert!(directory.read_optional("link.json", 128).is_err());
        std::fs::hard_link(
            home.path().join("state.json"),
            home.path().join("hard.json"),
        )
        .unwrap();
        assert!(directory.read("state.json", 128).is_err());
        assert!(directory.read_optional("state.json", 128).is_err());
        std::fs::remove_file(home.path().join("hard.json")).unwrap();
        std::fs::set_permissions(
            home.path().join("state.json"),
            std::fs::Permissions::from_mode(0o644),
        )
        .unwrap();
        assert!(directory.read("state.json", 128).is_err());
        directory.write("state.json", b"private").unwrap();
        assert!(directory.read("state.json", 2).is_err());
        assert!(
            directory
                .write("state.json", &vec![0; 128 * 1024 + 1])
                .is_err()
        );
        let fifo = CString::new(home.path().join("fifo").as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
        assert!(directory.read("fifo", 128).is_err());
        assert!(directory.read_optional("fifo", 128).is_err());
        let link = home.path().join("directory-link");
        symlink(home.path(), &link).unwrap();
        assert!(Directory::open(&link).is_err());
        std::fs::set_permissions(home.path(), std::fs::Permissions::from_mode(0o777)).unwrap();
        assert!(Directory::open(home.path()).is_err());
        assert!(directory.read("state.json", 128).is_err());
        assert!(directory.write("state.json", b"unsafe").is_err());
        let parent = tempfile::Builder::new()
            .prefix("milvago-discovery-replace-")
            .tempdir_in("/run")
            .unwrap();
        let path = parent.path().join("active");
        std::fs::create_dir(&path).unwrap();
        let pinned = Directory::open(&path).unwrap();
        pinned.write("state.json", b"old").unwrap();
        std::fs::rename(&path, parent.path().join("retired")).unwrap();
        std::fs::create_dir(&path).unwrap();
        assert!(pinned.read("state.json", 128).is_err());
        assert!(pinned.write("state.json", b"new").is_err());
    }
}
