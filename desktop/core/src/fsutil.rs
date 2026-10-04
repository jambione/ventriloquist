//! Small filesystem helpers: atomic writes and private (0600) files.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::Path;

/// Create `dir` (and parents). On unix, a directory this call creates is
/// made private (0700); existing directories are left alone.
pub(crate) fn create_private_dir_all(dir: &Path) -> io::Result<()> {
    if dir.is_dir() {
        return Ok(());
    }
    fs::create_dir_all(dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(dir, fs::Permissions::from_mode(0o700));
    }
    Ok(())
}

/// Atomically replace `path` with `bytes`: write a temporary file in the
/// same directory, fsync it, then rename it over `path`.
///
/// On unix the file is created with mode 0600. On Windows, `rename`
/// replaces the destination (MoveFileEx with REPLACE_EXISTING); the file
/// inherits the ACL of the per-user config directory (LocalAppData), which is
/// only accessible to the user.
pub(crate) fn atomic_write_private(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let dir = path
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "path has no parent"))?;
    create_private_dir_all(dir)?;
    let file_name = path
        .file_name()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "path has no file name"))?
        .to_string_lossy()
        .into_owned();
    let tmp = dir.join(format!(
        ".{file_name}.tmp-{}-{:016x}",
        std::process::id(),
        rand::random::<u64>()
    ));
    let result = (|| {
        let mut f = open_private_new(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
        drop(f);
        fs::rename(&tmp, path)?;
        #[cfg(unix)]
        {
            if let Ok(d) = File::open(dir) {
                let _ = d.sync_all();
            }
        }
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result
}

fn open_private_new(path: &Path) -> io::Result<File> {
    let mut opts = OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    opts.open(path)
}

/// On unix, force `path` to mode 0600 if it is anything else.
pub(crate) fn ensure_private_file(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let meta = fs::metadata(path)?;
        if meta.permissions().mode() & 0o777 != 0o600 {
            fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
        }
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn atomic_write_replaces_and_leaves_no_temp() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("sub").join("f.json");
        atomic_write_private(&p, b"one").unwrap();
        atomic_write_private(&p, b"two").unwrap();
        assert_eq!(fs::read(&p).unwrap(), b"two");
        let names: Vec<_> = fs::read_dir(p.parent().unwrap())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(names.len(), 1, "temp files left behind: {names:?}");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&p).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }
}
