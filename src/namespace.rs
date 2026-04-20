use anyhow::{Context, Result};
use log::{debug, info};
use nix::mount::{mount, MsFlags};
use nix::sched::{unshare, CloneFlags};
use nix::unistd::{getgid, getuid};
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use crate::home_files::HomeFileDirective;

/// RAII wrapper for a raw file descriptor — closes on drop.
struct OwnedFd(i32);

impl OwnedFd {
    fn raw(&self) -> i32 {
        self.0
    }
}

impl Drop for OwnedFd {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.0);
        }
    }
}

/// Where a passthrough path resides relative to ephemeral mounts.
enum MountLocation {
    UnderHome,
    UnderTmp,
    /// Descendant of another passthrough entry (not $HOME or /tmp).
    UnderEntry,
}

/// Whether a passthrough path is a file or directory.
enum EntryKind {
    File,
    Directory,
}

/// A saved fd to a path that needs to be bind-mounted through ephemeral layers.
struct SavedFd {
    fd: OwnedFd,
    path: PathBuf,
    kind: EntryKind,
    location: MountLocation,
    readonly: bool,
}

/// Set up user + mount namespace with ephemeral /tmp (tmpfs) and an empty read-only $HOME.
///
/// The `home_files` directives selectively populate $HOME:
/// - `Copy` entries are copied into $HOME (read-only).
/// - `Pass` entries are bind-mounted writably (like workdir/passthrough).
///
/// Writes to `workdir` and `passthrough` paths are preserved via writable bind mounts
/// that punch through the read-only $HOME.
pub fn setup_namespace(
    home_dir: &Path,
    workdir: &Path,
    passthrough: &[PathBuf],
    home_files: &[HomeFileDirective],
    net_isolate: bool,
) -> Result<()> {
    // Collect all paths that need bind-mount passthrough, with a readonly flag.
    // (workdir + CLI extras are writable; Pass directives are writable; Read directives are readonly)
    let mut all_entries: Vec<(&Path, bool)> = vec![(workdir, false)];
    for p in passthrough {
        all_entries.push((p.as_path(), false));
    }
    for d in home_files {
        match d {
            HomeFileDirective::Pass(ref p) => all_entries.push((p.as_path(), false)),
            HomeFileDirective::Read(ref p) => all_entries.push((p.as_path(), true)),
            _ => {}
        }
    }

    // Determine if any passthrough path IS /tmp or $HOME (skip those ephemeral mounts)
    let skip_tmp = all_entries.iter().any(|(p, _)| *p == Path::new("/tmp"));
    let skip_home = all_entries.iter().any(|(p, _)| *p == home_dir);

    debug!("mount: skip ephemeral /tmp: {}", skip_tmp);
    debug!("mount: skip ephemeral $HOME: {}", skip_home);
    for (path, readonly) in &all_entries {
        debug!(
            "mount: entry {} ({})",
            path.display(),
            if *readonly { "read-only" } else { "read-write" }
        );
    }

    enter_namespace(net_isolate)?;

    // Save fds AFTER entering the namespace but BEFORE ephemeral mounts cover the paths.
    let saved_fds = save_passthrough_fds(&all_entries, home_dir)?;
    debug!("mount: saved {} fd(s) for passthrough bind mounts", saved_fds.len());

    if !skip_tmp {
        info!("mount: tmpfs => /tmp");
        mount(
            Some("tmpfs"),
            "/tmp",
            Some("tmpfs"),
            MsFlags::empty(),
            None::<&str>,
        )
        .context("failed to mount tmpfs on /tmp")?;
    }

    if !skip_home {
        info!("mount: setting up read-only $HOME at {}", home_dir.display());
        setup_readonly_home(home_dir, home_files, &saved_fds)?;
    }

    bind_mount_passthroughs(&saved_fds)?;

    Ok(())
}

/// Enter a new user + mount namespace and configure uid/gid maps.
/// When `net_isolate` is true, also creates a new network namespace.
fn enter_namespace(net_isolate: bool) -> Result<()> {
    let real_uid = getuid();
    let real_gid = getgid();

    let mut flags = CloneFlags::CLONE_NEWUSER | CloneFlags::CLONE_NEWNS;
    if net_isolate {
        flags |= CloneFlags::CLONE_NEWNET;
        info!(
            "namespace: unsharing user+mount+net (uid={}, gid={})",
            real_uid, real_gid
        );
    } else {
        info!(
            "namespace: unsharing user+mount (uid={}, gid={})",
            real_uid, real_gid
        );
    }
    unshare(flags).context("failed to unshare namespace")?;

    // Write uid/gid maps: map real uid/gid to themselves inside the namespace.
    // CAP_SYS_ADMIN is granted by unshare(CLONE_NEWUSER) regardless of mapping.
    // In nested user namespaces, setgroups may already be "deny" (EACCES on write).
    // uid_map/gid_map may already be written (EEXIST). Both are harmless to skip.
    debug!("namespace: writing uid/gid maps ({0} -> {0})", real_uid.as_raw());
    write_proc_or_skip("/proc/self/setgroups", "deny", "setgroups")?;
    write_proc_or_skip(
        "/proc/self/uid_map",
        &format!("{0} {0} 1\n", real_uid.as_raw()),
        "uid_map",
    )?;
    write_proc_or_skip(
        "/proc/self/gid_map",
        &format!("{0} {0} 1\n", real_gid.as_raw()),
        "gid_map",
    )?;

    // Make all mounts private (prevent propagation to host)
    info!("namespace: setting mount propagation to private (MS_REC|MS_PRIVATE)");
    mount(
        None::<&str>,
        "/",
        None::<&str>,
        MsFlags::MS_REC | MsFlags::MS_PRIVATE,
        None::<&str>,
    )
    .context("failed to set mounts private")?;

    // Remount /sys so it reflects the new network namespace.
    // Without this, /sys/class/net/ still shows host interfaces.
    if net_isolate {
        info!("namespace: remounting /sys for network namespace");
        mount(
            Some("sysfs"),
            "/sys",
            Some("sysfs"),
            MsFlags::empty(),
            None::<&str>,
        )
        .context("failed to remount /sys for network namespace")?;
    }

    Ok(())
}

/// Open fds to passthrough paths that live under $HOME or /tmp, so they survive
/// ephemeral mounts. Must be called AFTER `enter_namespace` (kernel restriction:
/// fds must be opened in the same user namespace where bind mounts happen).
///
/// Each entry is `(path, readonly)` — readonly paths are bind-mounted then
/// remounted read-only in `bind_mount_passthroughs`.
fn save_passthrough_fds(entries: &[(&Path, bool)], home_dir: &Path) -> Result<Vec<SavedFd>> {
    let mut saved_fds = Vec::new();
    for &(path, readonly) in entries {
        let under_home = path.starts_with(home_dir) && path != home_dir;
        // If a path is under both $HOME and /tmp (e.g. HOME=/tmp/foo), prefer
        // the home classification — the $HOME overlay handles those stubs.
        let under_tmp =
            !under_home && path.starts_with("/tmp") && path != Path::new("/tmp");
        // Check if this path is a descendant of another entry in the list.
        let under_entry = !under_home
            && !under_tmp
            && entries
                .iter()
                .any(|&(other, _)| other != path && path.starts_with(other));
        let location = if under_home {
            MountLocation::UnderHome
        } else if under_tmp {
            MountLocation::UnderTmp
        } else if under_entry {
            MountLocation::UnderEntry
        } else {
            debug!("mount: skipping fd save for {} (not under $HOME or /tmp)", path.display());
            continue;
        };
        let kind = if path.is_file() {
            EntryKind::File
        } else {
            EntryKind::Directory
        };
        let loc_label = match location {
            MountLocation::UnderHome => "under $HOME",
            MountLocation::UnderTmp => "under /tmp",
            MountLocation::UnderEntry => "under another entry",
        };
        let kind_label = match kind {
            EntryKind::File => "file",
            EntryKind::Directory => "dir",
        };
        let fd = open_path_fd(path)
            .with_context(|| format!("failed to save fd for {}", path.display()))?;
        debug!(
            "mount: saved fd {} for {} ({}, {}, {})",
            fd.raw(),
            path.display(),
            loc_label,
            kind_label,
            if readonly { "ro" } else { "rw" }
        );
        saved_fds.push(SavedFd {
            fd,
            path: path.to_path_buf(),
            kind,
            location,
            readonly,
        });
    }
    // Sort so that ancestors are mounted before descendants — shorter paths first.
    saved_fds.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(saved_fds)
}

/// Set up $HOME as an empty read-only directory, selectively populated via staging.
/// Copy directives are copied in (read-only). Mount stubs are created for
/// passthrough paths that will be bind-mounted later.
fn setup_readonly_home(
    home_dir: &Path,
    home_files: &[HomeFileDirective],
    saved_fds: &[SavedFd],
) -> Result<()> {
    let staging_dir = PathBuf::from(format!(
        "/tmp/.hermit-{}/home-staging",
        std::process::id()
    ));
    debug!("mount: home staging dir: {}", staging_dir.display());
    fs::create_dir_all(&staging_dir)
        .context("failed to create home staging dir")?;

    // Copy phase: populate staging with copy directive contents
    for d in home_files {
        if let HomeFileDirective::Copy(ref src) = d {
            let rel = src.strip_prefix(home_dir).with_context(|| {
                format!(
                    "copy path {} is not under home dir {}",
                    src.display(),
                    home_dir.display()
                )
            })?;
            let dest = staging_dir.join(rel);
            if let Some(parent) = dest.parent() {
                fs::create_dir_all(parent).with_context(|| {
                    format!("failed to create parent dirs for {}", dest.display())
                })?;
            }
            debug!("mount: copying {} => {}", src.display(), dest.display());
            copy_entry(src, &dest).with_context(|| {
                format!("failed to copy {} to staging", src.display())
            })?;
        }
    }

    // Stub phase: create mount-point stubs for all paths that will be
    // bind-mounted under $HOME (workdir, passthroughs, pass directives).
    for saved in saved_fds {
        if let MountLocation::UnderHome = saved.location {
            let rel = saved.path.strip_prefix(home_dir).with_context(|| {
                format!(
                    "passthrough {} is not under home dir {}",
                    saved.path.display(),
                    home_dir.display()
                )
            })?;
            let stub = staging_dir.join(rel);
            debug!("mount: creating stub for {} at {}", saved.path.display(), stub.display());
            create_mount_stub(&stub, &saved.kind).with_context(|| {
                format!("failed to create mount stub for {}", stub.display())
            })?;
        }
    }

    // Bind mount staging onto $HOME
    info!("mount: bind {} => {} (MS_BIND)", staging_dir.display(), home_dir.display());
    mount(
        Some(staging_dir.as_path()),
        home_dir,
        None::<&str>,
        MsFlags::MS_BIND,
        None::<&str>,
    )
    .context("failed to bind mount staging onto $HOME")?;

    // Remount $HOME read-only. In a user namespace, "locked" flags
    // (nosuid, nodev, etc.) inherited from the bind-mount source cannot
    // be cleared. Read the current flags and preserve them.
    let locked_flags = get_locked_mount_flags(home_dir)
        .context("failed to read mount flags for $HOME")?;
    let remount_flags = MsFlags::MS_BIND | MsFlags::MS_REMOUNT | MsFlags::MS_RDONLY | locked_flags;
    info!(
        "mount: remount {} read-only (flags: {:?})",
        home_dir.display(),
        remount_flags
    );
    mount(
        None::<&str>,
        home_dir,
        None::<&str>,
        remount_flags,
        None::<&str>,
    )
    .context("failed to remount $HOME read-only")?;

    Ok(())
}

/// Bind mount all saved passthrough paths through ephemeral layers.
/// For /tmp paths, mount stubs are recreated under the fresh tmpfs first.
/// For $HOME paths, stubs were already created in the staging directory.
/// Read-only entries are remounted with MS_RDONLY after the initial bind.
fn bind_mount_passthroughs(saved_fds: &[SavedFd]) -> Result<()> {
    if saved_fds.is_empty() {
        debug!("mount: no passthrough bind mounts needed");
        return Ok(());
    }
    info!("mount: binding {} passthrough path(s)", saved_fds.len());
    for saved in saved_fds {
        match saved.location {
            MountLocation::UnderTmp | MountLocation::UnderEntry => {
                debug!("mount: recreating stub for {}", saved.path.display());
                create_mount_stub(&saved.path, &saved.kind).with_context(|| {
                    format!("failed to recreate mount point {}", saved.path.display())
                })?;
            }
            _ => {}
        }

        let fd_path = format!("/proc/self/fd/{}", saved.fd.raw());
        info!("mount: bind {} => {} (MS_BIND)", fd_path, saved.path.display());
        mount(
            Some(fd_path.as_str()),
            saved.path.as_path(),
            None::<&str>,
            MsFlags::MS_BIND,
            None::<&str>,
        )
        .with_context(|| format!("failed to bind mount {}", saved.path.display()))?;

        if saved.readonly {
            let locked_flags = get_locked_mount_flags(&saved.path).with_context(|| {
                format!("failed to read mount flags for {}", saved.path.display())
            })?;
            let remount_flags =
                MsFlags::MS_BIND | MsFlags::MS_REMOUNT | MsFlags::MS_RDONLY | locked_flags;
            info!(
                "mount: remount {} read-only (flags: {:?})",
                saved.path.display(),
                remount_flags
            );
            mount(
                None::<&str>,
                saved.path.as_path(),
                None::<&str>,
                remount_flags,
                None::<&str>,
            )
            .with_context(|| {
                format!("failed to remount {} read-only", saved.path.display())
            })?;
        }
        // fd is closed automatically when saved_fds is dropped
    }
    Ok(())
}

/// Write a proc file, silently skipping PermissionDenied (harmless in nested namespaces).
fn write_proc_or_skip(path: &str, content: &str, label: &str) -> Result<()> {
    if let Err(e) = fs::write(path, content) {
        if e.kind() != std::io::ErrorKind::PermissionDenied {
            return Err(e).with_context(|| format!("failed to write {}", label));
        }
    }
    Ok(())
}

/// Copy a file, directory (recursively), or symlink from `src` to `dest`.
fn copy_entry(src: &Path, dest: &Path) -> Result<()> {
    let meta = fs::symlink_metadata(src).with_context(|| {
        format!("failed to stat {}", src.display())
    })?;
    if meta.is_dir() {
        copy_dir_recursive(src, dest)
    } else if meta.is_symlink() {
        let target = fs::read_link(src).with_context(|| {
            format!("failed to read symlink {}", src.display())
        })?;
        std::os::unix::fs::symlink(&target, dest).with_context(|| {
            format!("failed to create symlink at {}", dest.display())
        })
    } else {
        fs::copy(src, dest).with_context(|| {
            format!("failed to copy {} to {}", src.display(), dest.display())
        })?;
        Ok(())
    }
}

/// Recursively copy a directory tree from `src` to `dest`.
fn copy_dir_recursive(src: &Path, dest: &Path) -> Result<()> {
    fs::create_dir_all(dest).with_context(|| {
        format!("failed to create dir {}", dest.display())
    })?;
    for entry in fs::read_dir(src).with_context(|| {
        format!("failed to read dir {}", src.display())
    })? {
        let entry = entry?;
        let child_dest = dest.join(entry.file_name());
        copy_entry(&entry.path(), &child_dest)?;
    }
    Ok(())
}

/// Create an empty mount-point stub (file or dir) at `path`, including parent dirs.
fn create_mount_stub(path: &Path, kind: &EntryKind) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_context(|| {
            format!("failed to create parent dirs for stub {}", path.display())
        })?;
    }
    match kind {
        EntryKind::File => {
            fs::write(path, b"").with_context(|| {
                format!("failed to create file stub {}", path.display())
            })?;
        }
        EntryKind::Directory => {
            fs::create_dir_all(path).with_context(|| {
                format!("failed to create dir stub {}", path.display())
            })?;
        }
    }
    Ok(())
}

/// Read mount flags that the kernel considers "locked" in a user namespace.
/// Uses statvfs — the ST_* flag bits match the MS_* mount flag bits on Linux.
/// We mask to the flags the kernel locks: nosuid, nodev, noexec, noatime,
/// nodiratime, relatime.
fn get_locked_mount_flags(path: &Path) -> Result<MsFlags> {
    let cpath = std::ffi::CString::new(path.as_os_str().as_bytes())
        .context("path contains null byte")?;
    let mut stat: libc::statvfs = unsafe { std::mem::zeroed() };
    let ret = unsafe { libc::statvfs(cpath.as_ptr(), &mut stat) };
    if ret != 0 {
        return Err(anyhow::anyhow!(
            "statvfs({}) failed: {}",
            path.display(),
            std::io::Error::last_os_error()
        ));
    }
    let locked_mask = MsFlags::MS_NOSUID
        | MsFlags::MS_NODEV
        | MsFlags::MS_NOEXEC
        | MsFlags::MS_NOATIME
        | MsFlags::MS_NODIRATIME
        | MsFlags::MS_RELATIME;
    Ok(MsFlags::from_bits_truncate(stat.f_flag as u64) & locked_mask)
}

/// Open an fd to a path (file or directory) that survives mount changes.
/// Uses O_PATH so it works for both files and directories. The fd keeps a
/// reference to the real inode, allowing bind mounts via /proc/self/fd/<n>
/// after ephemeral mounts cover the original path.
fn open_path_fd(path: &Path) -> Result<OwnedFd> {
    let cpath = std::ffi::CString::new(path.as_os_str().as_bytes())
        .context("path contains null byte")?;
    let fd = unsafe { libc::open(cpath.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) };
    if fd < 0 {
        Err(anyhow::anyhow!(
            "open({}, O_PATH) failed: {}",
            path.display(),
            std::io::Error::last_os_error()
        ))
    } else {
        Ok(OwnedFd(fd))
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_open_path_fd_directory() {
        let fd = open_path_fd(Path::new("/tmp")).unwrap();
        assert!(fd.raw() >= 0);
        // fd closed automatically on drop
    }

    #[test]
    fn test_open_path_fd_file() {
        // /etc/hostname should exist on most Linux systems
        let fd = open_path_fd(Path::new("/etc/hostname")).unwrap();
        assert!(fd.raw() >= 0);
        // fd closed automatically on drop
    }

    #[test]
    fn test_open_path_fd_invalid_path() {
        let result = open_path_fd(Path::new("/nonexistent_path_for_hermit_test"));
        assert!(result.is_err());
    }

    #[test]
    fn test_workdir_relationship_detection() {
        let home = Path::new("/home/user");
        let under_home = Path::new("/home/user/project");
        let is_home = Path::new("/home/user");
        let unrelated = Path::new("/opt/build");

        assert!(under_home.starts_with(home) && under_home != home);
        assert!(!(is_home.starts_with(home) && is_home != home));
        assert!(!unrelated.starts_with(home));
    }

    #[test]
    fn test_copy_entry_file() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("source.txt");
        let dest = dir.path().join("dest.txt");
        fs::write(&src, "hello").unwrap();
        copy_entry(&src, &dest).unwrap();
        assert_eq!(fs::read_to_string(&dest).unwrap(), "hello");
    }

    #[test]
    fn test_copy_entry_symlink() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("target.txt");
        let link = dir.path().join("link.txt");
        let dest = dir.path().join("dest_link.txt");
        fs::write(&target, "data").unwrap();
        std::os::unix::fs::symlink(&target, &link).unwrap();
        copy_entry(&link, &dest).unwrap();
        // dest should be a symlink pointing to the same target
        assert!(fs::symlink_metadata(&dest).unwrap().is_symlink());
        assert_eq!(fs::read_link(&dest).unwrap(), target);
    }

    #[test]
    fn test_copy_dir_recursive() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("srcdir");
        let dest = dir.path().join("destdir");
        fs::create_dir_all(src.join("sub")).unwrap();
        fs::write(src.join("a.txt"), "aaa").unwrap();
        fs::write(src.join("sub/b.txt"), "bbb").unwrap();

        copy_dir_recursive(&src, &dest).unwrap();
        assert_eq!(fs::read_to_string(dest.join("a.txt")).unwrap(), "aaa");
        assert_eq!(fs::read_to_string(dest.join("sub/b.txt")).unwrap(), "bbb");
    }

    #[test]
    fn test_create_mount_stub_file() {
        let dir = tempfile::tempdir().unwrap();
        let stub = dir.path().join("deep/nested/stub.txt");
        create_mount_stub(&stub, &EntryKind::File).unwrap();
        assert!(stub.is_file());
        assert_eq!(fs::read_to_string(&stub).unwrap(), "");
    }

    #[test]
    fn test_create_mount_stub_dir() {
        let dir = tempfile::tempdir().unwrap();
        let stub = dir.path().join("deep/nested/subdir");
        create_mount_stub(&stub, &EntryKind::Directory).unwrap();
        assert!(stub.is_dir());
    }

    #[test]
    fn test_save_fds_descendant_of_another_entry() {
        // When a path is a descendant of another entry (and not under $HOME or /tmp),
        // it should still get an fd saved with UnderEntry location.
        let dir = tempfile::tempdir_in("/var/tmp").unwrap();
        let parent = dir.path().to_path_buf();
        let child = parent.join("child");
        fs::create_dir_all(&child).unwrap();

        let home = Path::new("/nonexistent_home_for_hermit_test");
        let entries: Vec<(&Path, bool)> = vec![(parent.as_path(), false), (child.as_path(), false)];
        let saved = save_passthrough_fds(&entries, home).unwrap();

        // parent is not under $HOME, /tmp, or another entry — skipped.
        // child is a descendant of parent — saved as UnderEntry.
        assert_eq!(saved.len(), 1);
        assert_eq!(saved[0].path, child);
        assert!(matches!(saved[0].location, MountLocation::UnderEntry));
    }

    #[test]
    fn test_save_fds_sorted_ancestors_before_descendants() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("home");
        let project = home.join("project");
        let subdir = home.join("project/sub");
        fs::create_dir_all(&subdir).unwrap();

        // Pass in reverse order — subdir before project
        let entries: Vec<(&Path, bool)> = vec![(&subdir, false), (&project, false)];
        let saved = save_passthrough_fds(&entries, &home).unwrap();

        // Both should be saved (under $HOME), and sorted with project before subdir
        assert_eq!(saved.len(), 2);
        assert_eq!(saved[0].path, project);
        assert_eq!(saved[1].path, subdir);
    }
}
