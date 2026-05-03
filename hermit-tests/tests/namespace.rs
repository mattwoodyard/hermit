//! Tests for `hermit::namespace`.
//!
//! Reaches into private items via `hermit::namespace::__test_internals`
//! (only available because hermit-tests turns on the
//! `__test_internals` feature).

use hermit::namespace::__test_internals::{
    copy_dir_recursive, copy_entry, create_mount_stub, open_path_fd, save_passthrough_fds,
};
use hermit::namespace::{EntryKind, MountLocation};
use std::fs;
use std::path::Path;

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
fn test_copy_entry_dereferences_symlink() {
    // Symlinks at `src` get dereferenced: the destination is a
    // regular file holding the target's bytes, not another
    // symlink. The host's symlink target may not exist inside
    // the sandbox, so preserving the link would produce a
    // dangling reference at the destination.
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("target.txt");
    let link = dir.path().join("link.txt");
    let dest = dir.path().join("dest_link.txt");
    fs::write(&target, "data").unwrap();
    std::os::unix::fs::symlink(&target, &link).unwrap();

    copy_entry(&link, &dest).unwrap();

    let meta = fs::symlink_metadata(&dest).unwrap();
    assert!(!meta.is_symlink(), "destination must not preserve the symlink");
    assert!(meta.is_file());
    assert_eq!(fs::read_to_string(&dest).unwrap(), "data");
}

#[test]
fn test_copy_entry_dangling_symlink_errors() {
    // A symlink whose target was already deleted must not
    // silently produce an empty file at the destination — the
    // user gets a clear error so they can fix their `copy`
    // directive instead of debugging mysterious empty files
    // inside the sandbox.
    let dir = tempfile::tempdir().unwrap();
    let dangling = dir.path().join("dangling.txt");
    let dest = dir.path().join("dest.txt");
    std::os::unix::fs::symlink(dir.path().join("nope"), &dangling).unwrap();

    let err = copy_entry(&dangling, &dest).unwrap_err();
    assert!(
        err.to_string().contains("failed to stat")
            || err.to_string().contains("symlink target may not exist"),
        "expected stat-failure context, got: {err:#}"
    );
    assert!(!dest.exists());
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
    let entries: Vec<(&Path, &Path, bool)> = vec![
        (parent.as_path(), parent.as_path(), false),
        (child.as_path(), child.as_path(), false),
    ];
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
    let entries: Vec<(&Path, &Path, bool)> = vec![
        (&subdir, &subdir, false),
        (&project, &project, false),
    ];
    let saved = save_passthrough_fds(&entries, &home).unwrap();

    // Both should be saved (under $HOME), and sorted with project before subdir
    assert_eq!(saved.len(), 2);
    assert_eq!(saved[0].path, project);
    assert_eq!(saved[1].path, subdir);
}
