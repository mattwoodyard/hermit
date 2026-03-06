use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;

fn hermit_bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_hermit"))
}

// --- Basic passthrough tests ---

#[test]
fn test_passthrough_exit_zero() {
    let status = hermit_bin()
        .args(["--", "true"])
        .status()
        .expect("failed to run hermit");
    assert!(status.success());
}

#[test]
fn test_passthrough_exit_nonzero() {
    let status = hermit_bin()
        .args(["--", "false"])
        .status()
        .expect("failed to run hermit");
    assert!(!status.success());
    assert_eq!(status.code(), Some(1));
}

#[test]
fn test_passthrough_with_args() {
    let output = hermit_bin()
        .args(["--", "echo", "hello"])
        .output()
        .expect("failed to run hermit");
    assert!(
        output.status.success(),
        "hermit failed: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&output.stdout).trim(), "hello");
}

#[test]
fn test_missing_command() {
    let status = hermit_bin().status();
    match status {
        Ok(s) => assert!(!s.success()),
        Err(_) => {}
    }
}

// --- Landlock tests ---

#[test]
fn test_landlock_allows_reads_everywhere() {
    let output = hermit_bin()
        .args(["--project-dir", "/tmp", "--", "cat", "/etc/hostname"])
        .output()
        .expect("failed to run hermit");
    assert!(output.status.success());
}

#[test]
fn test_landlock_blocks_writes_outside_allowed() {
    let output = hermit_bin()
        .args([
            "--project-dir",
            "/tmp",
            "--",
            "sh",
            "-c",
            "echo blocked > /var/tmp/hermit_landlock_test 2>&1",
        ])
        .output()
        .expect("failed to run hermit");
    assert!(!output.status.success());
}

#[test]
fn test_landlock_allows_writes_to_tmp() {
    // Use --project-dir /tmp so /tmp stays real (not ephemeral tmpfs)
    let output = hermit_bin()
        .args([
            "--project-dir",
            "/tmp",
            "--",
            "sh",
            "-c",
            "echo ok > /tmp/hermit_ll_test && cat /tmp/hermit_ll_test",
        ])
        .output()
        .expect("failed to run hermit");
    assert!(output.status.success());
    assert_eq!(String::from_utf8_lossy(&output.stdout).trim(), "ok");
    let _ = std::fs::remove_file("/tmp/hermit_ll_test");
}

// --- Namespace isolation tests ---

#[test]
fn test_tmp_writes_dont_persist() {
    // Use a workdir under $HOME so that /tmp gets a fresh tmpfs
    let home = std::env::var("HOME").expect("HOME not set");
    let workdir = PathBuf::from(&home).join(".hermit_tmp_test_workdir");
    std::fs::create_dir_all(&workdir).expect("failed to create workdir");
    let workdir_str = workdir.to_str().unwrap();

    let marker = "/tmp/hermit_ns_persist_test";
    let _ = std::fs::remove_file(marker);

    let output = hermit_bin()
        .args([
            "--project-dir",
            workdir_str,
            "--",
            "sh",
            "-c",
            &format!("echo ephemeral > {}", marker),
        ])
        .output()
        .expect("failed to run hermit");
    assert!(
        output.status.success(),
        "hermit failed: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );

    // The file was written to tmpfs inside the namespace — it should NOT persist
    assert!(
        !std::path::Path::new(marker).exists(),
        "/tmp write persisted outside namespace"
    );

    let _ = std::fs::remove_dir_all(&workdir);
}

#[test]
fn test_home_writes_dont_persist() {
    // $HOME is now empty and read-only, so writes fail inside the sandbox.
    // Use 2>/dev/null to suppress the error and `|| true` to exit 0.
    let home = std::env::var("HOME").expect("HOME not set");
    let marker = format!("{}/.hermit_ns_persist_test", home);
    let _ = std::fs::remove_file(&marker);

    let output = hermit_bin()
        .args([
            "--project-dir",
            "/tmp",
            "--",
            "sh",
            "-c",
            &format!("echo ephemeral > {} 2>/dev/null || true", marker),
        ])
        .output()
        .expect("failed to run hermit");
    assert!(
        output.status.success(),
        "hermit failed: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );

    // The file should NOT exist outside the namespace
    assert!(
        !std::path::Path::new(&marker).exists(),
        "$HOME write persisted outside namespace"
    );
}

#[test]
fn test_workdir_writes_persist() {
    let dir = tempfile::tempdir().expect("failed to create temp dir");
    let dir_path = dir.path().to_str().unwrap();
    let test_file = format!("{}/hermit_persist_test", dir_path);

    let output = hermit_bin()
        .args([
            "--project-dir",
            dir_path,
            "--",
            "sh",
            "-c",
            &format!("echo persisted > {}", test_file),
        ])
        .output()
        .expect("failed to run hermit");
    assert!(
        output.status.success(),
        "hermit failed: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Workdir writes go through the bind mount to the real filesystem
    let content =
        std::fs::read_to_string(&test_file).expect("workdir write did not persist");
    assert_eq!(content.trim(), "persisted");
}

#[test]
fn test_workdir_under_home_writes_persist() {
    let home = std::env::var("HOME").expect("HOME not set");
    let workdir = PathBuf::from(&home).join(".hermit_test_workdir");
    std::fs::create_dir_all(&workdir).expect("failed to create test workdir under $HOME");

    let workdir_str = workdir.to_str().unwrap();
    let test_file = format!("{}/persist_test", workdir_str);

    let output = hermit_bin()
        .args([
            "--project-dir",
            workdir_str,
            "--",
            "sh",
            "-c",
            &format!("echo persisted > {}", test_file),
        ])
        .output()
        .expect("failed to run hermit");
    assert!(
        output.status.success(),
        "hermit failed: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Workdir under $HOME should punch through the RO mount via bind mount
    let content = std::fs::read_to_string(&test_file)
        .expect("workdir-under-$HOME write did not persist");
    assert_eq!(content.trim(), "persisted");

    let _ = std::fs::remove_dir_all(&workdir);
}

// --- Device node tests ---

#[test]
fn test_dev_null_writable() {
    let output = hermit_bin()
        .args([
            "--project-dir",
            "/tmp",
            "--",
            "sh",
            "-c",
            "echo discard > /dev/null && echo ok",
        ])
        .output()
        .expect("failed to run hermit");
    assert!(
        output.status.success(),
        "write to /dev/null failed: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&output.stdout).trim(), "ok");
}

// --- Namespace uid tests ---

#[test]
fn test_uid_is_not_root() {
    let output = hermit_bin()
        .args(["--project-dir", "/tmp", "--", "id", "-u"])
        .output()
        .expect("failed to run hermit");
    assert!(output.status.success());
    let uid: u32 = String::from_utf8_lossy(&output.stdout)
        .trim()
        .parse()
        .expect("id -u did not return a number");
    assert_ne!(uid, 0, "process should not be uid 0 (root) inside namespace");
}

// --- Passthrough tests ---

#[test]
fn test_passthrough_dir_under_home_writes_persist() {
    let home = std::env::var("HOME").expect("HOME not set");
    let workdir = PathBuf::from(&home).join(".hermit_pt_workdir");
    let pt_dir = PathBuf::from(&home).join(".hermit_pt_extra");
    std::fs::create_dir_all(&workdir).expect("failed to create workdir");
    std::fs::create_dir_all(&pt_dir).expect("failed to create passthrough dir");

    let test_file = format!("{}/pt_test", pt_dir.to_str().unwrap());

    let output = hermit_bin()
        .args([
            "--project-dir",
            workdir.to_str().unwrap(),
            "--passthrough",
            pt_dir.to_str().unwrap(),
            "--",
            "sh",
            "-c",
            &format!("echo persisted > {}", test_file),
        ])
        .output()
        .expect("failed to run hermit");
    assert!(
        output.status.success(),
        "hermit failed: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );

    let content =
        std::fs::read_to_string(&test_file).expect("passthrough dir write did not persist");
    assert_eq!(content.trim(), "persisted");

    let _ = std::fs::remove_dir_all(&workdir);
    let _ = std::fs::remove_dir_all(&pt_dir);
}

#[test]
fn test_passthrough_file_under_home_writes_persist() {
    let home = std::env::var("HOME").expect("HOME not set");
    let workdir = PathBuf::from(&home).join(".hermit_pt_file_workdir");
    let pt_file = PathBuf::from(&home).join(".hermit_pt_testfile");
    std::fs::create_dir_all(&workdir).expect("failed to create workdir");
    // Create the file before the sandbox so it exists for the fd to grab
    std::fs::write(&pt_file, "original\n").expect("failed to create passthrough file");

    let output = hermit_bin()
        .args([
            "--project-dir",
            workdir.to_str().unwrap(),
            "--passthrough",
            pt_file.to_str().unwrap(),
            "--",
            "sh",
            "-c",
            &format!("echo updated > {}", pt_file.to_str().unwrap()),
        ])
        .output()
        .expect("failed to run hermit");
    assert!(
        output.status.success(),
        "hermit failed: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );

    let content =
        std::fs::read_to_string(&pt_file).expect("passthrough file write did not persist");
    assert_eq!(content.trim(), "updated");

    let _ = std::fs::remove_dir_all(&workdir);
    let _ = std::fs::remove_file(&pt_file);
}

#[test]
fn test_passthrough_multiple() {
    let home = std::env::var("HOME").expect("HOME not set");
    let workdir = PathBuf::from(&home).join(".hermit_pt_multi_workdir");
    let pt_a = PathBuf::from(&home).join(".hermit_pt_multi_a");
    let pt_b = PathBuf::from(&home).join(".hermit_pt_multi_b");
    std::fs::create_dir_all(&workdir).expect("failed to create workdir");
    std::fs::create_dir_all(&pt_a).expect("failed to create passthrough dir a");
    std::fs::create_dir_all(&pt_b).expect("failed to create passthrough dir b");

    let file_a = format!("{}/test_a", pt_a.to_str().unwrap());
    let file_b = format!("{}/test_b", pt_b.to_str().unwrap());

    let script = format!("echo aa > {} && echo bb > {}", file_a, file_b);

    let output = hermit_bin()
        .args([
            "--project-dir",
            workdir.to_str().unwrap(),
            "--passthrough",
            pt_a.to_str().unwrap(),
            "--passthrough",
            pt_b.to_str().unwrap(),
            "--",
            "sh",
            "-c",
            &script,
        ])
        .output()
        .expect("failed to run hermit");
    assert!(
        output.status.success(),
        "hermit failed: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );

    let content_a = std::fs::read_to_string(&file_a).expect("passthrough A write did not persist");
    let content_b = std::fs::read_to_string(&file_b).expect("passthrough B write did not persist");
    assert_eq!(content_a.trim(), "aa");
    assert_eq!(content_b.trim(), "bb");

    let _ = std::fs::remove_dir_all(&workdir);
    let _ = std::fs::remove_dir_all(&pt_a);
    let _ = std::fs::remove_dir_all(&pt_b);
}

#[test]
fn test_passthrough_outside_home_works() {
    // A passthrough outside $HOME and /tmp doesn't need fd tricks — just Landlock access
    let dir = tempfile::tempdir().expect("failed to create temp dir");
    let pt_dir = tempfile::tempdir().expect("failed to create passthrough temp dir");
    let dir_path = dir.path().to_str().unwrap();
    let pt_path = pt_dir.path().to_str().unwrap();
    let test_file = format!("{}/pt_outside_test", pt_path);

    let output = hermit_bin()
        .args([
            "--project-dir",
            dir_path,
            "--passthrough",
            pt_path,
            "--",
            "sh",
            "-c",
            &format!("echo ok > {}", test_file),
        ])
        .output()
        .expect("failed to run hermit");
    assert!(
        output.status.success(),
        "hermit failed: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );

    let content =
        std::fs::read_to_string(&test_file).expect("passthrough outside $HOME did not persist");
    assert_eq!(content.trim(), "ok");
}

// --- End-to-end combined test ---

#[test]
fn test_full_sandbox_combined() {
    // Verify namespace isolation + Landlock work together:
    // - Workdir writes persist (bind mount through RO $HOME)
    // - /tmp writes are ephemeral (tmpfs in namespace)
    // - Writes outside allowed paths are blocked (Landlock)
    let home = std::env::var("HOME").expect("HOME not set");
    let workdir = PathBuf::from(&home).join(".hermit_combined_test_workdir");
    std::fs::create_dir_all(&workdir).expect("failed to create workdir");
    let workdir_str = workdir.to_str().unwrap();
    let persist_file = format!("{}/combined_test", workdir_str);

    let script = format!(
        concat!(
            "echo persist > {} && ",
            "echo ephemeral > /tmp/hermit_combined_test && ",
            "echo blocked > /var/tmp/hermit_combined_test 2>/dev/null; ",
            "true"
        ),
        persist_file
    );

    let output = hermit_bin()
        .args(["--project-dir", workdir_str, "--", "sh", "-c", &script])
        .output()
        .expect("failed to run hermit");
    assert!(
        output.status.success(),
        "hermit failed: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Workdir write persisted
    let content = std::fs::read_to_string(&persist_file)
        .expect("workdir write did not persist in combined test");
    assert_eq!(content.trim(), "persist");

    // /tmp write was ephemeral (on tmpfs inside namespace)
    assert!(
        !std::path::Path::new("/tmp/hermit_combined_test").exists(),
        "/tmp write persisted in combined test"
    );

    // /var/tmp write was blocked by Landlock
    assert!(
        !std::path::Path::new("/var/tmp/hermit_combined_test").exists(),
        "/var/tmp write was not blocked in combined test"
    );

    let _ = std::fs::remove_dir_all(&workdir);
}

// --- Home-files config tests ---

/// Helper: create a temp dir to use as $HOME with optional .hermit/home-files config.
/// Returns the temp dir (keeps it alive until dropped).
fn setup_test_home(config_content: Option<&str>) -> tempfile::TempDir {
    let home = tempfile::tempdir().expect("failed to create temp home");
    if let Some(content) = config_content {
        let hermit_dir = home.path().join(".hermit");
        std::fs::create_dir_all(&hermit_dir).expect("failed to create .hermit dir");
        std::fs::write(hermit_dir.join("home-files"), content)
            .expect("failed to write home-files config");
    }
    home
}



#[test]
fn test_home_is_readonly_without_config() {
    // Without any home-files config, $HOME is empty and read-only.
    // Writing to $HOME should fail.
    let test_home = setup_test_home(None);
    let home_str = test_home.path().to_str().unwrap();

    let output = hermit_bin()
        .env("HOME", home_str)
        .args([
            "--project-dir",
            "/tmp",
            "--",
            "sh",
            "-c",
            &format!("echo test > {}/should_fail 2>&1; echo $?", home_str),
        ])
        .output()
        .expect("failed to run hermit");
    assert!(
        output.status.success(),
        "hermit failed: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    // The write should fail (exit code != 0 from the subshell echo)
    assert!(
        !stdout.trim().ends_with('0'),
        "write to RO $HOME should have failed, stdout: {}",
        stdout
    );
}

#[test]
fn test_home_is_empty_without_config() {
    // Without any home-files config, $HOME should be empty.
    let test_home = setup_test_home(None);
    let home_str = test_home.path().to_str().unwrap();
    // Create a file in the test home so we can verify it's NOT visible inside
    std::fs::write(test_home.path().join("visible_outside"), "data")
        .expect("failed to create marker file");

    let output = hermit_bin()
        .env("HOME", home_str)
        .args([
            "--project-dir",
            "/tmp",
            "--",
            "sh",
            "-c",
            &format!("ls -A {}", home_str),
        ])
        .output()
        .expect("failed to run hermit");
    assert!(
        output.status.success(),
        "hermit failed: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.trim().is_empty(),
        "$HOME should be empty inside sandbox, got: {}",
        stdout
    );
}

#[test]
fn test_copy_directive_makes_file_readable() {
    let test_home = setup_test_home(Some("copy ~/.myconfig\n"));
    let home_str = test_home.path().to_str().unwrap();
    // Create the source file
    std::fs::write(test_home.path().join(".myconfig"), "secret=42\n")
        .expect("failed to create config file");

    let output = hermit_bin()
        .env("HOME", home_str)
        .args([
            "--project-dir",
            "/tmp",
            "--",
            "sh",
            "-c",
            &format!("cat {}/.myconfig", home_str),
        ])
        .output()
        .expect("failed to run hermit");
    assert!(
        output.status.success(),
        "hermit failed: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).trim(),
        "secret=42"
    );
}

#[test]
fn test_copy_directive_directory() {
    let test_home = setup_test_home(Some("copy ~/.config/myapp\n"));
    let home_str = test_home.path().to_str().unwrap();
    // Create the source directory with files
    let app_dir = test_home.path().join(".config/myapp");
    std::fs::create_dir_all(&app_dir).expect("failed to create app dir");
    std::fs::write(app_dir.join("settings.toml"), "key = \"value\"\n")
        .expect("failed to create settings file");
    std::fs::create_dir_all(app_dir.join("sub")).expect("failed to create subdir");
    std::fs::write(app_dir.join("sub/nested.txt"), "nested\n")
        .expect("failed to create nested file");

    let output = hermit_bin()
        .env("HOME", home_str)
        .args([
            "--project-dir",
            "/tmp",
            "--",
            "sh",
            "-c",
            &format!(
                "cat {}/.config/myapp/settings.toml && cat {}/.config/myapp/sub/nested.txt",
                home_str, home_str
            ),
        ])
        .output()
        .expect("failed to run hermit");
    assert!(
        output.status.success(),
        "hermit failed: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("key = \"value\""), "settings.toml missing: {}", stdout);
    assert!(stdout.contains("nested"), "nested.txt missing: {}", stdout);
}

#[test]
fn test_pass_directive_allows_writes() {
    // Create a test home with a pass directive for a directory
    let test_home = setup_test_home(Some("pass ~/.writable_dir\n"));
    let home_str = test_home.path().to_str().unwrap();
    let writable_dir = test_home.path().join(".writable_dir");
    std::fs::create_dir_all(&writable_dir).expect("failed to create writable dir");

    let test_file = writable_dir.join("written_inside");

    let output = hermit_bin()
        .env("HOME", home_str)
        .args([
            "--project-dir",
            "/tmp",
            "--",
            "sh",
            "-c",
            &format!("echo from_sandbox > {}", test_file.to_str().unwrap()),
        ])
        .output()
        .expect("failed to run hermit");
    assert!(
        output.status.success(),
        "hermit failed: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );

    // The write should persist on the real filesystem (pass = bind mount)
    let content = std::fs::read_to_string(&test_file)
        .expect("pass directive write did not persist");
    assert_eq!(content.trim(), "from_sandbox");
}

#[test]
fn test_home_contains_only_listed_entries() {
    // Populate $HOME with items both listed and unlisted in home-files config.
    // Inside the sandbox, only listed entries (copy/pass) should be visible.
    let test_home = setup_test_home(Some(
        "copy ~/.bashrc\ncopy ~/.config/myapp\npass ~/.ssh\n",
    ));
    let home_str = test_home.path().to_str().unwrap();

    // Listed entries
    std::fs::write(test_home.path().join(".bashrc"), "# shell config\n")
        .expect("failed to create .bashrc");
    let app_dir = test_home.path().join(".config/myapp");
    std::fs::create_dir_all(&app_dir).expect("failed to create .config/myapp");
    std::fs::write(app_dir.join("settings.toml"), "key = 1\n")
        .expect("failed to create settings.toml");
    let ssh_dir = test_home.path().join(".ssh");
    std::fs::create_dir_all(&ssh_dir).expect("failed to create .ssh");
    std::fs::write(ssh_dir.join("known_hosts"), "host1\n")
        .expect("failed to create known_hosts");

    // Unlisted entries — these should NOT appear inside the sandbox
    std::fs::write(test_home.path().join(".secret"), "password\n")
        .expect("failed to create .secret");
    std::fs::create_dir_all(test_home.path().join(".cache/thumbnails"))
        .expect("failed to create .cache");
    std::fs::write(
        test_home.path().join(".cache/thumbnails/img.dat"),
        "data",
    )
    .expect("failed to create cache file");
    std::fs::create_dir_all(test_home.path().join("documents"))
        .expect("failed to create documents");
    std::fs::write(test_home.path().join("documents/notes.txt"), "notes\n")
        .expect("failed to create notes.txt");

    // List all top-level entries in $HOME inside the sandbox, one per line sorted
    let output = hermit_bin()
        .env("HOME", home_str)
        .args([
            "--project-dir",
            "/tmp",
            "--",
            "sh",
            "-c",
            &format!("ls -1A {}", home_str),
        ])
        .output()
        .expect("failed to run hermit");
    assert!(
        output.status.success(),
        "hermit failed: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let entries: Vec<&str> = stdout.lines().map(|l| l.trim()).filter(|l| !l.is_empty()).collect();

    // Listed entries must be present
    assert!(
        entries.contains(&".bashrc"),
        ".bashrc should be in $HOME, got: {:?}",
        entries
    );
    assert!(
        entries.contains(&".config"),
        ".config should be in $HOME, got: {:?}",
        entries
    );
    assert!(
        entries.contains(&".ssh"),
        ".ssh should be in $HOME, got: {:?}",
        entries
    );

    // Unlisted entries must NOT be present
    assert!(
        !entries.contains(&".secret"),
        ".secret should NOT be in $HOME, got: {:?}",
        entries
    );
    assert!(
        !entries.contains(&".cache"),
        ".cache should NOT be in $HOME, got: {:?}",
        entries
    );
    assert!(
        !entries.contains(&"documents"),
        "documents should NOT be in $HOME, got: {:?}",
        entries
    );

    // Nothing else should be present (only .bashrc, .config, .ssh)
    assert_eq!(
        entries.len(),
        3,
        "expected exactly 3 entries in $HOME, got: {:?}",
        entries
    );
}

#[test]
fn test_missing_home_files_config_is_ok() {
    // No .hermit/home-files → hermit should still work without error
    let test_home = setup_test_home(None);
    let home_str = test_home.path().to_str().unwrap();

    let output = hermit_bin()
        .env("HOME", home_str)
        .args(["--project-dir", "/tmp", "--", "true"])
        .output()
        .expect("failed to run hermit");
    assert!(
        output.status.success(),
        "hermit should succeed without home-files config: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
}

// --- Read directive tests ---

#[test]
fn test_read_directive_makes_file_readable() {
    // `read` bind-mounts the real path read-only (live, not a snapshot).
    let test_home = setup_test_home(Some("read ~/.myconfig\n"));
    let home_str = test_home.path().to_str().unwrap();
    std::fs::write(test_home.path().join(".myconfig"), "live_data\n")
        .expect("failed to create config file");

    let output = hermit_bin()
        .env("HOME", home_str)
        .args([
            "--project-dir",
            "/tmp",
            "--",
            "sh",
            "-c",
            &format!("cat {}/.myconfig", home_str),
        ])
        .output()
        .expect("failed to run hermit");
    assert!(
        output.status.success(),
        "hermit failed: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).trim(),
        "live_data"
    );
}

#[test]
fn test_read_directive_blocks_writes() {
    // `read` should bind-mount read-only — writes must fail.
    let test_home = setup_test_home(Some("read ~/.readonly_dir\n"));
    let home_str = test_home.path().to_str().unwrap();
    let ro_dir = test_home.path().join(".readonly_dir");
    std::fs::create_dir_all(&ro_dir).expect("failed to create readonly dir");
    std::fs::write(ro_dir.join("existing.txt"), "original\n")
        .expect("failed to create existing file");

    let test_file = format!("{}/.readonly_dir/new_file", home_str);

    let output = hermit_bin()
        .env("HOME", home_str)
        .args([
            "--project-dir",
            "/tmp",
            "--",
            "sh",
            "-c",
            &format!("echo should_fail > {} 2>&1; echo $?", test_file),
        ])
        .output()
        .expect("failed to run hermit");
    assert!(
        output.status.success(),
        "hermit failed: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    // The write should fail (exit code != 0 from the subshell)
    assert!(
        !stdout.trim().ends_with('0'),
        "write to read-only bind mount should have failed, stdout: {}",
        stdout
    );

    // Original file should remain unchanged on the host
    let content = std::fs::read_to_string(ro_dir.join("existing.txt"))
        .expect("failed to read existing file");
    assert_eq!(content.trim(), "original");
}

#[test]
fn test_read_directive_directory_contents_visible() {
    // `read` on a directory should make all its contents visible (read-only).
    let test_home = setup_test_home(Some("read ~/.config/myapp\n"));
    let home_str = test_home.path().to_str().unwrap();
    let app_dir = test_home.path().join(".config/myapp");
    std::fs::create_dir_all(app_dir.join("sub")).expect("failed to create subdirs");
    std::fs::write(app_dir.join("settings.toml"), "key = \"val\"\n")
        .expect("failed to create settings");
    std::fs::write(app_dir.join("sub/nested.txt"), "nested_data\n")
        .expect("failed to create nested file");

    let output = hermit_bin()
        .env("HOME", home_str)
        .args([
            "--project-dir",
            "/tmp",
            "--",
            "sh",
            "-c",
            &format!(
                "cat {}/.config/myapp/settings.toml && cat {}/.config/myapp/sub/nested.txt",
                home_str, home_str
            ),
        ])
        .output()
        .expect("failed to run hermit");
    assert!(
        output.status.success(),
        "hermit failed: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("key = \"val\""),
        "settings.toml missing: {}",
        stdout
    );
    assert!(
        stdout.contains("nested_data"),
        "nested.txt missing: {}",
        stdout
    );
}

// --- Multi-source home-files config tests ---
//
// These tests create temp dirs under the real $HOME (not /tmp) because
// the namespace mounts fresh tmpfs on /tmp when --project-dir != /tmp,
// which would hide tempfile-created dirs.

/// Create a test directory under real $HOME, cleaned up on drop.
struct HomeTestDir(PathBuf);

impl HomeTestDir {
    fn new(name: &str) -> Self {
        let home = std::env::var("HOME").expect("HOME not set");
        let dir = PathBuf::from(&home).join(format!(
            ".hermit_test_{}_{}",
            name,
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).expect("failed to create test dir");
        Self(dir)
    }

    fn path(&self) -> &std::path::Path {
        &self.0
    }
}

impl Drop for HomeTestDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn test_project_level_home_files_config() {
    // Project-level .hermit/home-files is discovered and applied
    let test_home = HomeTestDir::new("proj_cfg_home");
    let project = HomeTestDir::new("proj_cfg_project");
    let home_str = test_home.path().to_str().unwrap();
    let project_str = project.path().to_str().unwrap();

    // Create a file in the test home
    std::fs::write(test_home.path().join(".project_rc"), "project_data\n")
        .expect("failed to create .project_rc");

    // Project-level config references it
    let hermit_dir = project.path().join(".hermit");
    std::fs::create_dir_all(&hermit_dir).expect("failed to create project .hermit dir");
    std::fs::write(hermit_dir.join("home-files"), "copy ~/.project_rc\n")
        .expect("failed to write project home-files");

    let output = hermit_bin()
        .env("HOME", home_str)
        .env_remove("HERMIT_HOME_FILES")
        .args([
            "--project-dir",
            project_str,
            "--",
            "sh",
            "-c",
            &format!("cat {}/.project_rc", home_str),
        ])
        .output()
        .expect("failed to run hermit");
    assert!(
        output.status.success(),
        "hermit failed: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).trim(),
        "project_data"
    );
}

#[test]
fn test_env_var_overrides_both_configs() {
    // HERMIT_HOME_FILES should override both project-level and user-level configs
    let test_home = HomeTestDir::new("env_override_home");
    let project = HomeTestDir::new("env_override_project");
    let home_str = test_home.path().to_str().unwrap();
    let project_str = project.path().to_str().unwrap();

    // User-level config
    let user_hermit = test_home.path().join(".hermit");
    std::fs::create_dir_all(&user_hermit).expect("failed to create user .hermit");
    std::fs::write(user_hermit.join("home-files"), "copy ~/.user_rc\n")
        .expect("failed to write user home-files");

    // Project-level config
    let proj_hermit = project.path().join(".hermit");
    std::fs::create_dir_all(&proj_hermit).expect("failed to create project .hermit");
    std::fs::write(proj_hermit.join("home-files"), "copy ~/.project_rc\n")
        .expect("failed to write project home-files");

    // Create all referenced files in the test home
    std::fs::write(test_home.path().join(".user_rc"), "user_data\n")
        .expect("failed to create .user_rc");
    std::fs::write(test_home.path().join(".env_rc"), "env_data\n")
        .expect("failed to create .env_rc");
    std::fs::write(test_home.path().join(".project_rc"), "project_data\n")
        .expect("failed to create .project_rc");

    // Write env var config that only references .env_rc
    let env_config_path = test_home.path().join(".hermit_env_config");
    std::fs::write(&env_config_path, "copy ~/.env_rc\n")
        .expect("failed to write env config");

    let output = hermit_bin()
        .env("HOME", home_str)
        .env("HERMIT_HOME_FILES", env_config_path.to_str().unwrap())
        .args([
            "--project-dir",
            project_str,
            "--",
            "sh",
            "-c",
            &format!("ls -1A {}", home_str),
        ])
        .output()
        .expect("failed to run hermit");
    assert!(
        output.status.success(),
        "hermit failed: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let entries: Vec<&str> = stdout.lines().map(|l| l.trim()).filter(|l| !l.is_empty()).collect();

    // Only .env_rc should be visible (from env var config), not .user_rc or .project_rc
    assert!(
        entries.contains(&".env_rc"),
        ".env_rc should be visible, got: {:?}",
        entries
    );
    assert!(
        !entries.contains(&".user_rc"),
        ".user_rc should NOT be visible (env var overrides user config), got: {:?}",
        entries
    );
    assert!(
        !entries.contains(&".project_rc"),
        ".project_rc should NOT be visible (env var overrides project config), got: {:?}",
        entries
    );
}

#[test]
fn test_project_and_user_configs_merge() {
    // Both project-level and user-level configs exist → directives are concatenated
    let test_home = HomeTestDir::new("merge_home");
    let project = HomeTestDir::new("merge_project");
    let home_str = test_home.path().to_str().unwrap();
    let project_str = project.path().to_str().unwrap();

    // User-level config
    let user_hermit = test_home.path().join(".hermit");
    std::fs::create_dir_all(&user_hermit).expect("failed to create user .hermit");
    std::fs::write(user_hermit.join("home-files"), "copy ~/.user_rc\n")
        .expect("failed to write user home-files");

    // Project-level config
    let proj_hermit = project.path().join(".hermit");
    std::fs::create_dir_all(&proj_hermit).expect("failed to create project .hermit");
    std::fs::write(proj_hermit.join("home-files"), "copy ~/.project_rc\n")
        .expect("failed to write project home-files");

    // Create referenced files
    std::fs::write(test_home.path().join(".user_rc"), "user_data\n")
        .expect("failed to create .user_rc");
    std::fs::write(test_home.path().join(".project_rc"), "project_data\n")
        .expect("failed to create .project_rc");

    let output = hermit_bin()
        .env("HOME", home_str)
        .env_remove("HERMIT_HOME_FILES")
        .args([
            "--project-dir",
            project_str,
            "--",
            "sh",
            "-c",
            &format!("ls -1A {}", home_str),
        ])
        .output()
        .expect("failed to run hermit");
    assert!(
        output.status.success(),
        "hermit failed: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let entries: Vec<&str> = stdout.lines().map(|l| l.trim()).filter(|l| !l.is_empty()).collect();

    // Both should be visible
    assert!(
        entries.contains(&".user_rc"),
        ".user_rc should be visible, got: {:?}",
        entries
    );
    assert!(
        entries.contains(&".project_rc"),
        ".project_rc should be visible, got: {:?}",
        entries
    );
}

// --- Network isolation tests ---

#[test]
fn test_net_isolate_basic_execution() {
    let output = hermit_bin()
        .args(["--net", "isolate", "--project-dir", "/tmp", "--", "echo", "hello"])
        .output()
        .expect("failed to run hermit");
    assert!(
        output.status.success(),
        "hermit --net isolate failed: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&output.stdout).trim(), "hello");
}

#[test]
fn test_net_isolate_exit_code_propagates() {
    let status = hermit_bin()
        .args([
            "--net", "isolate",
            "--project-dir", "/tmp",
            "--",
            "sh", "-c", "exit 42",
        ])
        .status()
        .expect("failed to run hermit");
    assert_eq!(status.code(), Some(42));
}

#[test]
fn test_net_isolate_no_network_interfaces() {
    // Inside an empty net namespace, /sys/class/net/ should only contain "lo"
    let output = hermit_bin()
        .args([
            "--net", "isolate",
            "--project-dir", "/tmp",
            "--",
            "sh", "-c", "ls /sys/class/net/",
        ])
        .output()
        .expect("failed to run hermit");
    assert!(
        output.status.success(),
        "hermit --net isolate failed: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let ifaces: Vec<&str> = stdout.split_whitespace().collect();
    assert_eq!(
        ifaces,
        vec!["lo"],
        "expected only 'lo' interface in net namespace, got: {:?}",
        ifaces
    );
}

#[test]
fn test_net_isolate_tcp_connect_fails() {
    // TCP connect to loopback should fail — lo is down in an empty net ns
    let output = hermit_bin()
        .args([
            "--net", "isolate",
            "--project-dir", "/tmp",
            "--",
            "sh", "-c",
            // Try connecting to a port on loopback. The connection should fail
            // because lo is down (not configured) in the new net namespace.
            "echo test | sh -c 'exec 3<>/dev/tcp/127.0.0.1/80' 2>&1; echo $?",
        ])
        .output()
        .expect("failed to run hermit");
    assert!(
        output.status.success(),
        "hermit process itself should succeed: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    // The TCP connect should fail (nonzero exit code from the inner sh)
    let last_line = stdout.trim().lines().last().unwrap_or("");
    assert_ne!(
        last_line, "0",
        "TCP connect should have failed in net namespace, stdout: {}",
        stdout
    );
}

#[test]
fn test_net_isolate_preserves_filesystem_isolation() {
    // Verify that filesystem isolation still works with --net isolate:
    // workdir writes persist, /tmp writes are ephemeral
    let dir = tempfile::tempdir().expect("failed to create temp dir");
    let dir_path = dir.path().to_str().unwrap();
    let persist_file = format!("{}/net_persist_test", dir_path);

    let script = format!(
        "echo persisted > {} && echo ephemeral > /tmp/hermit_net_fs_test",
        persist_file
    );

    let output = hermit_bin()
        .args([
            "--net", "isolate",
            "--project-dir", dir_path,
            "--",
            "sh", "-c", &script,
        ])
        .output()
        .expect("failed to run hermit");
    assert!(
        output.status.success(),
        "hermit --net isolate failed: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Workdir write persisted
    let content = std::fs::read_to_string(&persist_file)
        .expect("workdir write did not persist with --net isolate");
    assert_eq!(content.trim(), "persisted");

    // /tmp write was ephemeral
    assert!(
        !std::path::Path::new("/tmp/hermit_net_fs_test").exists(),
        "/tmp write persisted with --net isolate"
    );
}

#[test]
fn test_net_isolate_signal_forwarding() {
    // Start a long-running process with --net isolate, send SIGTERM to the
    // hermit parent, verify the child exits (hermit should exit with 128+15=143).
    use std::process::Stdio;

    let mut child = hermit_bin()
        .args([
            "--net", "isolate",
            "--project-dir", "/tmp",
            "--",
            "sleep", "60",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn hermit");

    // Give the child time to set up namespaces and start sleep
    std::thread::sleep(Duration::from_millis(500));

    // Send SIGTERM to the hermit parent process
    unsafe { libc::kill(child.id() as i32, libc::SIGTERM) };

    let status = child.wait().expect("failed to wait for hermit");
    assert!(
        !status.success(),
        "hermit should have exited non-zero after SIGTERM"
    );
}

#[test]
fn test_without_net_isolate_has_network() {
    // Without --net isolate, the sandbox should have normal network interfaces
    let output = hermit_bin()
        .args([
            "--project-dir", "/tmp",
            "--",
            "sh", "-c", "ls /sys/class/net/",
        ])
        .output()
        .expect("failed to run hermit");
    assert!(
        output.status.success(),
        "hermit failed: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let ifaces: Vec<&str> = stdout.split_whitespace().collect();
    assert!(
        ifaces.len() > 1 || ifaces.contains(&"lo"),
        "expected network interfaces without --net isolate, got: {:?}",
        ifaces
    );
}

