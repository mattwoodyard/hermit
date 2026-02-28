use std::path::PathBuf;
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-env-changed=PASTA_BINARY");

    if cfg!(feature = "vendored-pasta") {
        build_vendored_pasta();
    } else if let Ok(path) = std::env::var("PASTA_BINARY") {
        println!("cargo:rustc-env=PASTA_BINARY={}", path);
    }
}

fn build_vendored_pasta() {
    let manifest_dir =
        PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR not set"));
    let passt_dir = manifest_dir.join("../../vendor/passt");
    let passt_dir = passt_dir
        .canonicalize()
        .unwrap_or_else(|e| panic!("vendor/passt not found at {}: {}", passt_dir.display(), e));

    println!("cargo:rerun-if-changed={}", passt_dir.display());

    let status = Command::new("make")
        .arg("pasta")
        .current_dir(&passt_dir)
        .status()
        .expect("failed to run make in vendor/passt");

    if !status.success() {
        panic!("make pasta failed with {}", status);
    }

    let pasta_bin = passt_dir.join("pasta");
    if !pasta_bin.exists() {
        panic!(
            "make succeeded but pasta binary not found at {}",
            pasta_bin.display()
        );
    }

    println!("cargo:rustc-env=PASTA_BINARY={}", pasta_bin.display());
}
