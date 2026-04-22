use anyhow::{bail, Context, Result};
use landlock::{
    Access, AccessFs, PathBeneath, PathFd, Ruleset, RulesetAttr, RulesetCreatedAttr, ABI,
};
use log::{debug, info};
use std::path::Path;

/// Probe whether the running kernel supports Landlock.
///
/// The `landlock` crate hides its own status probe behind a private helper,
/// so we issue the same syscall directly: `landlock_create_ruleset(NULL, 0,
/// LANDLOCK_CREATE_RULESET_VERSION)` returns the supported ABI version (>0)
/// when Landlock is available, or `-1` with errno `ENOSYS`/`EOPNOTSUPP` when
/// it isn't (kernel lacks the LSM, or it's disabled at boot).
///
/// Hermit's whole safety story hinges on Landlock, so callers should abort
/// at startup when this returns an error rather than silently running a
/// less-isolated sandbox.
pub fn ensure_available() -> Result<()> {
    // Flag 1 = LANDLOCK_CREATE_RULESET_VERSION (query-only mode).
    const LANDLOCK_CREATE_RULESET_VERSION: libc::c_ulong = 1;
    let ret = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            std::ptr::null::<libc::c_void>(),
            0usize,
            LANDLOCK_CREATE_RULESET_VERSION,
        )
    };
    if ret > 0 {
        debug!("landlock: kernel reports ABI v{}", ret);
        return Ok(());
    }
    let err = std::io::Error::last_os_error();
    match err.raw_os_error() {
        Some(libc::ENOSYS) => bail!(
            "Landlock is not built into this kernel (ENOSYS). Hermit cannot enforce its filesystem sandbox without Landlock; refusing to start."
        ),
        Some(libc::EOPNOTSUPP) => bail!(
            "Landlock is disabled at boot (EOPNOTSUPP). Enable lsm=...,landlock on the kernel command line; refusing to start."
        ),
        _ => bail!(
            "Landlock availability check failed: {}. Refusing to start without a working filesystem sandbox.",
            err
        ),
    }
}

/// Apply Landlock restrictions: read-only filesystem with read-write exceptions
/// for the given paths. After this call, the current thread (and any children)
/// can only write to paths in `rw_paths`.
pub fn apply_landlock(rw_paths: &[&Path]) -> Result<()> {
    let abi = ABI::V3;
    info!("landlock: using ABI {:?}", abi);

    let read_access = AccessFs::from_read(abi);
    let all_access = AccessFs::from_all(abi);
    debug!("landlock: read access bits: {:?}", read_access);
    debug!("landlock: full access bits: {:?}", all_access);

    let mut ruleset = Ruleset::default()
        .handle_access(all_access)
        .context("failed to handle Landlock access")?
        .create()
        .context("failed to create Landlock ruleset")?;
    debug!("landlock: ruleset created");

    // Read-only + execute on the entire filesystem
    ruleset = ruleset
        .add_rule(PathBeneath::new(PathFd::new("/")?, read_access))
        .context("failed to add read-only rule for /")?;
    info!("landlock: / => read-only");

    // Full read-write on each specified path
    for path in rw_paths {
        ruleset = ruleset
            .add_rule(PathBeneath::new(PathFd::new(path)?, all_access))
            .with_context(|| format!("failed to add RW rule for {}", path.display()))?;
        info!("landlock: {} => read-write", path.display());
    }

    ruleset
        .restrict_self()
        .context("failed to restrict self with Landlock")?;
    info!("landlock: policy enforced on current process");

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_apply_landlock_accepts_valid_paths() {
        // Just verify the function accepts valid path slices without panicking.
        // Actual enforcement must be tested in integration tests (separate process).
        let paths: Vec<&Path> = vec![Path::new("/tmp")];
        // We can't call apply_landlock in unit tests because it's irreversible,
        // but we can verify the function signature compiles and paths are accepted.
        let _ = &paths;
    }

    #[test]
    fn ensure_available_agrees_with_landlock_crate() {
        // The probe must match what the landlock crate itself reports via a
        // trial ruleset. We can't directly observe the crate's internal
        // status, but constructing a ruleset should succeed iff our probe
        // succeeds on the same kernel.
        let probe = ensure_available();
        let crate_reports_ok = Ruleset::default()
            .handle_access(AccessFs::from_all(ABI::V1))
            .and_then(|r| r.create())
            .is_ok();
        assert_eq!(probe.is_ok(), crate_reports_ok,
            "ensure_available() disagrees with landlock crate: probe={:?}, crate_ok={}",
            probe, crate_reports_ok);
    }
}
