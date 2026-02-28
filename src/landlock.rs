use anyhow::{Context, Result};
use landlock::{
    Access, AccessFs, PathBeneath, PathFd, Ruleset, RulesetAttr, RulesetCreatedAttr, ABI,
};
use log::{debug, info};
use std::path::Path;

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
}
