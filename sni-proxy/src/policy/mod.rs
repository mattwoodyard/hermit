//! Policy module: hostname/path/method allow rules and the traits the
//! proxy listeners consult.
//!
//! Submodules:
//! - [`method`]: closed `HttpMethod` enum and its parser
//! - [`rule`]: `Verdict`, `Mechanism`, `BypassProtocol`, `AccessRule`,
//!   `IpRule`, plus the path-traversal guard
//! - [`ruleset`]: `RuleSet`, the `ConnectionPolicy`/`RequestPolicy`
//!   traits, and the legacy `AllowList`/`AllowAll` types

mod method;
mod rule;
mod ruleset;

pub use method::{HttpMethod, ParseMethodError};
pub use rule::{
    AccessRule, BypassProtocol, IpRule, Mechanism, ParseRuleError, Verdict,
};
pub use ruleset::{AllowAll, AllowList, ConnectionPolicy, RequestPolicy, RuleSet};

/// Wrappers around `policy`'s private items for the dedicated test
/// crate (`sni-proxy-tests`). Off by default; the test crate flips on
/// the `__test_internals` feature in its `[dependencies]` entry.
///
/// Wrappers (rather than `pub use`) because Rust E0364 forbids
/// re-exporting `pub(crate)` items outside the crate. The items
/// themselves stay `pub(crate)` — the broadening is contained to
/// these wrapper signatures.
#[cfg(feature = "__test_internals")]
#[doc(hidden)]
pub mod __test_internals {
    use super::rule::AccessRule;

    pub fn rule_matches(rule: &AccessRule, hostname: &str, path: &str, method: &str) -> bool {
        rule.matches(hostname, path, method)
    }

    pub fn rule_matches_host(rule: &AccessRule, hostname: &str) -> bool {
        rule.matches_host(hostname)
    }
}
