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
