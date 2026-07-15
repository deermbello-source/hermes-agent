//! The constraint engine: what must remain preserved across lawful transitions.
//!
//! Constraints are constitutive, not decorative — they are loaded as
//! structured data (TOML), hashed, and every judgment records the hash of the
//! exact constraint set it was made under.

use std::path::Path;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConstraintSet {
    pub schema_version: u32,
    #[serde(rename = "constraint", default)]
    pub constraints: Vec<Constraint>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Constraint {
    pub id: String,
    pub description: String,
    #[serde(flatten)]
    pub rule: Rule,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Rule {
    /// Transition kinds that are never admissible, regardless of target.
    ForbidKinds { kinds: Vec<String> },
    /// Paths that no transition may delete or write into (prefix match,
    /// case-insensitive, separator-normalized).
    ProtectPaths { paths: Vec<String> },
    /// Processes that must not be killed (by name, case-insensitive; PID 1 is
    /// always protected regardless of this list).
    ProtectProcesses { names: Vec<String> },
    /// Services that must not be stopped or restarted.
    ProtectServices { names: Vec<String> },
}

impl ConstraintSet {
    pub fn load(path: &Path) -> Result<Self, String> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| format!("cannot read constraints {}: {e}", path.display()))?;
        let set: ConstraintSet =
            toml::from_str(&content).map_err(|e| format!("invalid constraints file: {e}"))?;
        set.validate()?;
        Ok(set)
    }

    pub fn validate(&self) -> Result<(), String> {
        let mut seen = std::collections::HashSet::new();
        for c in &self.constraints {
            if c.id.trim().is_empty() {
                return Err("constraint with empty id".into());
            }
            if !seen.insert(&c.id) {
                return Err(format!("duplicate constraint id: {}", c.id));
            }
        }
        Ok(())
    }

    /// Canonical hash of the constraint set, recorded in every witness.
    pub fn content_hash(&self) -> String {
        let json = serde_json::to_string(self).expect("constraint set serializes");
        crate::receipts::sha256_hex(json.as_bytes())
    }
}

/// The default constraint set compiled into the binary, used when no
/// constraints file is given. Also shipped as `constraints/default.toml`.
pub const DEFAULT_CONSTRAINTS_TOML: &str = include_str!("../constraints/default.toml");

pub fn load_or_default(path: Option<&Path>) -> Result<ConstraintSet, String> {
    match path {
        Some(p) => ConstraintSet::load(p),
        None => {
            let set: ConstraintSet = toml::from_str(DEFAULT_CONSTRAINTS_TOML)
                .map_err(|e| format!("built-in default constraints are invalid: {e}"))?;
            set.validate()?;
            Ok(set)
        }
    }
}

/// Normalize a path for protection checks: lowercase, forward slashes,
/// no trailing slash. Makes `C:\Windows\System32` comparable to `c:/windows`.
pub fn normalize_path(path: &str) -> String {
    let mut s = path.replace('\\', "/").to_lowercase();
    while s.len() > 1 && s.ends_with('/') {
        s.pop();
    }
    s
}

/// True if `target` is the protected path itself, inside it, or an ancestor
/// of it (deleting an ancestor also destroys the protected path).
pub fn path_conflicts(protected: &str, target: &str) -> bool {
    let p = normalize_path(protected);
    let t = normalize_path(target);
    t == p
        || t.starts_with(&format!("{p}/"))
        || p.starts_with(&format!("{t}/"))
}
