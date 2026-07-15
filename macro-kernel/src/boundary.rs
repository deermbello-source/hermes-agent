//! Boundary discovery: what counts as the governed machine domain for this run.
//!
//! The boundary is not a container metaphor — it is the domain over which
//! preservation claims are meaningful. It records the host identity, when the
//! domain was observed, and exactly which probes succeeded (a failed probe
//! narrows the boundary; the kernel never pretends to govern what it could
//! not read).

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::state::inspect::ProbeStatus;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Boundary {
    pub run_id: String,
    pub hostname: String,
    pub os_family: String,
    pub discovered_at: String,
    /// Which subsystems this run could actually observe.
    pub probes: Vec<ProbeStatus>,
}

impl Boundary {
    pub fn new(run_id: String, hostname: String, os_family: String, probes: Vec<ProbeStatus>) -> Self {
        Self {
            run_id,
            hostname,
            os_family,
            discovered_at: chrono::Utc::now().to_rfc3339(),
            probes,
        }
    }
}

/// A sortable, filesystem-safe run identifier: UTC timestamp + pid.
pub fn new_run_id() -> String {
    let now = chrono::Utc::now().format("%Y%m%dT%H%M%S%3fZ");
    format!("{now}-{}", std::process::id())
}

/// The kernel's own writable home. This is the ONLY location the kernel writes
/// to in milestone 1 (snapshots and receipts). Resolution order:
/// `--home` flag > `MACRO_KERNEL_HOME` env > `~/.macro-kernel`.
pub fn resolve_home(flag: Option<PathBuf>) -> Result<PathBuf, String> {
    if let Some(p) = flag {
        return Ok(p);
    }
    if let Some(env) = std::env::var_os("MACRO_KERNEL_HOME") {
        return Ok(PathBuf::from(env));
    }
    let home_var = if cfg!(windows) { "USERPROFILE" } else { "HOME" };
    let base = std::env::var_os(home_var)
        .ok_or_else(|| format!("cannot resolve kernel home: {home_var} is not set"))?;
    Ok(PathBuf::from(base).join(".macro-kernel"))
}

pub fn snapshots_dir(home: &Path) -> PathBuf {
    home.join("snapshots")
}

/// Latest snapshot = lexicographically greatest file name, which works because
/// run ids start with a sortable UTC timestamp.
pub fn latest_snapshot_path(home: &Path) -> Result<Option<PathBuf>, String> {
    let dir = snapshots_dir(home);
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return Ok(None);
    };
    let mut names: Vec<PathBuf> = entries
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|ext| ext == "json"))
        .collect();
    names.sort();
    Ok(names.pop())
}
