//! The candidate transition engine.
//!
//! A CandidateTransition is a *description* of a possible change — it carries
//! no ability to run. This module proposes candidates from observed snapshot
//! facts and loads user-supplied transition specs for judgment. Nothing here
//! (or anywhere else in milestone 1) executes a transition.

use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::state::StructuralState;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransitionKind {
    /// Re-observe the domain. The only intrinsically non-mutating kind.
    NoopObserve,
    DeletePath,
    StopService,
    RestartService,
    KillProcess,
}

impl TransitionKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            TransitionKind::NoopObserve => "noop_observe",
            TransitionKind::DeletePath => "delete_path",
            TransitionKind::StopService => "stop_service",
            TransitionKind::RestartService => "restart_service",
            TransitionKind::KillProcess => "kill_process",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Effect {
    Mutation,
    DataLoss,
    Irreversible,
    ServiceInterruption,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CandidateTransition {
    pub id: String,
    pub kind: TransitionKind,
    /// What the transition acts on: a path, a service name, or a PID
    /// (as a string), depending on kind. Empty for noop_observe.
    #[serde(default)]
    pub target: String,
    pub description: String,
    /// Effects the proposer declares beyond those intrinsic to the kind.
    #[serde(default)]
    pub declared_effects: Vec<Effect>,
}

impl CandidateTransition {
    /// Effects intrinsic to the transition kind. Declared effects are added
    /// on top; they can widen but never narrow what a kind implies.
    pub fn effects(&self) -> Vec<Effect> {
        let mut effects = match self.kind {
            TransitionKind::NoopObserve => vec![],
            TransitionKind::DeletePath => {
                vec![Effect::Mutation, Effect::DataLoss, Effect::Irreversible]
            }
            TransitionKind::StopService | TransitionKind::RestartService => {
                vec![Effect::Mutation, Effect::ServiceInterruption]
            }
            TransitionKind::KillProcess => {
                vec![Effect::Mutation, Effect::ServiceInterruption]
            }
        };
        for e in &self.declared_effects {
            if !effects.contains(e) {
                effects.push(*e);
            }
        }
        effects
    }

    pub fn content_hash(&self) -> String {
        let json = serde_json::to_string(self).expect("transition serializes");
        crate::receipts::sha256_hex(json.as_bytes())
    }

    pub fn load(path: &Path) -> Result<Self, String> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| format!("cannot read transition {}: {e}", path.display()))?;
        serde_json::from_str(&content).map_err(|e| format!("invalid transition spec: {e}"))
    }
}

/// Propose candidate transitions from observed snapshot facts. Every
/// candidate cites the observation that motivated it in its description.
pub fn propose(state: &StructuralState) -> Vec<CandidateTransition> {
    let mut out = vec![CandidateTransition {
        id: "observe-rescan".into(),
        kind: TransitionKind::NoopObserve,
        target: String::new(),
        description: "Re-scan the bounded domain to refresh the structural state.".into(),
        declared_effects: vec![],
    }];

    for service in state.services.iter().filter(|s| s.state == "failed") {
        out.push(CandidateTransition {
            id: format!("restart-failed-service-{}", service.name),
            kind: TransitionKind::RestartService,
            target: service.name.clone(),
            description: format!(
                "Service '{}' was observed in state 'failed'; restarting could restore it.",
                service.name
            ),
            declared_effects: vec![],
        });
    }

    for process in state
        .processes
        .iter()
        .filter(|p| p.state.as_deref() == Some("Z"))
    {
        out.push(CandidateTransition {
            id: format!("reap-zombie-{}", process.pid),
            kind: TransitionKind::KillProcess,
            target: process.pid.to_string(),
            description: format!(
                "Process {} ('{}') was observed in zombie state.",
                process.pid, process.name
            ),
            declared_effects: vec![],
        });
    }

    out.extend(propose_stale_temp(state));
    out
}

/// Propose cleanup of stale top-level entries in the platform temp directory
/// (read-only inspection; capped so the list stays reviewable).
fn propose_stale_temp(state: &StructuralState) -> Vec<CandidateTransition> {
    const STALE_AFTER: std::time::Duration = std::time::Duration::from_secs(7 * 24 * 3600);
    const MAX_CANDIDATES: usize = 5;
    let _ = state; // temp inspection is direct; the snapshot fixes the boundary in time
    let temp = std::env::temp_dir();
    let Ok(entries) = std::fs::read_dir(&temp) else {
        return vec![];
    };
    let now = std::time::SystemTime::now();
    let mut out = Vec::new();
    for entry in entries.flatten() {
        if out.len() >= MAX_CANDIDATES {
            break;
        }
        let Ok(meta) = entry.metadata() else { continue };
        let Ok(modified) = meta.modified() else { continue };
        let Ok(age) = now.duration_since(modified) else { continue };
        if age < STALE_AFTER {
            continue;
        }
        let path = entry.path();
        out.push(CandidateTransition {
            id: format!("clean-stale-temp-{}", out.len()),
            kind: TransitionKind::DeletePath,
            target: path.display().to_string(),
            description: format!(
                "Temp entry '{}' was last modified {} days ago.",
                path.display(),
                age.as_secs() / 86400
            ),
            declared_effects: vec![],
        });
    }
    out
}
