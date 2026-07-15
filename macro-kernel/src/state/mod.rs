pub mod inspect;
pub mod linux;
pub mod windows;

use serde::{Deserialize, Serialize};

/// The structured state model of the bounded machine domain.
///
/// This is the "StructuralState" of the foundation spec: not everything that
/// is true about the machine, but the least bounded relational structure the
/// kernel needs in order to judge what may lawfully happen next.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StructuralState {
    pub schema_version: u32,
    pub captured_at: String,
    pub os: OsInfo,
    pub processes: Vec<ProcessInfo>,
    pub services: Vec<ServiceInfo>,
    pub listening_ports: Vec<ListeningPort>,
    pub mounts: Vec<MountInfo>,
    pub scheduled_tasks: Vec<ScheduledTask>,
    pub toolchains: Vec<Toolchain>,
}

pub const STATE_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsInfo {
    /// "linux" | "windows" | "macos" | ...
    pub family: String,
    pub name: String,
    pub kernel_version: String,
    pub hostname: String,
    pub arch: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessInfo {
    pub pid: u32,
    pub ppid: Option<u32>,
    pub name: String,
    /// Single-letter process state where the platform reports one
    /// (e.g. "R", "S", "Z" on Linux). None on Windows.
    pub state: Option<String>,
    pub cmdline: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceInfo {
    pub name: String,
    /// Normalized state: "running" | "stopped" | "failed" | other raw value.
    pub state: String,
    pub description: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListeningPort {
    pub protocol: String,
    pub address: String,
    pub port: u16,
    pub pid: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MountInfo {
    pub source: String,
    pub target: String,
    pub fstype: String,
    pub total_bytes: Option<u64>,
    pub available_bytes: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScheduledTask {
    pub name: String,
    pub schedule: Option<String>,
    pub command: Option<String>,
    /// Where the task was discovered: "crontab", "/etc/cron.d", "systemd-timer",
    /// "windows-task-scheduler", ...
    pub source: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Toolchain {
    pub name: String,
    pub version: Option<String>,
    pub path: String,
}

impl StructuralState {
    /// Canonical content hash of the snapshot. Witnesses reference this hash so
    /// a judgment is always tied to the exact state it was made against.
    pub fn content_hash(&self) -> String {
        let json = serde_json::to_string(self).expect("state serializes");
        crate::receipts::sha256_hex(json.as_bytes())
    }
}
