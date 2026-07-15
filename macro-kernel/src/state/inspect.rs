//! The Inspector abstraction: how the kernel reads the bounded machine domain.
//!
//! Every probe is read-only. Probes are allowed to fail individually — a
//! failed probe narrows the boundary (the kernel governs less) but never
//! aborts the scan. Which probes succeeded is recorded in the Boundary.

use std::path::Path;
use std::process::Command;

use super::{
    ListeningPort, MountInfo, OsInfo, ProcessInfo, ScheduledTask, ServiceInfo, StructuralState,
    Toolchain, STATE_SCHEMA_VERSION,
};

pub type ProbeResult<T> = Result<T, String>;

/// Outcome of one probe, recorded in the Boundary so it is always explicit
/// which subsystems the snapshot actually covers.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ProbeStatus {
    pub name: String,
    pub ok: bool,
    pub detail: Option<String>,
}

pub trait Inspector {
    fn os_info(&self) -> ProbeResult<OsInfo>;
    fn processes(&self) -> ProbeResult<Vec<ProcessInfo>>;
    fn services(&self) -> ProbeResult<Vec<ServiceInfo>>;
    fn listening_ports(&self) -> ProbeResult<Vec<ListeningPort>>;
    fn mounts(&self) -> ProbeResult<Vec<MountInfo>>;
    fn scheduled_tasks(&self) -> ProbeResult<Vec<ScheduledTask>>;

    /// Toolchain discovery is platform-independent: locate known developer
    /// tools on PATH and ask each for its version.
    fn toolchains(&self) -> ProbeResult<Vec<Toolchain>> {
        Ok(probe_toolchains())
    }
}

/// Select the inspection backend for the OS the kernel is running on.
pub fn platform_inspector() -> Box<dyn Inspector> {
    match std::env::consts::OS {
        "windows" => Box::new(super::windows::WindowsInspector),
        _ => Box::new(super::linux::LinuxInspector),
    }
}

/// Run every probe, degrading gracefully: a failed probe yields an empty
/// section plus a ProbeStatus explaining what could not be read.
pub fn capture(inspector: &dyn Inspector) -> (StructuralState, Vec<ProbeStatus>) {
    let mut statuses = Vec::new();

    fn run<T: Default>(
        statuses: &mut Vec<ProbeStatus>,
        name: &str,
        result: ProbeResult<T>,
    ) -> T {
        match result {
            Ok(v) => {
                statuses.push(ProbeStatus {
                    name: name.to_string(),
                    ok: true,
                    detail: None,
                });
                v
            }
            Err(e) => {
                statuses.push(ProbeStatus {
                    name: name.to_string(),
                    ok: false,
                    detail: Some(e),
                });
                T::default()
            }
        }
    }

    let os = match inspector.os_info() {
        Ok(v) => {
            statuses.push(ProbeStatus {
                name: "os_info".into(),
                ok: true,
                detail: None,
            });
            v
        }
        Err(e) => {
            statuses.push(ProbeStatus {
                name: "os_info".into(),
                ok: false,
                detail: Some(e),
            });
            OsInfo {
                family: std::env::consts::OS.to_string(),
                name: "unknown".into(),
                kernel_version: "unknown".into(),
                hostname: "unknown".into(),
                arch: std::env::consts::ARCH.to_string(),
            }
        }
    };

    let processes = run(&mut statuses, "processes", inspector.processes());
    let services = run(&mut statuses, "services", inspector.services());
    let listening_ports = run(&mut statuses, "listening_ports", inspector.listening_ports());
    let mounts = run(&mut statuses, "mounts", inspector.mounts());
    let scheduled_tasks = run(&mut statuses, "scheduled_tasks", inspector.scheduled_tasks());
    let toolchains = run(&mut statuses, "toolchains", inspector.toolchains());

    let state = StructuralState {
        schema_version: STATE_SCHEMA_VERSION,
        captured_at: chrono::Utc::now().to_rfc3339(),
        os,
        processes,
        services,
        listening_ports,
        mounts,
        scheduled_tasks,
        toolchains,
    };
    (state, statuses)
}

/// Minimal PATH lookup (avoids shelling out to `which`/`where`).
pub fn find_on_path(tool: &str) -> Option<std::path::PathBuf> {
    let path_var = std::env::var_os("PATH")?;
    let exts: &[&str] = if cfg!(windows) {
        &[".exe", ".cmd", ".bat", ""]
    } else {
        &[""]
    };
    for dir in std::env::split_paths(&path_var) {
        for ext in exts {
            let candidate = dir.join(format!("{tool}{ext}"));
            if is_executable(&candidate) {
                return Some(candidate);
            }
        }
    }
    None
}

fn is_executable(path: &Path) -> bool {
    let Ok(meta) = std::fs::metadata(path) else {
        return false;
    };
    if !meta.is_file() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        meta.permissions().mode() & 0o111 != 0
    }
    #[cfg(not(unix))]
    {
        true
    }
}

const KNOWN_TOOLS: &[&str] = &[
    "python3", "python", "node", "npm", "cargo", "rustc", "git", "docker", "go", "java", "pwsh",
    "powershell", "uv", "bun",
];

fn probe_toolchains() -> Vec<Toolchain> {
    let mut out = Vec::new();
    for tool in KNOWN_TOOLS {
        let Some(path) = find_on_path(tool) else {
            continue;
        };
        let version_flag = if *tool == "java" { "-version" } else { "--version" };
        let version = Command::new(&path)
            .arg(version_flag)
            .output()
            .ok()
            .and_then(|o| {
                let text = if o.stdout.is_empty() { o.stderr } else { o.stdout };
                String::from_utf8(text)
                    .ok()
                    .and_then(|s| s.lines().next().map(|l| l.trim().to_string()))
                    .filter(|s| !s.is_empty())
            });
        out.push(Toolchain {
            name: tool.to_string(),
            version,
            path: path.display().to_string(),
        });
    }
    out
}

/// Helper shared by backends: run a command and capture stdout as UTF-8.
pub fn run_capture(program: &str, args: &[&str]) -> ProbeResult<String> {
    let output = Command::new(program)
        .args(args)
        .output()
        .map_err(|e| format!("failed to spawn {program}: {e}"))?;
    if !output.status.success() {
        return Err(format!(
            "{program} exited with {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    String::from_utf8(output.stdout).map_err(|e| format!("{program} produced non-UTF8 output: {e}"))
}
