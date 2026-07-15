//! Windows inspection backend.
//!
//! Uses read-only PowerShell/CIM queries executed as subprocesses, with
//! results exchanged as JSON. No Windows API bindings are required, so this
//! backend compiles (and is type-checked) on every platform; it is selected
//! at runtime only when the kernel actually runs on Windows.

use serde::Deserialize;

use super::inspect::{Inspector, ProbeResult};
use super::{ListeningPort, MountInfo, OsInfo, ProcessInfo, ScheduledTask, ServiceInfo};

pub struct WindowsInspector;

/// Run a read-only PowerShell expression and parse its JSON output.
/// `-InputObject @(...)` guarantees an array even for 0/1 results.
fn ps_json<T: for<'de> Deserialize<'de>>(expression: &str) -> ProbeResult<Vec<T>> {
    let shell = if super::inspect::find_on_path("pwsh").is_some() {
        "pwsh"
    } else {
        "powershell"
    };
    let command = format!("ConvertTo-Json -Depth 4 -Compress -InputObject @({expression})");
    let stdout = super::inspect::run_capture(
        shell,
        &["-NoProfile", "-NonInteractive", "-Command", &command],
    )?;
    let trimmed = stdout.trim();
    if trimmed.is_empty() {
        return Ok(Vec::new());
    }
    serde_json::from_str(trimmed).map_err(|e| format!("cannot parse PowerShell JSON: {e}"))
}

impl Inspector for WindowsInspector {
    fn os_info(&self) -> ProbeResult<OsInfo> {
        #[derive(Deserialize)]
        struct Row {
            #[serde(rename = "Caption")]
            caption: Option<String>,
            #[serde(rename = "Version")]
            version: Option<String>,
            #[serde(rename = "CSName")]
            cs_name: Option<String>,
        }
        let rows: Vec<Row> = ps_json(
            "Get-CimInstance Win32_OperatingSystem | Select-Object Caption,Version,CSName",
        )?;
        let row = rows.into_iter().next().ok_or("no OS info returned")?;
        Ok(OsInfo {
            family: "windows".into(),
            name: row.caption.unwrap_or_else(|| "Windows".into()),
            kernel_version: row.version.unwrap_or_else(|| "unknown".into()),
            hostname: row.cs_name.unwrap_or_else(|| "unknown".into()),
            arch: std::env::consts::ARCH.to_string(),
        })
    }

    fn processes(&self) -> ProbeResult<Vec<ProcessInfo>> {
        #[derive(Deserialize)]
        struct Row {
            #[serde(rename = "ProcessId")]
            pid: u32,
            #[serde(rename = "ParentProcessId")]
            ppid: Option<u32>,
            #[serde(rename = "Name")]
            name: Option<String>,
            #[serde(rename = "CommandLine")]
            cmdline: Option<String>,
        }
        let rows: Vec<Row> = ps_json(
            "Get-CimInstance Win32_Process | Select-Object ProcessId,ParentProcessId,Name,CommandLine",
        )?;
        Ok(rows
            .into_iter()
            .map(|r| ProcessInfo {
                pid: r.pid,
                ppid: r.ppid,
                name: r.name.unwrap_or_default(),
                state: None,
                cmdline: r.cmdline.filter(|s| !s.is_empty()),
            })
            .collect())
    }

    fn services(&self) -> ProbeResult<Vec<ServiceInfo>> {
        #[derive(Deserialize)]
        struct Row {
            #[serde(rename = "Name")]
            name: String,
            #[serde(rename = "State")]
            state: Option<String>,
            #[serde(rename = "Description")]
            description: Option<String>,
        }
        let rows: Vec<Row> =
            ps_json("Get-CimInstance Win32_Service | Select-Object Name,State,Description")?;
        Ok(rows
            .into_iter()
            .map(|r| {
                let state = match r.state.as_deref() {
                    Some("Running") => "running".to_string(),
                    Some("Stopped") => "stopped".to_string(),
                    Some(other) => other.to_lowercase(),
                    None => "unknown".to_string(),
                };
                ServiceInfo {
                    name: r.name,
                    state,
                    description: r.description.filter(|s| !s.is_empty()),
                }
            })
            .collect())
    }

    fn listening_ports(&self) -> ProbeResult<Vec<ListeningPort>> {
        #[derive(Deserialize)]
        struct Row {
            #[serde(rename = "LocalAddress")]
            address: Option<String>,
            #[serde(rename = "LocalPort")]
            port: u16,
            #[serde(rename = "OwningProcess")]
            pid: Option<u32>,
        }
        let rows: Vec<Row> = ps_json(
            "Get-NetTCPConnection -State Listen | Select-Object LocalAddress,LocalPort,OwningProcess",
        )?;
        Ok(rows
            .into_iter()
            .map(|r| ListeningPort {
                protocol: "tcp".into(),
                address: r.address.unwrap_or_default(),
                port: r.port,
                pid: r.pid,
            })
            .collect())
    }

    fn mounts(&self) -> ProbeResult<Vec<MountInfo>> {
        #[derive(Deserialize)]
        struct Row {
            #[serde(rename = "DeviceID")]
            device: Option<String>,
            #[serde(rename = "FileSystem")]
            fs: Option<String>,
            #[serde(rename = "Size")]
            size: Option<u64>,
            #[serde(rename = "FreeSpace")]
            free: Option<u64>,
        }
        let rows: Vec<Row> = ps_json(
            "Get-CimInstance Win32_LogicalDisk | Select-Object DeviceID,FileSystem,Size,FreeSpace",
        )?;
        Ok(rows
            .into_iter()
            .map(|r| {
                let device = r.device.unwrap_or_default();
                MountInfo {
                    source: device.clone(),
                    target: device,
                    fstype: r.fs.unwrap_or_else(|| "unknown".into()),
                    total_bytes: r.size,
                    available_bytes: r.free,
                }
            })
            .collect())
    }

    fn scheduled_tasks(&self) -> ProbeResult<Vec<ScheduledTask>> {
        #[derive(Deserialize)]
        struct Row {
            #[serde(rename = "TaskName")]
            name: Option<String>,
            #[serde(rename = "TaskPath")]
            path: Option<String>,
            #[serde(rename = "State")]
            state: Option<serde_json::Value>,
        }
        let rows: Vec<Row> =
            ps_json("Get-ScheduledTask | Select-Object TaskName,TaskPath,State")?;
        Ok(rows
            .into_iter()
            .map(|r| ScheduledTask {
                name: format!(
                    "{}{}",
                    r.path.unwrap_or_default(),
                    r.name.unwrap_or_default()
                ),
                schedule: r.state.map(|s| format!("state={s}")),
                command: None,
                source: "windows-task-scheduler".into(),
            })
            .collect())
    }
}
