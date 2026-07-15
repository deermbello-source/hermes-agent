//! Linux inspection backend. Reads native kernel interfaces (/proc, /etc)
//! directly and falls back to well-known read-only commands (systemctl,
//! crontab) for subsystems /proc does not expose.

use std::fs;
use std::path::Path;

use super::inspect::{run_capture, Inspector, ProbeResult};
use super::{ListeningPort, MountInfo, OsInfo, ProcessInfo, ScheduledTask, ServiceInfo};

pub struct LinuxInspector;

impl Inspector for LinuxInspector {
    fn os_info(&self) -> ProbeResult<OsInfo> {
        let name = fs::read_to_string("/etc/os-release")
            .ok()
            .and_then(|content| {
                content.lines().find_map(|line| {
                    line.strip_prefix("PRETTY_NAME=")
                        .map(|v| v.trim_matches('"').to_string())
                })
            })
            .unwrap_or_else(|| "Linux".to_string());
        let kernel_version = fs::read_to_string("/proc/sys/kernel/osrelease")
            .map(|s| s.trim().to_string())
            .unwrap_or_else(|_| "unknown".to_string());
        let hostname = fs::read_to_string("/proc/sys/kernel/hostname")
            .map(|s| s.trim().to_string())
            .unwrap_or_else(|_| "unknown".to_string());
        Ok(OsInfo {
            family: "linux".into(),
            name,
            kernel_version,
            hostname,
            arch: std::env::consts::ARCH.to_string(),
        })
    }

    fn processes(&self) -> ProbeResult<Vec<ProcessInfo>> {
        let mut out = Vec::new();
        let entries = fs::read_dir("/proc").map_err(|e| format!("cannot read /proc: {e}"))?;
        for entry in entries.flatten() {
            let file_name = entry.file_name();
            let Some(pid) = file_name.to_str().and_then(|s| s.parse::<u32>().ok()) else {
                continue;
            };
            let proc_dir = entry.path();
            let Some((name, state, ppid)) = read_stat(&proc_dir) else {
                continue; // process exited mid-scan
            };
            let cmdline = fs::read(proc_dir.join("cmdline"))
                .ok()
                .map(|bytes| {
                    bytes
                        .split(|b| *b == 0)
                        .filter(|part| !part.is_empty())
                        .map(|part| String::from_utf8_lossy(part).into_owned())
                        .collect::<Vec<_>>()
                        .join(" ")
                })
                .filter(|s| !s.is_empty());
            out.push(ProcessInfo {
                pid,
                ppid: Some(ppid),
                name,
                state: Some(state),
                cmdline,
            });
        }
        out.sort_by_key(|p| p.pid);
        Ok(out)
    }

    fn services(&self) -> ProbeResult<Vec<ServiceInfo>> {
        let stdout = run_capture(
            "systemctl",
            &[
                "list-units",
                "--type=service",
                "--all",
                "--no-pager",
                "--no-legend",
                "--plain",
            ],
        )?;
        let mut out = Vec::new();
        for line in stdout.lines() {
            // Columns: UNIT LOAD ACTIVE SUB DESCRIPTION...
            let mut parts = line.split_whitespace();
            let (Some(unit), Some(_load), Some(active), Some(_sub)) =
                (parts.next(), parts.next(), parts.next(), parts.next())
            else {
                continue;
            };
            let description = parts.collect::<Vec<_>>().join(" ");
            let state = match active {
                "active" => "running",
                "inactive" => "stopped",
                "failed" => "failed",
                other => other,
            };
            out.push(ServiceInfo {
                name: unit.trim_end_matches(".service").to_string(),
                state: state.to_string(),
                description: (!description.is_empty()).then_some(description),
            });
        }
        Ok(out)
    }

    fn listening_ports(&self) -> ProbeResult<Vec<ListeningPort>> {
        let mut out = Vec::new();
        for (file, proto) in [("/proc/net/tcp", "tcp"), ("/proc/net/tcp6", "tcp6")] {
            let Ok(content) = fs::read_to_string(file) else {
                continue;
            };
            for line in content.lines().skip(1) {
                let fields: Vec<&str> = line.split_whitespace().collect();
                // fields[1] = local_address (hex ip:port), fields[3] = state
                if fields.len() < 4 || fields[3] != "0A" {
                    continue; // 0A = TCP_LISTEN
                }
                let Some((addr_hex, port_hex)) = fields[1].split_once(':') else {
                    continue;
                };
                let Ok(port) = u16::from_str_radix(port_hex, 16) else {
                    continue;
                };
                out.push(ListeningPort {
                    protocol: proto.to_string(),
                    address: decode_hex_addr(addr_hex),
                    port,
                    pid: None,
                });
            }
        }
        out.sort_by(|a, b| (a.port, &a.protocol).cmp(&(b.port, &b.protocol)));
        out.dedup_by(|a, b| a.port == b.port && a.protocol == b.protocol && a.address == b.address);
        Ok(out)
    }

    fn mounts(&self) -> ProbeResult<Vec<MountInfo>> {
        let content =
            fs::read_to_string("/proc/mounts").map_err(|e| format!("cannot read /proc/mounts: {e}"))?;
        let mut out = Vec::new();
        for line in content.lines() {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() < 3 {
                continue;
            }
            // Skip the noisy virtual filesystems; keep real and overlay mounts.
            if matches!(
                fields[2],
                "proc" | "sysfs" | "cgroup" | "cgroup2" | "devpts" | "mqueue" | "securityfs"
                    | "debugfs" | "tracefs" | "pstore" | "bpf" | "autofs" | "fusectl"
                    | "configfs" | "binfmt_misc" | "hugetlbfs" | "rpc_pipefs"
            ) {
                continue;
            }
            out.push(MountInfo {
                source: fields[0].to_string(),
                target: fields[1].to_string(),
                fstype: fields[2].to_string(),
                total_bytes: None,
                available_bytes: None,
            });
        }
        Ok(out)
    }

    fn scheduled_tasks(&self) -> ProbeResult<Vec<ScheduledTask>> {
        let mut out = Vec::new();

        if let Ok(stdout) = run_capture("crontab", &["-l"]) {
            out.extend(parse_crontab(&stdout, "crontab", false));
        }
        if let Ok(content) = fs::read_to_string("/etc/crontab") {
            out.extend(parse_crontab(&content, "/etc/crontab", true));
        }
        if let Ok(entries) = fs::read_dir("/etc/cron.d") {
            for entry in entries.flatten() {
                if let Ok(content) = fs::read_to_string(entry.path()) {
                    out.extend(parse_crontab(
                        &content,
                        &entry.path().display().to_string(),
                        true,
                    ));
                }
            }
        }
        if let Ok(stdout) = run_capture(
            "systemctl",
            &["list-timers", "--all", "--no-pager", "--no-legend"],
        ) {
            for line in stdout.lines() {
                // The UNIT column is the first token ending in ".timer".
                if let Some(unit) = line.split_whitespace().find(|t| t.ends_with(".timer")) {
                    out.push(ScheduledTask {
                        name: unit.to_string(),
                        schedule: None,
                        command: None,
                        source: "systemd-timer".into(),
                    });
                }
            }
        }
        Ok(out)
    }
}

/// Parse /proc/<pid>/stat, which embeds the process name in parentheses
/// (the name itself may contain spaces or parens, so split on the LAST ')').
fn read_stat(proc_dir: &Path) -> Option<(String, String, u32)> {
    let stat = fs::read_to_string(proc_dir.join("stat")).ok()?;
    let open = stat.find('(')?;
    let close = stat.rfind(')')?;
    let name = stat.get(open + 1..close)?.to_string();
    let rest: Vec<&str> = stat.get(close + 1..)?.split_whitespace().collect();
    // rest[0] = state, rest[1] = ppid
    let state = rest.first()?.to_string();
    let ppid = rest.get(1)?.parse().ok()?;
    Some((name, state, ppid))
}

/// Decode a /proc/net/tcp hex address (little-endian per 32-bit group).
fn decode_hex_addr(hex: &str) -> String {
    if hex.len() == 8 {
        let Ok(v) = u32::from_str_radix(hex, 16) else {
            return hex.to_string();
        };
        let b = v.to_le_bytes();
        format!("{}.{}.{}.{}", b[0], b[1], b[2], b[3])
    } else if hex.len() == 32 {
        // IPv6: report the common cases readably, otherwise raw hex.
        if hex == "00000000000000000000000000000000" {
            "::".to_string()
        } else if hex.ends_with("01000000") && hex.starts_with("000000000000000000000000") {
            "::1".to_string()
        } else {
            hex.to_string()
        }
    } else {
        hex.to_string()
    }
}

fn parse_crontab(content: &str, source: &str, has_user_field: bool) -> Vec<ScheduledTask> {
    let mut out = Vec::new();
    for line in content.lines() {
        let line = line.trim();
        // Real entries start with a minute field or an @shortcut; this also
        // drops comments and VAR=value lines.
        if !line.starts_with(|c: char| c.is_ascii_digit() || c == '*' || c == '@') {
            continue;
        }
        let fields: Vec<&str> = line.split_whitespace().collect();
        let (schedule_len, min_fields) = if line.starts_with('@') { (1, 2) } else { (5, 6) };
        let command_start = schedule_len + usize::from(has_user_field);
        if fields.len() < min_fields + usize::from(has_user_field) {
            continue;
        }
        let schedule = fields[..schedule_len].join(" ");
        let command = fields[command_start..].join(" ");
        out.push(ScheduledTask {
            name: format!("{source}:{command}"),
            schedule: Some(schedule),
            command: Some(command),
            source: source.to_string(),
        });
    }
    out
}
