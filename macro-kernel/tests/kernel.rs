//! Tests for the governing kernel: constraint loading, lawfulness verdicts,
//! receipt chain integrity, and the CLI end-to-end (read-only scan/judge).

use std::path::PathBuf;

use macro_kernel::constraints::{self, path_conflicts};
use macro_kernel::lawfulness::{self, CheckResult, Verdict};
use macro_kernel::receipts::{verify_chain, ReceiptWriter};
use macro_kernel::state::{
    OsInfo, ProcessInfo, ServiceInfo, StructuralState, STATE_SCHEMA_VERSION,
};
use macro_kernel::transitions::{CandidateTransition, TransitionKind};

fn synthetic_state() -> StructuralState {
    StructuralState {
        schema_version: STATE_SCHEMA_VERSION,
        captured_at: "2026-01-01T00:00:00Z".into(),
        os: OsInfo {
            family: "linux".into(),
            name: "Test Linux".into(),
            kernel_version: "6.0".into(),
            hostname: "testhost".into(),
            arch: "x86_64".into(),
        },
        processes: vec![
            ProcessInfo {
                pid: 1,
                ppid: Some(0),
                name: "systemd".into(),
                state: Some("S".into()),
                cmdline: None,
            },
            ProcessInfo {
                pid: 4242,
                ppid: Some(1),
                name: "some-user-tool".into(),
                state: Some("S".into()),
                cmdline: None,
            },
        ],
        services: vec![
            ServiceInfo {
                name: "sshd".into(),
                state: "running".into(),
                description: None,
            },
            ServiceInfo {
                name: "user-app".into(),
                state: "failed".into(),
                description: None,
            },
        ],
        listening_ports: vec![],
        mounts: vec![],
        scheduled_tasks: vec![],
        toolchains: vec![],
    }
}

fn transition(kind: TransitionKind, target: &str) -> CandidateTransition {
    CandidateTransition {
        id: format!("test-{}-{target}", kind.as_str()),
        kind,
        target: target.into(),
        description: "test transition".into(),
        declared_effects: vec![],
    }
}

#[test]
fn default_constraints_load_and_validate() {
    let set = constraints::load_or_default(None).expect("default constraints load");
    assert!(set.constraints.len() >= 4);
    let ids: Vec<&str> = set.constraints.iter().map(|c| c.id.as_str()).collect();
    assert!(ids.contains(&"protected-paths"));
    assert!(ids.contains(&"protected-processes"));
    assert!(ids.contains(&"protected-services"));
}

#[test]
fn path_conflict_normalizes_separators_and_case() {
    assert!(path_conflicts("C:/Windows", "c:\\windows\\system32\\drivers"));
    assert!(path_conflicts("/etc", "/etc/hosts"));
    // deleting an ancestor of a protected path also conflicts
    assert!(path_conflicts("/etc/ssh", "/etc"));
    assert!(!path_conflicts("/etc", "/etcetera"));
    assert!(!path_conflicts("/etc", "/home/user/file"));
}

#[test]
fn noop_observe_is_admissible() {
    let state = synthetic_state();
    let set = constraints::load_or_default(None).unwrap();
    let witness = lawfulness::judge(&state, &set, &transition(TransitionKind::NoopObserve, ""));
    assert_eq!(witness.verdict, Verdict::Admissible);
    assert_eq!(witness.snapshot_hash, state.content_hash());
}

#[test]
fn delete_protected_path_is_inadmissible() {
    let state = synthetic_state();
    let set = constraints::load_or_default(None).unwrap();
    let witness = lawfulness::judge(&state, &set, &transition(TransitionKind::DeletePath, "/etc/hosts"));
    assert_eq!(witness.verdict, Verdict::Inadmissible);
    assert!(witness
        .checks
        .iter()
        .any(|c| c.constraint_id == "protected-paths" && c.result == CheckResult::Violation));
}

#[test]
fn kill_pid_1_is_inadmissible() {
    let state = synthetic_state();
    let set = constraints::load_or_default(None).unwrap();
    let witness = lawfulness::judge(&state, &set, &transition(TransitionKind::KillProcess, "1"));
    assert_eq!(witness.verdict, Verdict::Inadmissible);
}

#[test]
fn kill_protected_process_by_snapshot_name_is_inadmissible() {
    let mut state = synthetic_state();
    // make sshd a process with a normal pid
    state.processes.push(ProcessInfo {
        pid: 900,
        ppid: Some(1),
        name: "sshd".into(),
        state: Some("S".into()),
        cmdline: None,
    });
    let set = constraints::load_or_default(None).unwrap();
    let witness = lawfulness::judge(&state, &set, &transition(TransitionKind::KillProcess, "900"));
    assert_eq!(witness.verdict, Verdict::Inadmissible);
    assert!(witness
        .checks
        .iter()
        .any(|c| c.constraint_id == "protected-processes" && c.result == CheckResult::Violation));
}

#[test]
fn kill_unobserved_pid_is_outside_the_boundary() {
    let state = synthetic_state();
    let set = constraints::load_or_default(None).unwrap();
    let witness = lawfulness::judge(&state, &set, &transition(TransitionKind::KillProcess, "99999"));
    assert_eq!(witness.verdict, Verdict::Inadmissible);
    assert!(witness
        .checks
        .iter()
        .any(|c| c.constraint_id == "boundary" && c.result == CheckResult::Violation));
}

#[test]
fn stop_unprotected_observed_service_requires_approval() {
    let state = synthetic_state();
    let set = constraints::load_or_default(None).unwrap();
    let witness = lawfulness::judge(&state, &set, &transition(TransitionKind::StopService, "user-app"));
    assert_eq!(witness.verdict, Verdict::RequiresApproval);
}

#[test]
fn stop_protected_service_is_inadmissible() {
    let state = synthetic_state();
    let set = constraints::load_or_default(None).unwrap();
    let witness = lawfulness::judge(&state, &set, &transition(TransitionKind::StopService, "sshd"));
    assert_eq!(witness.verdict, Verdict::Inadmissible);
}

#[test]
fn proposer_cites_failed_services() {
    let state = synthetic_state();
    let candidates = macro_kernel::transitions::propose(&state);
    assert!(candidates
        .iter()
        .any(|c| c.kind == TransitionKind::RestartService && c.target == "user-app"));
    // the rescan candidate is always present
    assert!(candidates.iter().any(|c| c.kind == TransitionKind::NoopObserve));
}

fn temp_home(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "macro-kernel-test-{tag}-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn receipt_chain_verifies_and_detects_tampering() {
    let home = temp_home("receipts");
    let mut writer = ReceiptWriter::create(&home, "testrun").unwrap();
    writer.emit("boundary_discovered", serde_json::json!({"a": 1})).unwrap();
    writer.emit("snapshot_captured", serde_json::json!({"b": 2})).unwrap();
    writer.emit("judgment", serde_json::json!({"c": 3})).unwrap();
    let path = writer.path().to_path_buf();

    let report = verify_chain(&path).unwrap();
    assert!(report.valid, "fresh chain must verify: {:?}", report.detail);
    assert_eq!(report.receipts, 3);

    // tamper with the middle receipt's body
    let content = std::fs::read_to_string(&path).unwrap();
    let tampered = content.replace("\"b\":2", "\"b\":20");
    assert_ne!(content, tampered, "tampering must actually change the file");
    std::fs::write(&path, tampered).unwrap();

    let report = verify_chain(&path).unwrap();
    assert!(!report.valid);
    assert_eq!(report.first_invalid_seq, Some(1));

    let _ = std::fs::remove_dir_all(&home);
}

#[test]
fn cli_end_to_end_scan_judge_receipts() {
    let home = temp_home("cli");
    let bin = env!("CARGO_BIN_EXE_mkernel");

    let run = |args: &[&str]| {
        std::process::Command::new(bin)
            .arg("--home")
            .arg(&home)
            .args(args)
            .output()
            .expect("mkernel runs")
    };

    // scan captures a snapshot
    let out = run(&["scan"]);
    assert!(out.status.success(), "scan failed: {}", String::from_utf8_lossy(&out.stderr));
    let snapshots: Vec<_> = std::fs::read_dir(home.join("snapshots")).unwrap().collect();
    assert_eq!(snapshots.len(), 1);

    // an admissible observation
    let spec = home.join("observe.json");
    std::fs::write(
        &spec,
        r#"{"id":"t","kind":"noop_observe","target":"","description":"d","declared_effects":[]}"#,
    )
    .unwrap();
    let out = run(&["judge", spec.to_str().unwrap()]);
    assert!(out.status.success());
    assert!(String::from_utf8_lossy(&out.stdout).contains("ADMISSIBLE"));

    // an inadmissible deletion exits non-zero
    let spec = home.join("delete.json");
    std::fs::write(
        &spec,
        r#"{"id":"t2","kind":"delete_path","target":"/etc","description":"d","declared_effects":[]}"#,
    )
    .unwrap();
    let out = run(&["judge", spec.to_str().unwrap()]);
    assert!(!out.status.success(), "inadmissible judgment must exit non-zero");
    assert!(String::from_utf8_lossy(&out.stdout).contains("INADMISSIBLE"));

    // transitions lists candidates without executing anything
    let out = run(&["transitions"]);
    assert!(out.status.success(), "transitions failed: {}", String::from_utf8_lossy(&out.stderr));
    assert!(String::from_utf8_lossy(&out.stdout).contains("observe-rescan"));

    // every receipt chain written by the above verifies
    for entry in std::fs::read_dir(home.join("receipts")).unwrap().flatten() {
        let out = run(&["receipts", "--file", entry.path().to_str().unwrap()]);
        assert!(
            out.status.success(),
            "receipt chain {} failed to verify",
            entry.path().display()
        );
    }

    let _ = std::fs::remove_dir_all(&home);
}
