//! mkernel — a user-space governing kernel (milestone 1: read-only).
//!
//! Pipeline: bounded intake -> structured state -> candidate transition
//! -> lawfulness check -> (approval + execution: NOT in this milestone)
//! Every step emits hash-chained receipts. The only writes this binary
//! performs are into its own kernel home (snapshots + receipts).

use macro_kernel::{boundary, constraints, lawfulness, receipts, state, transitions};

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Parser, Subcommand};

use boundary::Boundary;
use lawfulness::Verdict;
use receipts::ReceiptWriter;
use state::StructuralState;

#[derive(Parser)]
#[command(
    name = "mkernel",
    version,
    about = "A user-space governing kernel: reads the machine as a bounded structure, \
             models its state, proposes candidate transitions, and judges lawfulness. \
             Milestone 1 is strictly read-only: there is no execute command."
)]
struct Cli {
    /// Kernel home directory (snapshots + receipts). Defaults to
    /// $MACRO_KERNEL_HOME, then ~/.macro-kernel.
    #[arg(long, global = true)]
    home: Option<PathBuf>,

    /// Constraints file (TOML). Defaults to the built-in constraint set.
    #[arg(long, global = true)]
    constraints: Option<PathBuf>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Discover the boundary and capture a structural state snapshot.
    Scan,
    /// Show the latest snapshot summary, or diff two snapshot files.
    Snapshot {
        /// Diff: older snapshot file.
        #[arg(long, requires = "new")]
        old: Option<PathBuf>,
        /// Diff: newer snapshot file.
        #[arg(long, requires = "old")]
        new: Option<PathBuf>,
    },
    /// Propose candidate transitions from the latest snapshot and judge each.
    Transitions,
    /// Judge a user-supplied transition spec (JSON) against the latest snapshot.
    Judge { spec: PathBuf },
    /// Verify the hash chain of a receipts file (default: the most recent run).
    Receipts {
        #[arg(long)]
        file: Option<PathBuf>,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli) -> Result<(), String> {
    let home = boundary::resolve_home(cli.home)?;
    let constraint_set = constraints::load_or_default(cli.constraints.as_deref())?;

    match cli.command {
        Command::Scan => cmd_scan(&home),
        Command::Snapshot { old, new } => cmd_snapshot(&home, old, new),
        Command::Transitions => cmd_transitions(&home, &constraint_set),
        Command::Judge { spec } => cmd_judge(&home, &constraint_set, &spec),
        Command::Receipts { file } => cmd_receipts(&home, file),
    }
}

fn cmd_scan(home: &Path) -> Result<(), String> {
    let run_id = boundary::new_run_id();
    let mut receipts = ReceiptWriter::create(home, &run_id)?;

    let inspector = state::inspect::platform_inspector();
    let (snapshot, probes) = state::inspect::capture(inspector.as_ref());

    let boundary = Boundary::new(
        run_id.clone(),
        snapshot.os.hostname.clone(),
        snapshot.os.family.clone(),
        probes,
    );
    receipts.emit("boundary_discovered", serde_json::to_value(&boundary).unwrap())?;

    let snapshot_hash = snapshot.content_hash();
    let dir = boundary::snapshots_dir(home);
    std::fs::create_dir_all(&dir).map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
    let snapshot_path = dir.join(format!("{run_id}.json"));
    let json = serde_json::to_string_pretty(&snapshot).map_err(|e| e.to_string())?;
    std::fs::write(&snapshot_path, json)
        .map_err(|e| format!("cannot write {}: {e}", snapshot_path.display()))?;

    receipts.emit(
        "snapshot_captured",
        serde_json::json!({
            "run_id": run_id,
            "snapshot_path": snapshot_path.display().to_string(),
            "snapshot_hash": snapshot_hash,
            "counts": {
                "processes": snapshot.processes.len(),
                "services": snapshot.services.len(),
                "listening_ports": snapshot.listening_ports.len(),
                "mounts": snapshot.mounts.len(),
                "scheduled_tasks": snapshot.scheduled_tasks.len(),
                "toolchains": snapshot.toolchains.len(),
            }
        }),
    )?;

    println!("run:       {run_id}");
    println!("host:      {} ({})", snapshot.os.hostname, snapshot.os.name);
    println!("snapshot:  {}", snapshot_path.display());
    println!("hash:      {snapshot_hash}");
    println!("receipts:  {}", receipts.path().display());
    println!();
    println!("boundary probes:");
    for probe in &boundary.probes {
        match (&probe.ok, &probe.detail) {
            (true, _) => println!("  [ok]      {}", probe.name),
            (false, Some(d)) => println!("  [outside] {} ({d})", probe.name),
            (false, None) => println!("  [outside] {}", probe.name),
        }
    }
    println!();
    println!(
        "state: {} processes, {} services, {} listening ports, {} mounts, {} scheduled tasks, {} toolchains",
        snapshot.processes.len(),
        snapshot.services.len(),
        snapshot.listening_ports.len(),
        snapshot.mounts.len(),
        snapshot.scheduled_tasks.len(),
        snapshot.toolchains.len(),
    );
    Ok(())
}

fn load_latest_snapshot(home: &Path) -> Result<(PathBuf, StructuralState), String> {
    let path = boundary::latest_snapshot_path(home)?
        .ok_or("no snapshot found — run `mkernel scan` first")?;
    let content =
        std::fs::read_to_string(&path).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    let snapshot: StructuralState =
        serde_json::from_str(&content).map_err(|e| format!("invalid snapshot {}: {e}", path.display()))?;
    Ok((path, snapshot))
}

fn cmd_snapshot(home: &Path, old: Option<PathBuf>, new: Option<PathBuf>) -> Result<(), String> {
    if let (Some(old), Some(new)) = (old, new) {
        return diff_snapshots(&old, &new);
    }
    let (path, snapshot) = load_latest_snapshot(home)?;

    let run_id = boundary::new_run_id();
    let mut receipts = ReceiptWriter::create(home, &run_id)?;
    receipts.emit(
        "projection",
        serde_json::json!({
            "command": "snapshot",
            "snapshot_path": path.display().to_string(),
            "snapshot_hash": snapshot.content_hash(),
        }),
    )?;

    println!("snapshot:  {}", path.display());
    println!("captured:  {}", snapshot.captured_at);
    println!("host:      {} ({})", snapshot.os.hostname, snapshot.os.name);
    println!("kernel:    {} / {}", snapshot.os.family, snapshot.os.kernel_version);
    println!();
    println!("processes ({}):", snapshot.processes.len());
    for p in snapshot.processes.iter().take(15) {
        println!("  {:>7}  {}", p.pid, p.name);
    }
    if snapshot.processes.len() > 15 {
        println!("  ... and {} more", snapshot.processes.len() - 15);
    }
    println!();
    println!("listening ports ({}):", snapshot.listening_ports.len());
    for port in &snapshot.listening_ports {
        println!("  {}/{} on {}", port.port, port.protocol, port.address);
    }
    println!();
    println!("toolchains ({}):", snapshot.toolchains.len());
    for t in &snapshot.toolchains {
        println!(
            "  {:<12} {}",
            t.name,
            t.version.as_deref().unwrap_or("(version unknown)")
        );
    }
    Ok(())
}

fn diff_snapshots(old_path: &Path, new_path: &Path) -> Result<(), String> {
    let load = |p: &Path| -> Result<StructuralState, String> {
        let content =
            std::fs::read_to_string(p).map_err(|e| format!("cannot read {}: {e}", p.display()))?;
        serde_json::from_str(&content).map_err(|e| format!("invalid snapshot {}: {e}", p.display()))
    };
    let old = load(old_path)?;
    let new = load(new_path)?;

    fn diff_names(label: &str, old: Vec<String>, new: Vec<String>) {
        let old_set: std::collections::BTreeSet<_> = old.into_iter().collect();
        let new_set: std::collections::BTreeSet<_> = new.into_iter().collect();
        let added: Vec<_> = new_set.difference(&old_set).cloned().collect();
        let removed: Vec<_> = old_set.difference(&new_set).cloned().collect();
        println!("{label}: +{} -{}", added.len(), removed.len());
        for a in added.iter().take(20) {
            println!("  + {a}");
        }
        for r in removed.iter().take(20) {
            println!("  - {r}");
        }
    }

    println!("diff {} -> {}", old_path.display(), new_path.display());
    println!();
    diff_names(
        "processes",
        old.processes.iter().map(|p| format!("{} ({})", p.name, p.pid)).collect(),
        new.processes.iter().map(|p| format!("{} ({})", p.name, p.pid)).collect(),
    );
    diff_names(
        "services",
        old.services.iter().map(|s| format!("{} [{}]", s.name, s.state)).collect(),
        new.services.iter().map(|s| format!("{} [{}]", s.name, s.state)).collect(),
    );
    diff_names(
        "listening_ports",
        old.listening_ports.iter().map(|p| format!("{}/{}", p.port, p.protocol)).collect(),
        new.listening_ports.iter().map(|p| format!("{}/{}", p.port, p.protocol)).collect(),
    );
    Ok(())
}

fn verdict_tag(verdict: Verdict) -> &'static str {
    match verdict {
        Verdict::Admissible => "ADMISSIBLE",
        Verdict::RequiresApproval => "REQUIRES-APPROVAL",
        Verdict::Inadmissible => "INADMISSIBLE",
    }
}

fn cmd_transitions(home: &Path, constraint_set: &constraints::ConstraintSet) -> Result<(), String> {
    let (snapshot_path, snapshot) = load_latest_snapshot(home)?;
    let run_id = boundary::new_run_id();
    let mut receipts = ReceiptWriter::create(home, &run_id)?;

    let candidates = transitions::propose(&snapshot);
    receipts.emit(
        "candidates_proposed",
        serde_json::json!({
            "snapshot_path": snapshot_path.display().to_string(),
            "snapshot_hash": snapshot.content_hash(),
            "candidates": candidates,
        }),
    )?;

    println!(
        "judging {} candidate transition(s) against {}",
        candidates.len(),
        snapshot_path.display()
    );
    println!("(milestone 1: judgments only — nothing is executed)");
    println!();
    for candidate in &candidates {
        let witness = lawfulness::judge(&snapshot, constraint_set, candidate);
        receipts.emit("judgment", serde_json::to_value(&witness).unwrap())?;
        println!("[{}] {}", verdict_tag(witness.verdict), candidate.id);
        println!("    kind:   {}", candidate.kind.as_str());
        if !candidate.target.is_empty() {
            println!("    target: {}", candidate.target);
        }
        println!("    why:    {}", candidate.description);
        println!("    verdict: {}", witness.verdict_reason);
        println!();
    }
    println!("receipts: {}", receipts.path().display());
    Ok(())
}

fn cmd_judge(
    home: &Path,
    constraint_set: &constraints::ConstraintSet,
    spec: &Path,
) -> Result<(), String> {
    let (snapshot_path, snapshot) = load_latest_snapshot(home)?;
    let transition = transitions::CandidateTransition::load(spec)?;

    let run_id = boundary::new_run_id();
    let mut receipts = ReceiptWriter::create(home, &run_id)?;

    let witness = lawfulness::judge(&snapshot, constraint_set, &transition);
    receipts.emit("judgment", serde_json::to_value(&witness).unwrap())?;

    println!("transition: {} ({})", transition.id, transition.kind.as_str());
    if !transition.target.is_empty() {
        println!("target:     {}", transition.target);
    }
    println!("snapshot:   {}", snapshot_path.display());
    println!();
    println!("checks:");
    for check in &witness.checks {
        let tag = match check.result {
            lawfulness::CheckResult::Pass => "pass",
            lawfulness::CheckResult::Violation => "VIOLATION",
            lawfulness::CheckResult::NotApplicable => "n/a",
        };
        match &check.detail {
            Some(d) => println!("  [{tag:<9}] {} — {d}", check.constraint_id),
            None => println!("  [{tag:<9}] {}", check.constraint_id),
        }
    }
    println!();
    println!("verdict: {} — {}", verdict_tag(witness.verdict), witness.verdict_reason);
    println!("witness receipt: {}", receipts.path().display());

    if witness.verdict == Verdict::Inadmissible {
        return Err("transition is inadmissible".into());
    }
    Ok(())
}

fn cmd_receipts(home: &Path, file: Option<PathBuf>) -> Result<(), String> {
    let path = match file {
        Some(p) => p,
        None => {
            let dir = home.join("receipts");
            let mut entries: Vec<PathBuf> = std::fs::read_dir(&dir)
                .map_err(|e| format!("cannot read {}: {e}", dir.display()))?
                .flatten()
                .map(|e| e.path())
                .filter(|p| p.extension().is_some_and(|ext| ext == "jsonl"))
                .collect();
            entries.sort();
            entries.pop().ok_or("no receipt files found")?
        }
    };
    let report = receipts::verify_chain(&path)?;
    println!("file:     {}", path.display());
    println!("receipts: {}", report.receipts);
    if report.valid {
        println!("chain:    VALID");
        Ok(())
    } else {
        println!(
            "chain:    BROKEN at seq {:?}: {}",
            report.first_invalid_seq,
            report.detail.as_deref().unwrap_or("unknown")
        );
        Err("receipt chain verification failed".into())
    }
}
