# macro-kernel

A **user-space governing kernel**: a local system that reads your machine as a
bounded structure, models its current state, proposes candidate transitions,
and judges whether each transition is lawful — **without executing anything**.

> Nothing is allowed to become expression or action unless it preserves the
> structure that produced it.

The kernel is not the machine and it never freely mutates the machine. It sits
between observed machine state and possible transition. Its job is to govern
transitions, not to overwrite reality.

Design documents: [docs/agent-brief.md](docs/agent-brief.md) (build brief) and
[docs/foundation-spec.md](docs/foundation-spec.md) (the structural-preservation
foundation this implements).

## Milestone 1 status: read-only, by design

This milestone implements the governing layer only:

```text
bounded intake -> structured state -> candidate transition -> lawfulness check
                                                                    |
                              (approval gate + execution: NOT built yet,
                               deliberately — see the brief's final instruction)
```

There is **no execute command**. The only writes the binary performs are into
its own kernel home (snapshots and receipts). A transition judged
`REQUIRES-APPROVAL` cannot run because no approval gate exists yet; that is the
point of this milestone.

## Build and run

```bash
cd macro-kernel
cargo build --release
./target/release/mkernel scan
```

Works on Linux and Windows from the same source. On Windows the kernel
inspects via read-only PowerShell/CIM queries (`Get-CimInstance`,
`Get-NetTCPConnection`, `Get-ScheduledTask`); on Linux it reads `/proc`
directly plus `systemctl`/`crontab`. A probe that cannot run (e.g. no systemd)
is reported as `[outside]` the boundary — the kernel never pretends to govern
what it could not read.

## Commands

| Command | What it does |
|---------|--------------|
| `mkernel scan` | Discover the boundary, capture a structural state snapshot, emit receipts. |
| `mkernel snapshot` | Show the latest snapshot summary. |
| `mkernel snapshot --old A.json --new B.json` | Structural diff between two snapshots. |
| `mkernel transitions` | Propose candidate transitions from observed facts and judge each one. |
| `mkernel judge spec.json` | Judge a user-supplied transition spec; exits non-zero if inadmissible. |
| `mkernel receipts [--file F]` | Verify the hash chain of a receipt file. |

Global flags: `--home <dir>` (kernel home, default `~/.macro-kernel`, or
`MACRO_KERNEL_HOME`) and `--constraints <file.toml>` (default: the built-in
set, also shipped as [constraints/default.toml](constraints/default.toml)).

Example transition specs to try live in [examples/](examples/):

```bash
./target/release/mkernel judge examples/observe.json               # ADMISSIBLE
./target/release/mkernel judge examples/delete-protected-path.json # INADMISSIBLE
./target/release/mkernel judge examples/kill-pid-1.json            # INADMISSIBLE
```

## The three verdicts

- **ADMISSIBLE** — non-mutating and violates no constraint.
- **REQUIRES-APPROVAL** — lawful under the constraint set, but mutating.
  Execution would require explicit approval; no approval gate exists in
  milestone 1, so it cannot run.
- **INADMISSIBLE** — violates a constraint, or targets something outside the
  observed boundary (the kernel refuses to judge what it never observed).

## The preservation witness

Every judgment produces a `PreservationWitness`: a structured record binding
the verdict to the sha256 of the **exact snapshot**, the **exact constraint
set**, and the **exact transition** it was made from, with per-constraint
check results. The witness is evidence that the judgment happened under the
structure it claims — not narration after the fact.

## The receipt spine

Every meaningful step (boundary discovery, snapshot capture, candidate
proposal, judgment, projection) appends a receipt to
`<home>/receipts/<run-id>.jsonl`:

```json
{"seq":0,"timestamp":"...","kind":"judgment","payload_hash":"...","prev_hash":"...","hash":"...","body":{...}}
```

Receipts are hash-chained — each record commits to the previous record's
hash — so any later edit, deletion, or reordering is detected by
`mkernel receipts`.

## Constraints

Constraints are structured data (TOML), not prose. Four rule kinds exist
today: `forbid_kinds`, `protect_paths`, `protect_processes`,
`protect_services`. Copy `constraints/default.toml`, edit it, and pass it with
`--constraints`. Every witness records the hash of the constraint set it was
judged under, so changing the constraints visibly changes the identity of the
governing structure.

## What this is not

- an autonomous desktop agent
- a general assistant with machine control
- a kernel-mode driver
- a chatbot wrapper over shell commands
- an output filter applied after generation

## Roadmap

1. **Milestone 2 — approval gate:** an explicit, receipted approval step for
   `REQUIRES-APPROVAL` transitions; still no autonomous execution.
2. **Milestone 3 — gated executor:** execution of an approved transition,
   licensed only by a valid preservation witness plus a recorded approval,
   emitting an execution receipt that references both.

## Development

```bash
cargo test          # 12 tests: constraints, verdicts, receipt chain, CLI end-to-end
cargo clippy --all-targets
```
