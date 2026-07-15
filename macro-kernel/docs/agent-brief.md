# Macro Kernel Agent Brief

## Objective

I want you to build a local user-space governing kernel for Windows.

My goal is to create a launchable system that reads my PC as a bounded structure, models its current state, proposes candidate transitions, and blocks execution unless the transition is lawful.

I do not want an AI that just acts on my computer. I want a bounded governing kernel that reads my computer, understands possible transitions, and only permits lawful ones.

## Core Principle

Nothing is allowed to become expression or action unless it preserves the structure that produced it.

This system is not the machine itself and it must not freely mutate the machine. It sits between observed machine state and possible transition. Its job is to govern transitions, not to overwrite reality.

## Hard Constraints

- Read-only by default
- Do not mutate my machine automatically
- Do not build a kernel driver
- Do not execute autonomously
- Any action must require my explicit approval
- Every read, judgment, and action must emit filesystem receipts
- Natural language explanations are secondary; core state and rules must be structured
- Treat the PC as the bounded domain, but do not confuse the governing kernel with the PC itself

## Required Behavior

The system must:

1. Read my computer as a bounded domain.
2. Build a structured state model from what it reads.
3. Separate observation from action.
4. Represent candidate transitions before any execution happens.
5. Evaluate whether those transitions are lawful.
6. Block unlawful transitions.
7. Require explicit approval before any lawful transition is executed.
8. Write receipts for observation, judgment, approval, and execution.

## Architecture Direction

I want the build organized around these components:

1. Boundary discovery
Determine what counts as the governed machine domain for the current run.

2. Structured state model
Represent the current machine state as structured data rather than free text.

3. Constraint engine
Represent what must remain preserved across lawful transitions.

4. Candidate transition engine
Generate possible next actions or state changes without executing them.

5. Lawfulness evaluator
Determine whether a proposed transition preserves the required structure.

6. Projection layer
Provide a CLI first. A UI can come later.

7. Receipt and evidence spine
Write durable receipts for every meaningful step.

## First Milestone

Build a local CLI that:

- scans my machine
- builds a bounded state snapshot
- lists possible transitions
- marks each transition as admissible or inadmissible
- does not execute any transition yet

The first milestone is successful only if the system can inspect, model, and judge without mutating the PC.

## Technical Preferences

For the first implementation:

- Prefer a user-space process over anything low-level
- Prefer a Rust core for the governing engine
- Use native Windows inspection paths where possible
- Use filesystem receipts first
- Keep the system local
- Keep the initial surface CLI-only

Optional helper layers are acceptable, but the governing logic itself should not depend on natural language as its final medium of truth.

## What This Is Not

This is not:

- an autonomous desktop agent
- a general assistant with machine control
- a kernel-mode driver
- a chatbot wrapper over shell commands
- an output filter applied after generation

## What This Is

This is:

- a bounded local governing layer
- a machine-reading and transition-governing process
- a system that sits between observed machine state and possible machine action
- a foundation for solving the current AI drift problem in a structurally governed way

## Implementation Rule

Do not begin from output generation and then add controls later.

Begin from:

```text
bounded intake -> structured state -> candidate transition -> lawfulness check -> explicit approval -> execution -> receipt
```

## Deliverable Expectations

When implementing, I want:

- clear local structure
- minimal moving parts at first
- explicit receipts on disk
- no hidden autonomous behavior
- a system I can launch, inspect, and trust step by step

## Final Instruction

Build the smallest real version of this first.

Do not inflate scope. Do not jump to full autonomy. Do not treat “reading the machine” as permission to change the machine.

Start by building the governing layer that can inspect, model, and judge transitions locally. Only after that exists should execution be added behind an explicit approval gate.
