# Structural Preservation Foundation

## Status

Draft foundation specification for a governed expression system.

This document does not define a product surface or repository API. It defines the meta-structure that must exist before a governed runtime can claim that any expression is lawful.

## Purpose

Modern language systems drift because expression is usually treated as primary and governance is applied afterward. This specification reverses that order.

The governing principle is:

> Nothing is allowed to become expression unless it preserves the structure that produced it.

This is not a policy slogan. It is a structural requirement. If preservation is not established, expression is not merely "bad" or "disallowed"; it is inadmissible.

## Problem Statement

Most systems are organized like this:

```text
model -> output -> evaluation -> correction
```

This organization permits drift because the system is allowed to generate first and be judged later.

The required organization is:

```text
boundary -> constraints -> state -> lawful transition -> expression
```

In this order, expression is a downstream event licensed by a prior structural relation.

## Core Definitions

### Boundary

The boundary defines what belongs to the governed object and what does not.

Boundary is the minimal closure of:

- governed elements
- governed relations
- admissible inputs
- admissible outputs
- external disturbances

The boundary is not a container metaphor. It is the domain over which preservation claims are meaningful. Without a boundary, constraints leak into abstraction and cannot be tested.

### Constraint

A constraint is a rule on allowable transformations of the bounded structure.

Constraints are not decorations attached to state. Constraints are constitutive of state because they determine what may emerge, what is excluded, and what changes preserve identity.

If constraints change, the identity of the governed structure changes even if surface contents appear continuous.

### State

A state is the current constrained structure inside a defined boundary, sufficient to determine lawful next transformation and admissible expression.

Equivalent formulation:

> A state is the smallest preserved structure that constrains what may happen next.

State is therefore not "everything currently true." It is the least bounded relational structure that must remain intact for the next lawful step to still belong to the same system.

State minimally includes:

- bounded structure
- active constraints
- current degrees of freedom
- admissible next transformations

### Lawful Transition

A lawful transition is a change inside the boundary that preserves the defining constraints of the state.

The important point is not that a transition produces a desirable outcome. The important point is that the transition carries the source structure forward without violating the conditions that made the source structure what it was.

### Expression

Expression is an output crossing the boundary that is licensed by a lawful transition.

Expression is not primary. Expression is not an independent object awaiting downstream evaluation. Expression is a derived artifact whose admissibility depends on prior preservation.

## Drift

Drift is not merely lower quality output.

Drift occurs when expression preserves surface continuity while the constraint structure that generated it has changed.

Equivalent formulation:

> Outputs continue crossing the boundary, but the boundary-defining constraints were not preserved in the system that produced them.

This definition matters because it shifts the problem from performance judgment to identity failure.

## Primitive Gap

The framework above is necessary, but it is still meta-structure unless the system defines the primitive preservation relation itself.

The unresolved kernel question is:

> What exact relation must hold between a source structure and a transformed structure for the source to be preserved through the transformation?

Until that relation is defined, the framework remains an interpretive scaffold.

## Proposed Primitive

The first-class primitive should be a preservation relation:

```text
preserves(source_structure, transformed_structure)
```

or, more formally:

```text
PreservationWitness : SourceStructure -> TransformedStructure -> Prop
```

This primitive is more fundamental than policy labels such as allow, block, approve, or receipt-present. Those may still exist in an implementation, but they are downstream artifacts. They cannot serve as the foundation.

## Derived Structure From the Primitive

Once the preservation relation exists, the rest of the ontology becomes local and testable:

- boundary: the domain over which the preservation relation ranges
- constraints: the conditions required for preservation to hold
- state: the structure available to be preserved
- lawful transition: a transformation carrying a preservation witness
- expression: a projection permitted only from a witnessed transformation

This is the point where governance stops being interpretation and becomes structure.

## Minimal Conceptual Types

The following types are sufficient for a first kernel draft:

```text
Boundary
ConstraintSet
StructuralState
LawfulTransition
PreservationWitness
AdmissibleExpression
```

Suggested meanings:

- `Boundary`: specifies the governed domain
- `ConstraintSet`: specifies the allowable transformation conditions within that domain
- `StructuralState`: the present constrained structure
- `LawfulTransition`: a candidate change of `StructuralState`
- `PreservationWitness`: evidence that the transition preserves the required structure
- `AdmissibleExpression`: an externalized artifact licensed by the witnessed transition

## Ordering Constraint

The system must respect the following dependency order:

```text
Boundary
  -> what counts as inside

ConstraintSet
  -> what changes are allowed inside that boundary

StructuralState
  -> the current bounded structure under those constraints

LawfulTransition
  -> a bounded change that preserves the constraints

AdmissibleExpression
  -> a boundary crossing licensed by that lawful transition
```

Any design that begins from output and moves backward is structurally secondary.

## Design Consequences

If this foundation is taken seriously, several common patterns become invalid as first principles:

- Output scoring cannot be the primary governance mechanism.
- Alignment labels cannot substitute for preservation proofs.
- Surface continuity cannot be used as evidence of identity continuity.
- Policy text cannot stand in for a structural witness.
- A system cannot claim governed expression merely because it logged receipts after generation.

Receipts and runtime evidence remain useful, but only if they certify the preservation relation rather than narrate decisions after the fact.

## Professional Use

This document should be used as:

- a foundation note before implementation
- a design constraint for kernel work
- a review lens for policy and runtime proposals
- a rejection criterion for systems that govern outputs but not their generative structure

This document should not be mistaken for:

- a complete formal proof
- a complete type system
- a runtime protocol
- a product spec

## Next Formalization Step

The next useful move is not more vocabulary expansion. The next useful move is to define, in formal terms, the preservation relation itself.

Concretely:

1. Define the bounded object that can be preserved.
2. Define the transformations that may act on it.
3. Define the invariant relation that must survive transformation.
4. Define the witness object that certifies that survival.
5. Define expression as admissible only when derived from that witness-bearing transition.

## One-Sentence Kernel

> A governed system is one in which expression is admissible only as a boundary crossing derived from a lawful transition that preserves the constrained structure of a bounded state.
