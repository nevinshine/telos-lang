# Telos Threat Model & Technical Guarantees

Telos operates under a Zero-Trust architecture designed to execute sensitive policy payloads safely. This document explicitly identifies our compiler guarantees and formal limitations.

## In-Scope: What We Guarantee 🔒

When a Telos policy successfully passes `telosc verify` and `telosc build`, we establish the following:

### 1. Complete Information Flow Control (IFC) 
Data wrapped in `Secret<T>` is strictly anchored against leakage.
- **Explicit Containment**: `Secret` variables cannot be directly assigned or piped into `Public` variables.
- **Implicit/Structural Containment**: Program Dependent Graph checking evaluates local branching. A variable conditionally mutated inside a scope wrapped by a `Secret` bound is intrinsically elevated to `Secret`. 

### 2. Formal Memory Safety (via Z3)
Instead of dynamic runtime panics, the compiler maps the intermediate kernel BPF targets into Z3 theorem components. The generated sandbox bytecode is guaranteed to:
- Never invoke undefined pointer offsets.
- Always conform strictly to Linux return expectations (`0` or negative error integers for LSM hooks).
- Execute fully within the verifier's deterministic instruction limits.

### 3. Fail-Closed Synchronization
Generated binaries synthesize host code alongside embedded BPF sandbox payloads. The `llvm.global_ctors` bootstrap mandates that if the kernel capability validation logic rejects the mapped sandbox, the primary application instantly triggers a terminal `abort`, securing the system statically.

---

## Out-of-Scope: Known Limitations ⚠️

Telos does *not* protect against the following:

1. **Host-Side Denial of Service / Memory Exhaustion**
While the kernel component is bounded via Z3, the generic host application logic operates within standard Linux limits. Loop constructs handling infinite inbound sockets will trigger the `OOM killer`.
2. **Declassification Exploitability**
Telos permits explicit, intentional data dilution through the `declassify(..., "ALGO")` intent. The compiler trusts your judgment here; if you declassify a secret intentionally into a public payload unsuited for it, the language assumes semantic intent.
3. **Hardware / Micro-Architectural Side Channels**
Hardware vulnerabilities (e.g. Spectre variants) mapped against CPU execution windows are out of scope. Telos secures the semantic boundary layout, not the physical processor execution queue.
