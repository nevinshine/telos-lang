Telos Systems Programming Language
==================================

A zero-trust, kernel-aware systems programming language designed to unify application business logic with strict Linux kernel security policies. Telos abolishes the semantic gap between how software is programmed in user-space and how it is restricted by the operating system platform.

## 1. Architectural Overview

Traditional systems languages (C, C++, Rust) isolate security enforcement to external layers (AppArmor, SELinux, Kubernetes policies). 
Telos embeds the security primitives natively into the language semantics using a **Dual-Target IR Pipeline**:

1.  **Host Execution (User-Space LLVM IR)**: The primary application logic is compiled into generic x86_64 or AArch64 machine code using the `inkwell` LLVM wrapper.
2.  **Sandbox Generation (BPF LLVM IR)**: Capability definitions (`intent` blocks) are recursively lowered into `BPF_PROG_TYPE_LSM` eBPF bytecode targeting specific Linux Security Module hook points.

### The Fail-Closed Bootstrap Injector
The generated eBPF bytecode array is dynamically linked into the host ELF `.rodata` section. Telos utilizes `llvm.global_ctors` to synthesize a low-level `.init` preamble that issues raw `bpf(BPF_PROG_LOAD)` syscalls before `main()` execution. If the Linux kernel rejects the eBPF isolation sandbox bounds, the binary unconditionally aborts. A Telos binary mathematically cannot execute its internal logic without its required kernel security matrix.

## 2. Information Flow Control (IFC) Lattice

Telos guarantees non-interference and strictly isolates data trajectories through a transparent, zero-cost security lattice integrated directly into the semantic AST tree.

### Data-Flow Anesthesia
Variables are explicitly annotated using the architectural security wrappers: `Secret<T>`, `Tainted<T>`, and `Public<T>`.

```rust
fn core_evaluation() -> Void {
    let critical_token: Secret<String> = "/etc/shadow";
    
    // [TELOS FATAL]: ExplicitLeak("Cannot flow Secret data into Public sink in assignment 'external_socket'")
    let external_socket: Public<String> = critical_token;
}
```

### Implicit Context Boundaries (Program Dependence Graphs)
Conditional jumps inherently bind their enclosed scope variables. The internal `typecheck.rs` evaluation model strictly evaluates the structural ceiling via a dynamic Program Counter (PC) stack to prevent indirect leaks.

```rust
fn implicit_leak() -> Void {
    let internal_eval: Secret<I64> = 1;
    let outbound_telemetry: Public<I64> = 0;
    
    // Pushing the `Secret` context onto the local PC evaluation stack
    if internal_eval {
        // [TELOS FATAL]: ImplicitLeak("Cannot flow Secret data into Public sink in assignment 'outbound_telemetry'")
        outbound_telemetry = 1; 
    }
}
```

--- 

## 3. Z3 SMT Formal Verification

The compiler actively incorporates static theorem proving into its translation bounds. During compilation within `verify_smt.rs`, the generated LLVM Basic Blocks representing the eBPF LSM intercept hooks are statically modeled as Bit-Vector representations. 

Before the BPF sandbox array is serialized, the Z3 SMT Theorem Prover calculates all operational CFG branching constraints to prove:
- Division-by-Zero safety.
- Restricted Shift Ranges.
- Pointer Arithmetic bounds.
- Valid Linux LSM Return structural values (`0` for success or `-EPERM`/`-1` access denied limitations).

If the Z3 model evaluates to `SAT` (a violating sequence is computationally possible), compilation aborts.

## 4. Immediate Roadmap and Missing Core Implementation Constraints

The current minimal viable compiler operates Phase 5 architecture natively. The following elements must be implemented to achieve the final Phase 6 production architecture:

### Phase 3 Missing Files (To be implemented):
-   `src/declassify.rs`: The cryptographic declassification boundary. Telos currently rejects any flow down the lattice. We must expose `declassify()` primitives (bound algorithms like `AES-GCM` or `SHA-256`) that explicitly down-cast `Secret<T>` payload hashes into `Public<T>`.
-   `tests/declassify_pass.telos`: To prove cryptographic algorithms actively circumvent the typechecker bounds.

### Phase 4 Missing Files (To be implemented):
-   "Pipelock" MCP Firewall Synchronization (`src/codegen/pipelock.rs`).
-   Implement structural LLVM synthesis mapping for zero-copy `BPF_MAP_TYPE_USER_RINGBUF` maps.
-   Stream internal kernel contextual boundaries up dynamically into external Layer 7 proxy implementations (like a remote LLM API firewall block proxy).
-   SipHash-2-4 HMAC integration for validation sequence validation tokens within the Ring 0 context buffer.

## 5. Build and Execution Instructions

All generation is contained within the `telosc` root crate wrapper.

```bash
# Standard Compilation Check:
cargo check

# Evaluate the internal implicit and explicit flow-graph validations:
cargo run tests/ifc_fail.telos
cargo run tests/ifc_implicit.telos
```
