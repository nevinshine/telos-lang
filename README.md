Telos: Policy-as-code
=====================

[![CI](https://github.com/nevinshine/telos-lang/actions/workflows/ci.yml/badge.svg)](https://github.com/nevinshine/telos-lang/actions/workflows/ci.yml)

A strictly typed, policy-as-code systems language structured for zero-trust Linux environments. Telos unifies application logic with formally-verified Linux kernel security capabilities natively.

## 5-Minute Quickstart

Telos generates formally-verified, fail-closed Linux executables containing embedded eBPF LSM sandboxes directly from your source.

```bash
# 1. Clone the repository
git clone https://github.com/nevinshine/telos-lang.git
cd telos-lang/telosc

# 2. Build the compiler pipeline (Requires LLVM 15 and Z3 via your package manager)
cargo build

# 3. Compile & Run the Demonstration Sandbox (Root required to map the BPF)
sudo cargo run tests/hello_world.telos
```

## v0.1 MVP Scope

**What Telos v0.1 Is:**
- A dual-target generator translating semantic actions into x86_64 host instructions + kernel-level eBPF sandboxes.
- A static mathematical verifier using Microsoft Z3 to mathematically prove all kernel constraints are satisfied prior to emission.
- A language enforcing Information Flow Control (`Secret<T>` vs `Public<T>`) natively, guaranteeing zero data leakage at compile time.

**What Telos v0.1 Is Not:**
- A generalized general-purpose language with a massive standard library (like Rust or Go). It is designed strictly for high-security wedge code.
- A cross-platform framework. It is tightly bound directly into the Linux capability matrix.

---


## Language Features 

* **Zero-Trust Execution (Fail-Closed)**: Telos executables contain an embedded `.init` bootstrap injector. If the Linux kernel rejects the internal LSM eBPF sandbox, the binary explicitly self-aborts before `main()`. 
* **Dual-Target IR Pipeline**: Synthesizes host architecture (x86_64) parallel to kernel architectures (`bpf-unknown-none`) in one unified pass.
* **Static Information Flow Control (IFC)**: A zero-cost lattice (`Secret<T>`, `Public<T>`) prevents both explicit data variable leaking and implicit structural flow leaking through control boundaries (`If` / `While`).
* **Cryptographic Boundary Casting**: `Secret` strings are locked to the execution boundary permanently. They can only be declassified via compiler-whitelisted algorithms (`SHA-256`, `AES-GCM`).
* **Semantic LSM Intent Extraction**: Capabilities mapped natively into BPF hash maps automatically intercept `socket_connect` and `file_open` Linux Security Modules.
* **Pipelock MCP Synchronization**: Integrates native Ringbuffer streaming from the eBPF layer into a local JSON-RPC consumer thread for Model Context Protocol (MCP) telemetry export.
* **Z3 SMT Formal Verification**: Every basic block of the eBPF hook is formally constrained by Microsoft Z3 to mathematically prove memory safety and structural adherence before compilation concludes.
* **AARM Cryptographic Receipts (Phase 8)**: Native SipHash-2-4 IR generation within the eBPF context, providing tamper-evident forensic receipts for Autonomous Action Runtime Management (AARM) compliance.
* **Hyperion XDP Bridge (Phase 9)**: Hardware-level network drops using `BPF_PROG_TYPE_XDP`. Intercepts and drops unauthorized packets at the NIC driver level, bypassing the kernel networking stack for extreme performance.


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

## 4. Build and Execution Instructions

All generation is contained within the `telosc` root crate wrapper. Use the included `hello_world.telos` file to see the full compiler syntax in action.

```bash
# Standard Compilation Check:
cargo check

# Compile and Run the Showcase Demonstration:
sudo cargo run tests/hello_world.telos
```
> **Note**: `sudo` is required to attach the compiled eBPF LSM sandboxes to the kernel successfully. The compiler uses `llvm.global_ctors` to synthesize an embedded preamble. If `CAP_BPF` is missing, the binary executes a strict fail-closed trap and aborts instantly with an `Illegal instruction (core dumped)` prior to `main()` executing.
