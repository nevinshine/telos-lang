# Telos Language

A zero-trust systems programming language designed to unify business logic and kernel security policies.

## Architecture
Telos compiles a single source file into a Dual-Target pipeline:
1. **User-Space Logic** -> Native host LLVM IR (x86_64/AArch64)
2. **Intent Bounds** -> BPF IR (`BPF_PROG_TYPE_LSM`)

The binary relies on a **Fail-Closed Bootstrap Injector**: it mathematically cannot execute user-space logic unless it successfully attaches its Ring 0 eBPF sandbox via `bpf(BPF_PROG_LOAD)` syscalls before `main()` execution.

## Current Status: Phase 5 Complete
The compiler natively integrates **Z3 SMT Formal Verification**.

During compilation, the `verify_smt.rs` symbolic executor traverses all translated `BPF_PROG_TYPE_LSM` hooks before generating the `.rodata` hex array. The Z3 theorem prover mathematically verifies:
- Memory bounds
- Arithmetic safety
- Explicit structural bounds for Linux LSM return values (`0` or `-EPERM`)

Compilation is strictly aborted if the BPF module generates an unprovable or violating control flow graph.

```
[TELOS] Running SMT formal verification...
[TELOS VERIFIER] Verifying LSM hook: telos_check_connect
[TELOS VERIFIER] ✓ telos_check_connect — all safety properties proven
[TELOS VERIFIER] Verifying LSM hook: telos_file_open
[TELOS VERIFIER] ✓ telos_file_open — all safety properties proven
[TELOS VERIFIER] ✓ All LSM hooks formally verified
```

## Next Phase: Phase 3
Implementing Static Information Flow Control (IFC) lattice to guarantee non-interference through `Secret<T>`, `Tainted<T>`, and `Public<T>` type boundaries.
