<div align="center">
  <h1>🛡️ Telos Language</h1>
  <p><b>A kernel-aware, zero-trust systems programming language.</b></p>
  <p><i>Unifying business logic and Linux kernel security policies through dual-target LLVM BPF compilation, Z3 theorem proving, and strict Information Flow Control (IFC).</i></p>
</div>

---

## ⚡ Core Philosophy

Traditional systems programming languages like C and Rust decouple **application logic** from **execution security**. Developers write business logic in user-space, while platform engineers enforce security boundaries via external YAML policies (Kubernetes, AppArmor, SELinux).

**Telos obliterates this semantic gap.** 

Telos elevates security primitives directly into the core language syntax. It compiles a single source file into *both* a standard host executable (x86_64/AArch64) and an embedded Ring 0 eBPF sandbox (`BPF_PROG_TYPE_LSM`). The binary mathematically cannot execute its application logic unless the kernel successfully bootstraps and attaches the eBPF isolation sandbox.

## 🛠️ Architecural Innovations

### 1. Dual-Target IR Pipeline
Telos compiles your single source file twice leveraging two parallel `inkwell` LLVM contexts:
- **Target 1**: The user-space execution logic (e.g., standard `x86_64` machine code).
- **Target 2**: The capability definitions are synthesized into Linux Security Module (LSM) hooks via LLVM's `bpf` backend.

### 2. Fail-Closed Embedded Bootstrapping
The BPF bytecode is injected directly into the ELF's `.rodata` hex section. Telos automatically wraps the binary with an `llvm.global_ctors` `init` wrapper that evaluates `bpf(BPF_PROG_LOAD)` *before* `main()` ever runs. If the sandbox fails to attach, the binary unconditionally aborts.

### 3. Z3 SMT Formal Verification
Before the compiler generates the BPF bytecode, the internal CFG is mapped into bit-vector constraints and proven mathematically safe via statically linked Z3 SMT theorem proving. If an intent block evaluates to an invalid structural bounds limit (`-EPERM`), compilation fails.

### 4. Zero-Cost Information Flow Control (IFC)
Telos prevents data exfiltration by enforcing a strict security lattice natively inside the Type Checker.
Constraints are evaluated via a global Program Dependence Graph (PDG) targeting Explicit Leaks (direct assignment) and Implicit Leaks (conditional PC block context tracking).

## 📖 Language Syntax & Demo

### Capability Intents (The Sandbox)
Capabilities establish exactly what the isolated executable is mathematically allowed to do.

```rust
// Limits the program entirely to calling this exact domain and port.
intent fetch {
    allow Capability::Net::Connect {
        host: "api.example.com",
        port: 443,
    }
}
```

### Static Lattice Data-Flow (IFC)
Variables are strictly bounded by `Secret<T>`, `Tainted<T>`, and `Public<T>` annotations.

```rust
fn explicit_leak() -> Void {
    let shadow: Secret<String> = "/etc/shadow";
    
    // ❌ [COMPILER FATAL]: Cannot flow Secret data into Public sink.
    let external_buffer: Public<String> = shadow;
}
```

Implicit leaks are strictly tracked through branch bounds using PC-evaluation stack pushes:

```rust
fn implicit_leak() -> Void {
    let condition: Secret<I64> = 1;
    let b: Public<I64> = 0;
    
    if condition {
        // ❌ [COMPILER FATAL]: Cannot assign to Public sink inside a Secret PC-Stack boundary!
        b = 1; 
    }
}
```

## 🚀 Project Status & Roadmap
- [x] **Phase 1**: Dual-Target LLVM Pipeline & `init` fail-closed BPF array bootstrapping.
- [x] **Phase 2**: Semantic-to-LSM translation (mapping Intent to Socket/File `eBPF` hooks).
- [x] **Phase 3**: Static IFC Typechecker (Explicit and Implicit graph flow bounds).
- [x] **Phase 5**: Z3 SMT integration verifying BPF memory bounds dynamically.
- [ ] **Phase 4**: Pipelock MCP integration (Streaming eBPF context buffers to Layer 7 hardware syncs).
