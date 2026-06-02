pub mod bpf;
pub mod host;
pub mod bootstrap;
pub mod verify_smt;
pub mod pipelock;
pub mod xdp;
pub mod aarm_crypto;

use inkwell::context::Context;
use inkwell::targets::{Target, TargetTriple, RelocMode, CodeModel, InitializationConfig};
use inkwell::OptimizationLevel;
use crate::parser::Program;

pub struct DualCompiler<'ctx> {
    host_ctx: &'ctx Context,
    bpf_ctx: &'ctx Context,
}

impl<'ctx> DualCompiler<'ctx> {
    pub fn new(host_ctx: &'ctx Context, bpf_ctx: &'ctx Context) -> Self {
        Self { host_ctx, bpf_ctx }
    }

    pub fn compile(&self, program: &Program) {
        // 0. Static IFC Typechecker
        println!("[TELOS IFC] Verifying Information Flow Control lattice...");
        if let Err(e) = crate::typecheck::typecheck_program(program) {
            panic!("[TELOS IFC] FATAL: {:?}", e);
        }
        println!("[TELOS IFC] ✓ Lattice validated");

        // 0.5 Formal LTL Temporal Verification
        println!("[TELOS LTL] Verifying Temporal Logic constraints...");
        if let Err(e) = verify_smt::verify_program_temporal(program) {
            panic!("[TELOS LTL] FATAL: {}", e);
        }
        println!("[TELOS LTL] ✓ Temporal LTL validated");

        // 1. Initialize Targets
        Target::initialize_riscv(&InitializationConfig::default());

        // 2. Setup Host (riscv64) Module
        let host_target = Target::from_name("riscv64").unwrap();
        let host_machine = host_target.create_target_machine(
            &TargetTriple::create("riscv64-unknown-elf"), "generic", "", 
            OptimizationLevel::Aggressive, RelocMode::Default, CodeModel::Default
        ).unwrap();
        
        // 3. Skip Kernel (BPF) Module for TCA V2 Silicon Tape-out
        let bpf_hooks = Vec::new();

        // 4. Generate Host Executable
        host::emit_executable(self.host_ctx, &host_machine, &program.functions, bpf_hooks);

        // 5. Phase 4: Synthesize Pipelock MCP consumer in host module (Skipped for RISC-V Bare-metal)
        println!("[TELOS] Skipping Pipelock MCP and eBPF generation for RISC-V bare-metal target.");
    }
}
