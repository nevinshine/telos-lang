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

        // 1. Initialize Targets
        Target::initialize_x86(&InitializationConfig::default());
        Target::initialize_bpf(&InitializationConfig::default());

        // 2. Setup Host (x86_64) Module
        let host_target = Target::from_name("x86-64").unwrap();
        let host_machine = host_target.create_target_machine(
            &TargetTriple::create("x86_64-unknown-linux-gnu"), "generic", "", 
            OptimizationLevel::Aggressive, RelocMode::Default, CodeModel::Default
        ).unwrap();
        
        // 3. Setup Kernel (BPF) Module
        let bpf_target = Target::from_name("bpf").unwrap();
        // Using "probe" allows the LLVM BPF backend to query the host kernel for available extensions.
        let bpf_machine = bpf_target.create_target_machine(
            &TargetTriple::create("bpf-unknown-none"), "probe", "", 
            OptimizationLevel::None, RelocMode::Default, CodeModel::Default
        ).unwrap();

        // 4. Generate BPF Bytecode in memory
        let bpf_hooks = bpf::emit_sandbox(self.bpf_ctx, &bpf_machine, &program.intents);

        // 5. Generate Host Executable and embed the BPF bytes
        host::emit_executable(self.host_ctx, &host_machine, &program.functions, bpf_hooks);

        // 6. Phase 4: Synthesize Pipelock MCP consumer in host module
        println!("[TELOS PIPELOCK] Synthesizing MCP event consumer...");
        let pipelock_module = self.host_ctx.create_module("telos_pipelock");
        let consumer_fn = pipelock::synthesize_event_consumer(self.host_ctx, &pipelock_module);
        pipelock::synthesize_consumer_spawner(self.host_ctx, &pipelock_module, consumer_fn);
    }
}
