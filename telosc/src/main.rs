pub mod parser;
pub mod typecheck;
pub mod codegen;
pub mod heki;

use inkwell::context::Context;
use crate::parser::Program;
use crate::codegen::DualCompiler;

use chumsky::Parser;
use clap::{Parser as ClapParser, Subcommand};

#[derive(ClapParser)]
#[command(name = "telosc")]
#[command(about = "Telos Policy-as-Code Systems Compiler", long_about = None)]
#[command(version = "0.1.0")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Creates a new foundational Telos wedge policy
    New {
        /// Name of the environment
        name: String,
    },
    /// Statically typechecks the syntax tree and IFC bounds without compiling
    Check {
        /// The path to the .telos file
        file: String,
    },
    /// Formally verifies logic constraints via Microsoft Z3
    Verify {
        /// The path to the .telos file
        file: String,
    },
    /// Lowers the script into valid dual-target execution environments (ELF + BPF)
    Build {
        /// The path to the .telos file
        file: String,
    },
}

fn parse_and_get_program(filepath: &str) -> Program {
    let content = std::fs::read_to_string(filepath).expect("Failed to read file");
    match crate::parser::program_parser().parse(content) {
        Ok(prog) => prog,
        Err(errs) => {
            eprintln!("Syntax error matching top-level script:");
            for e in errs {
                eprintln!("{:?}", e);
            }
            std::process::exit(1);
        }
    }
}

fn main() {
    let cli = Cli::parse();

    match &cli.command {
        Commands::New { name } => {
            println!("Initializing new Telos policy environment: {}", name);
            let template = "intent proxy {\n    allow Capability::Net::Connect {\n        host: \"api.secure.com\",\n        port: 443,\n    }\n}\n\nfn main() -> Void {\n    // Add safe policy logic here\n}\n";
            std::fs::write(format!("{}.telos", name), template).expect("Failed to write template file");
            println!("Successfully generated {}.telos", name);
        }
        Commands::Check { file } => {
            println!("Initiating static IFC policy checking for: {}", file);
            let program = parse_and_get_program(file);

            // Run the IFC lattice typechecker against all functions
            match crate::typecheck::typecheck_program(&program) {
                Ok(()) => {
                    println!("[TELOS IFC] ✓ All information flow constraints validated.");
                    println!("No implicit or explicit data leaks detected.");
                }
                Err(e) => {
                    eprintln!("[TELOS IFC] VIOLATION DETECTED: {:?}", e);
                    std::process::exit(1);
                }
            }
        }
        Commands::Verify { file } => {
            println!("Invoking Z3 formal verification on: {}", file);
            let program = parse_and_get_program(file);

            // Phase 1: IFC typechecking is a prerequisite for Z3 verification
            println!("[TELOS IFC] Verifying Information Flow Control lattice...");
            match crate::typecheck::typecheck_program(&program) {
                Ok(()) => println!("[TELOS IFC] ✓ Lattice validated"),
                Err(e) => {
                    eprintln!("[TELOS IFC] FATAL: {:?}", e);
                    std::process::exit(1);
                }
            }

            // Phase 2: Initialize BPF target and compile to LLVM IR for Z3 analysis
            use inkwell::targets::{Target, InitializationConfig};
            Target::initialize_bpf(&InitializationConfig::default());

            let bpf_target = Target::from_name("bpf").unwrap();
            let bpf_machine = bpf_target.create_target_machine(
                &inkwell::targets::TargetTriple::create("bpf-unknown-none"),
                "probe", "",
                inkwell::OptimizationLevel::None,
                inkwell::targets::RelocMode::Default,
                inkwell::targets::CodeModel::Default,
            ).unwrap();

            // Phase 3: Generate BPF module in memory (without emitting object file)
            let bpf_ctx = Context::create();
            let _hooks = crate::codegen::bpf::emit_sandbox(&bpf_ctx, &bpf_machine, &program.intents);

            // SMT verification runs inside emit_sandbox via verify_module().
            // If we reach here, all Z3 proofs passed (failures panic inside emit_sandbox).
            println!("[TELOS VERIFIER] ✓ Z3 Theorem Prover: all safety properties proven.");
            println!("All basic blocks are deterministically bounded.");
        }
        Commands::Build { file } => {
            println!("Telos Compiler MVP Initialized.");
            let program = parse_and_get_program(file);
            println!("Successfully parsed Program, Intents, and Function blocks!");
            
            let host_ctx = Context::create();
            let bpf_ctx = Context::create();

            let compiler = DualCompiler::new(&host_ctx, &bpf_ctx);
            compiler.compile(&program);
            
            println!("Compilation finished. Object file generated at output.o");
        }
    }
}
