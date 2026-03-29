pub mod parser;
pub mod typecheck;
pub mod codegen;

use inkwell::context::Context;
use crate::parser::Program;
use crate::codegen::DualCompiler;

use chumsky::Parser;

fn main() {
    println!("Telos Compiler MVP Initialized.");
    
    let args: Vec<String> = std::env::args().collect();
    let mut program = Program {
        intents: vec![],
        functions: vec![],
        syncs: vec![],
    };

    if args.len() > 1 {
        let content = std::fs::read_to_string(&args[1]).expect("Failed to read file");
        match crate::parser::program_parser().parse(content) {
            Ok(prog) => {
                program = prog;
                println!("Successfully parsed Program, Intents, and Function blocks!");
            }
            Err(errs) => {
                println!("Syntax error matching top-level script:");
                for e in errs {
                    println!("{:?}", e);
                }
                std::process::exit(1);
            }
        }
    }

    let host_ctx = Context::create();
    let bpf_ctx = Context::create();

    let compiler = DualCompiler::new(&host_ctx, &bpf_ctx);
    compiler.compile(&program);
    
    println!("Compilation finished. Object file generated at output.o");
}
