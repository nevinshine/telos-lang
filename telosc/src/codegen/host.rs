use std::path::Path;
use inkwell::context::Context;
use inkwell::targets::{TargetMachine, FileType};
use inkwell::values::{BasicValueEnum, FunctionValue};
use crate::parser::{Function, Stmt, Expr};
use crate::codegen::bootstrap;

pub fn emit_executable<'a>(ctx: &'a Context, machine: &TargetMachine, functions: &[Function], bpf_hooks: Vec<(String, Vec<u8>)>) {
    let module = ctx.create_module("telos_host");
    
    // Inject the fail-closed bootstrap routine
    bootstrap::inject_preamble(ctx, &module, bpf_hooks);
    
    let i64_type = ctx.i64_type();
    let void_type = ctx.void_type();

    // 1. Declare functions
    for func in functions {
        let fn_type = if func.ret_type == crate::parser::Type::Void {
            void_type.fn_type(&[], false)
        } else {
            i64_type.fn_type(&[], false)
        };
        module.add_function(&func.name, fn_type, None);
    }

    let builder = ctx.create_builder();

    // 2. Generate function bodies
    for func in functions {
        let fn_val = module.get_function(&func.name).unwrap();
        let entry_block = ctx.append_basic_block(fn_val, "entry");
        builder.position_at_end(entry_block);

        // Simple AST emission
        for stmt in &func.body {
            emit_stmt(ctx, &builder, stmt, fn_val, None);
        }

        // Implicit return if void
        if func.ret_type == crate::parser::Type::Void {
            let last_inst = builder.get_insert_block().unwrap().get_last_instruction();
            let needs_ret = match last_inst {
                Some(inst) => inst.get_opcode() != inkwell::values::InstructionOpcode::Return,
                None => true,
            };
            if needs_ret {
                builder.build_return(None);
            }
        }
    }

    // Machine emit to object
    machine.write_to_file(&module, FileType::Object, Path::new("output.o")).unwrap();
}

fn emit_stmt<'a>(
    ctx: &'a Context, 
    builder: &inkwell::builder::Builder<'a>, 
    stmt: &Stmt, 
    fn_val: FunctionValue<'a>,
    catch_bb_opt: Option<inkwell::basic_block::BasicBlock<'a>>
) {
    let i64_type = ctx.i64_type();
    
    match stmt {
        Stmt::Let(_name, _ty, _expr) => {}
        Stmt::Assign(_name, _expr) => {}
        Stmt::If(_cond, _body) => {}
        Stmt::While(_cond, _body) => {}
        Stmt::Return(opt_expr) => {
            match opt_expr {
                Some(expr) => {
                    let val = emit_expr(ctx, builder, expr);
                    builder.build_return(Some(&val));
                }
                None => {
                    builder.build_return(None);
                }
            }
        }
        Stmt::Expr(expr) => {
            emit_expr(ctx, builder, expr);
        }
        Stmt::Intend(intent_name) => {
            // Compute deterministic hash for the intent
            let intent_hash = if intent_name == "network" {
                0x42
            } else {
                let mut hash: u64 = 0xcbf29ce484222325; // FNV-1a offset basis
                for byte in intent_name.bytes() {
                    hash ^= byte as u64;
                    hash = hash.wrapping_mul(0x100000001b3); // FNV-1a prime
                }
                hash
            };

            // Ecall returns a status code in a0 (e.g. -EPERM)
            let asm_fn_type = i64_type.fn_type(&[], false);
            
            // Generate exact U-mode ecall assembly block for RISC-V intent elevation
            let asm_str = format!("li a0, {}\necall", intent_hash);
            let inline_asm = ctx.create_inline_asm(
                asm_fn_type,
                asm_str,
                "={a0},~{memory}".to_string(), // Returns in a0, clobbers memory
                true, false, None, false
            );
            
            let res = builder.build_indirect_call(
                asm_fn_type,
                inline_asm,
                &[],
                "intent_trap"
            ).try_as_basic_value().left().unwrap().into_int_value();
            
            // If inside a try_intent block, check for -EPERM (-1)
            if let Some(catch_bb) = catch_bb_opt {
                let minus_one = i64_type.const_int(!0, true); // -1
                let is_eperm = builder.build_int_compare(inkwell::IntPredicate::EQ, res, minus_one, "is_eperm");
                
                let cont_bb = ctx.append_basic_block(fn_val, "intent_cont");
                builder.build_conditional_branch(is_eperm, catch_bb, cont_bb);
                builder.position_at_end(cont_bb);
            }
        }
        Stmt::TryCatch(try_block, catch_block) => {
            let catch_bb = ctx.append_basic_block(fn_val, "catch_bb");
            let cont_bb = ctx.append_basic_block(fn_val, "cont_bb");
            
            for t_stmt in try_block {
                emit_stmt(ctx, builder, t_stmt, fn_val, Some(catch_bb));
            }
            
            // If the try block naturally finishes, jump to continuation block
            let current_bb = builder.get_insert_block().unwrap();
            if current_bb.get_terminator().is_none() {
                builder.build_unconditional_branch(cont_bb);
            }
            
            // Emit catch block
            builder.position_at_end(catch_bb);
            for c_stmt in catch_block {
                emit_stmt(ctx, builder, c_stmt, fn_val, None);
            }
            
            let current_bb_catch = builder.get_insert_block().unwrap();
            if current_bb_catch.get_terminator().is_none() {
                builder.build_unconditional_branch(cont_bb);
            }
            
            builder.position_at_end(cont_bb);
        }
    }
}

fn emit_expr<'a>(ctx: &'a Context, builder: &inkwell::builder::Builder<'a>, expr: &Expr) -> BasicValueEnum<'a> {
    let i64_type = ctx.i64_type();
    match expr {
        Expr::Number(val) => i64_type.const_int(*val as u64, false).into(),
        Expr::Call(func_name, args) => {
            if func_name == "heki_drawbridge_update" {
                // Generate Ring -1 Drawbridge Protocol Assembly
                // Expected signature: heki_drawbridge_update(nonce: u64, map_ptr: u64)
                let asm_fn_type = i64_type.fn_type(&[i64_type.into(), i64_type.into()], false);
                let asm_str = "ebreak".to_string(); // Trigger VM-Exit for hypervisor introspection
                let inline_asm = ctx.create_inline_asm(
                    asm_fn_type,
                    asm_str,
                    "={a0},{a0},{a1},~{memory}".to_string(), // Result in a0, nonce in a0, map_ptr in a1
                    true, false, None, false
                );
                
                let nonce_val = if args.len() > 0 { emit_expr(ctx, builder, &args[0]).into_int_value() } else { i64_type.const_int(0, false) };
                let map_ptr_val = if args.len() > 1 { emit_expr(ctx, builder, &args[1]).into_int_value() } else { i64_type.const_int(0, false) };

                return builder.build_indirect_call(
                    asm_fn_type,
                    inline_asm,
                    &[nonce_val.into(), map_ptr_val.into()],
                    "heki_vm_exit"
                ).try_as_basic_value().left().unwrap();
            }
            i64_type.const_int(0, false).into() // fallback for other calls
        },
        _ => i64_type.const_int(0, false).into(), // fallback
    }
}
