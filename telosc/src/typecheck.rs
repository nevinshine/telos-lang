use crate::parser::{Program, Function, Stmt, Expr, Type, SecurityLabel};
use std::collections::HashMap;
use z3::{ast::Ast, Config, Context, Solver};

/// Approved cryptographic algorithms that may declassify Secret data.
const APPROVED_ALGORITHMS: &[&str] = &[
    "AES-GCM",
    "AES-256-GCM",
    "SHA-256",
    "SHA-384",
    "SHA-512",
    "HMAC-SHA256",
    "ChaCha20-Poly1305",
    "Ed25519",
];

#[derive(Debug)]
pub enum TypeError {
    ImplicitLeak(String),
    ExplicitLeak(String),
    UndefinedVariable(String),
    InvalidDeclassify(String),
}

pub fn typecheck_program(program: &Program) -> Result<(), TypeError> {
    let mut func_sigs = HashMap::new();
    for func in &program.functions {
        func_sigs.insert(func.name.clone(), get_label(&func.ret_type));
    }

    let mut cfg = Config::new();
    // Enable core extraction for informative errors
    cfg.set_bool_param_value("unsat_core", true);
    let ctx = Context::new(&cfg);
    let solver = Solver::new(&ctx);

    for func in &program.functions {
        typecheck_function(func, &func_sigs, &program.intents, &ctx, &solver)?;
    }

    let res = solver.check();
    if res == z3::SatResult::Unsat {
        let core = solver.get_unsat_core();
        return Err(TypeError::ExplicitLeak(format!("Z3 SMT IFC Violation: Taint flow proved Unsat. Invalid downward flow detected! Core: {:?}", core)));
    }

    Ok(())
}

fn typecheck_function<'ctx>(
    func: &Function, 
    func_sigs: &HashMap<String, SecurityLabel>, 
    intents: &[crate::parser::IntentDecl],
    ctx: &'ctx Context,
    solver: &Solver<'ctx>
) -> Result<(), TypeError> {
    let mut env: HashMap<String, z3::ast::Int<'ctx>> = HashMap::new();
    let mut pc_stack: Vec<z3::ast::Int<'ctx>> = Vec::new();

    // Register arguments
    for (arg_name, arg_type) in &func.args {
        let label = get_label(arg_type);
        let z3_val = z3::ast::Int::from_i64(ctx, label_to_int(&label));
        env.insert(arg_name.clone(), z3_val);
    }

    let ret_label = get_label(&func.ret_type);
    let ret_z3 = z3::ast::Int::from_i64(ctx, label_to_int(&ret_label));

    typecheck_stmts(&func.body, &mut env, &mut pc_stack, &ret_z3, func_sigs, intents, ctx, solver)
}

fn typecheck_stmts<'ctx>(
    stmts: &[Stmt], 
    env: &mut HashMap<String, z3::ast::Int<'ctx>>, 
    pc_stack: &mut Vec<z3::ast::Int<'ctx>>, 
    ret_type: &z3::ast::Int<'ctx>, 
    func_sigs: &HashMap<String, SecurityLabel>, 
    intents: &[crate::parser::IntentDecl],
    ctx: &'ctx Context,
    solver: &Solver<'ctx>
) -> Result<(), TypeError> {
    let mut stmt_counter = 0;
    for stmt in stmts {
        stmt_counter += 1;
        match stmt {
            Stmt::Let(name, ty, expr) => {
                let decl_label = get_label(ty);
                let decl_val = label_to_int(&decl_label);
                let dst_node = z3::ast::Int::from_i64(ctx, decl_val);
                
                let src_node = evaluate_label_z3(expr, env, func_sigs, ctx)?;
                
                // Assert dst >= src
                let constraint = dst_node.ge(&src_node);
                let marker = z3::ast::Bool::new_const(ctx, format!("flow_let_{}_{}", name, stmt_counter).as_str());
                solver.assert_and_track(&constraint, &marker);

                let effective_pc = get_effective_pc_z3(pc_stack, ctx);
                let pc_constraint = dst_node.ge(&effective_pc);
                let pc_marker = z3::ast::Bool::new_const(ctx, format!("pc_let_{}_{}", name, stmt_counter).as_str());
                solver.assert_and_track(&pc_constraint, &pc_marker);
                
                env.insert(name.clone(), dst_node);
            }
            Stmt::Assign(name, expr) => {
                let target_node = env.get(name).ok_or_else(|| TypeError::UndefinedVariable(name.clone()))?.clone();
                let src_node = evaluate_label_z3(expr, env, func_sigs, ctx)?;
                
                let constraint = target_node.ge(&src_node);
                let marker = z3::ast::Bool::new_const(ctx, format!("flow_assign_{}_{}", name, stmt_counter).as_str());
                solver.assert_and_track(&constraint, &marker);
                
                let effective_pc = get_effective_pc_z3(pc_stack, ctx);
                let pc_constraint = target_node.ge(&effective_pc);
                let pc_marker = z3::ast::Bool::new_const(ctx, format!("pc_assign_{}_{}", name, stmt_counter).as_str());
                solver.assert_and_track(&pc_constraint, &pc_marker);
            }
            Stmt::If(cond, body) => {
                let cond_node = evaluate_label_z3(cond, env, func_sigs, ctx)?;
                pc_stack.push(cond_node);
                
                typecheck_stmts(body, env, pc_stack, ret_type, func_sigs, intents, ctx, solver)?;
                
                pc_stack.pop();
            }
            Stmt::While(cond, body) => {
                let cond_node = evaluate_label_z3(cond, env, func_sigs, ctx)?;
                pc_stack.push(cond_node);
                
                typecheck_stmts(body, env, pc_stack, ret_type, func_sigs, intents, ctx, solver)?;
                
                pc_stack.pop();
            }
            Stmt::Return(expr_opt) => {
                let src_node = match expr_opt {
                    Some(expr) => evaluate_label_z3(expr, env, func_sigs, ctx)?,
                    None => z3::ast::Int::from_i64(ctx, label_to_int(&SecurityLabel::Public)),
                };
                
                let constraint = ret_type.ge(&src_node);
                let marker = z3::ast::Bool::new_const(ctx, format!("flow_ret_{}", stmt_counter).as_str());
                solver.assert_and_track(&constraint, &marker);
                
                let effective_pc = get_effective_pc_z3(pc_stack, ctx);
                let pc_constraint = ret_type.ge(&effective_pc);
                let pc_marker = z3::ast::Bool::new_const(ctx, format!("pc_ret_{}", stmt_counter).as_str());
                solver.assert_and_track(&pc_constraint, &pc_marker);
            }
            Stmt::Expr(expr) => {
                evaluate_label_z3(expr, env, func_sigs, ctx)?;
            }
            Stmt::Intend(name) => {
                let exists = intents.iter().any(|i| i.name == *name);
                if !exists {
                    return Err(TypeError::UndefinedVariable(format!("Intent '{}' is not declared in this program.", name)));
                }
            }
            Stmt::TryCatch(try_block, catch_block) => {
                pc_stack.push(z3::ast::Int::from_i64(ctx, label_to_int(&SecurityLabel::Public)));
                typecheck_stmts(try_block, env, pc_stack, ret_type, func_sigs, intents, ctx, solver)?;
                pc_stack.pop();
                
                pc_stack.push(z3::ast::Int::from_i64(ctx, label_to_int(&SecurityLabel::Public)));
                typecheck_stmts(catch_block, env, pc_stack, ret_type, func_sigs, intents, ctx, solver)?;
                pc_stack.pop();
            }
        }
    }
    Ok(())
}

fn get_effective_pc_z3<'ctx>(pc_stack: &[z3::ast::Int<'ctx>], ctx: &'ctx Context) -> z3::ast::Int<'ctx> {
    let mut effective = z3::ast::Int::from_i64(ctx, 0); // Public
    for lbl in pc_stack {
        // We need max(effective, lbl). For simplicity, since it's just AST construction,
        // we can create an If-Then-Else: if lbl > effective then lbl else effective.
        let cond = lbl.gt(&effective);
        effective = cond.ite(lbl, &effective);
    }
    effective
}

fn get_label(ty: &Type) -> SecurityLabel {
    match ty {
        Type::I64(l) => l.clone(),
        Type::String(l) => l.clone(),
        Type::Void => SecurityLabel::Public, // defaults to Public
    }
}

fn label_to_int(l: &SecurityLabel) -> i64 {
    match l {
        SecurityLabel::Public => 0,
        SecurityLabel::Tainted => 1,
        SecurityLabel::Secret => 2,
    }
}

fn evaluate_label_z3<'ctx>(
    expr: &Expr, 
    env: &HashMap<String, z3::ast::Int<'ctx>>, 
    func_sigs: &HashMap<String, SecurityLabel>,
    ctx: &'ctx Context
) -> Result<z3::ast::Int<'ctx>, TypeError> {
    match expr {
        Expr::Number(_) | Expr::StringLiteral(_) => Ok(z3::ast::Int::from_i64(ctx, label_to_int(&SecurityLabel::Public))),
        Expr::Var(name) => {
            let lbl = env.get(name).ok_or_else(|| TypeError::UndefinedVariable(name.clone()))?;
            Ok(lbl.clone())
        }
        Expr::Call(func_name, args) => {
            if func_name == "heki_drawbridge_update" || func_name == "socket_open" || func_name == "socket_close" {
                for arg in args {
                    evaluate_label_z3(arg, env, func_sigs, ctx)?;
                }
                return Ok(z3::ast::Int::from_i64(ctx, label_to_int(&SecurityLabel::Public)));
            }

            let mut max_arg = z3::ast::Int::from_i64(ctx, 0);
            for arg in args {
                let arg_lbl = evaluate_label_z3(arg, env, func_sigs, ctx)?;
                let cond = arg_lbl.gt(&max_arg);
                max_arg = cond.ite(&arg_lbl, &max_arg);
            }
            let ret_label = func_sigs.get(func_name)
                .ok_or_else(|| TypeError::UndefinedVariable(format!("Function '{}' not found", func_name)))?;
            let ret_z3 = z3::ast::Int::from_i64(ctx, label_to_int(ret_label));
            
            // max(ret_z3, max_arg)
            let cond = max_arg.gt(&ret_z3);
            Ok(cond.ite(&max_arg, &ret_z3))
        }
        Expr::Declassify(inner_expr, algorithm) => {
            // Validate the algorithm is in the approved whitelist
            if !APPROVED_ALGORITHMS.iter().any(|a| a == algorithm) {
                return Err(TypeError::InvalidDeclassify(
                    format!("Algorithm '{}' is not in the approved cryptographic whitelist. Approved: {:?}", algorithm, APPROVED_ALGORITHMS)
                ));
            }
            let _inner_label = evaluate_label_z3(inner_expr, env, func_sigs, ctx)?;
            println!("[TELOS IFC] declassify: stripping label via approved algorithm '{}'", algorithm);
            Ok(z3::ast::Int::from_i64(ctx, label_to_int(&SecurityLabel::Public)))
        }
    }
}
