use crate::parser::{Program, Function, Stmt, Expr, Type, SecurityLabel};
use std::collections::HashMap;

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

    for func in &program.functions {
        typecheck_function(func, &func_sigs)?;
    }
    Ok(())
}

fn typecheck_function(func: &Function, func_sigs: &HashMap<String, SecurityLabel>) -> Result<(), TypeError> {
    let mut env: HashMap<String, SecurityLabel> = HashMap::new();
    let mut pc_stack: Vec<SecurityLabel> = Vec::new();

    // Register arguments
    for (arg_name, arg_type) in &func.args {
        env.insert(arg_name.clone(), get_label(arg_type));
    }

    typecheck_stmts(&func.body, &mut env, &mut pc_stack, &func.ret_type, func_sigs)
}

fn typecheck_stmts(stmts: &[Stmt], env: &mut HashMap<String, SecurityLabel>, pc_stack: &mut Vec<SecurityLabel>, ret_type: &Type, func_sigs: &HashMap<String, SecurityLabel>) -> Result<(), TypeError> {
    for stmt in stmts {
        match stmt {
            Stmt::Let(name, ty, expr) => {
                let decl_label = get_label(ty);
                let expr_label = evaluate_label(expr, env, func_sigs)?;
                
                // Enforce Explicit Flow
                check_flow(&expr_label, &decl_label).map_err(|e| TypeError::ExplicitLeak(format!("{} in binding '{}'", e, name)))?;
                
                // Enforce Implicit Flow (PC block ceiling)
                let effective_pc = get_effective_pc(pc_stack);
                check_flow(&effective_pc, &decl_label).map_err(|e| TypeError::ImplicitLeak(format!("{} in binding '{}'", e, name)))?;
                
                env.insert(name.clone(), decl_label);
            }
            Stmt::Assign(name, expr) => {
                let target_label = env.get(name).ok_or_else(|| TypeError::UndefinedVariable(name.clone()))?.clone();
                let expr_label = evaluate_label(expr, env, func_sigs)?;
                
                check_flow(&expr_label, &target_label).map_err(|e| TypeError::ExplicitLeak(format!("{} in assignment '{}'", e, name)))?;
                
                // Enforce Implicit Flow
                let effective_pc = get_effective_pc(pc_stack);
                check_flow(&effective_pc, &target_label).map_err(|e| TypeError::ImplicitLeak(format!("{} in assignment '{}'", e, name)))?;
            }
            Stmt::If(cond, body) => {
                let cond_label = evaluate_label(cond, env, func_sigs)?;
                pc_stack.push(cond_label); // Push conditional scope bounds
                
                typecheck_stmts(body, env, pc_stack, ret_type, func_sigs)?;
                
                pc_stack.pop(); // Pop off context
            }
            Stmt::While(cond, body) => {
                let cond_label = evaluate_label(cond, env, func_sigs)?;
                pc_stack.push(cond_label); // Push loop condition bounds
                
                typecheck_stmts(body, env, pc_stack, ret_type, func_sigs)?;
                
                pc_stack.pop(); // Pop off context
            }
            Stmt::Return(expr_opt) => {
                let expr_label = match expr_opt {
                    Some(expr) => evaluate_label(expr, env, func_sigs)?,
                    None => SecurityLabel::Public,
                };
                let declared_ret_label = get_label(ret_type);
                check_flow(&expr_label, &declared_ret_label).map_err(|e| TypeError::ExplicitLeak(format!("{} in return statement", e)))?;
                
                // Implicit flow: Returning from within an 'if (Secret)' implicitly leaks the condition.
                let effective_pc = get_effective_pc(pc_stack);
                check_flow(&effective_pc, &declared_ret_label).map_err(|e| TypeError::ImplicitLeak(format!("{} in return statement", e)))?;
            }
            Stmt::Expr(expr) => {
                evaluate_label(expr, env, func_sigs)?;
            }
        }
    }
    Ok(())
}

fn get_effective_pc(pc_stack: &[SecurityLabel]) -> SecurityLabel {
    let mut effective = SecurityLabel::Public;
    for lbl in pc_stack {
        effective = join(&effective, lbl);
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

fn evaluate_label(expr: &Expr, env: &HashMap<String, SecurityLabel>, func_sigs: &HashMap<String, SecurityLabel>) -> Result<SecurityLabel, TypeError> {
    match expr {
        Expr::Number(_) | Expr::StringLiteral(_) => Ok(SecurityLabel::Public),
        Expr::Var(name) => {
            let lbl = env.get(name).ok_or_else(|| TypeError::UndefinedVariable(name.clone()))?;
            Ok(lbl.clone())
        }
        Expr::Call(func_name, args) => {
            for arg in args {
                evaluate_label(arg, env, func_sigs)?;
            }
            let ret_label = func_sigs.get(func_name)
                .ok_or_else(|| TypeError::UndefinedVariable(format!("Function '{}' not found", func_name)))?;
            Ok(ret_label.clone())
        }
        Expr::Declassify(inner_expr, algorithm) => {
            // Validate the algorithm is in the approved whitelist
            if !APPROVED_ALGORITHMS.iter().any(|a| a == algorithm) {
                return Err(TypeError::InvalidDeclassify(
                    format!("Algorithm '{}' is not in the approved cryptographic whitelist. Approved: {:?}", algorithm, APPROVED_ALGORITHMS)
                ));
            }
            // Evaluate the inner expression to confirm it exists
            let _inner_label = evaluate_label(inner_expr, env, func_sigs)?;
            // Declassify strips the label down to Public
            println!("[TELOS IFC] declassify: stripping label via approved algorithm '{}'", algorithm);
            Ok(SecurityLabel::Public)
        }
    }
}

// Secret > Public
// Tainted is unrelated to Confidentiality lattice, or treated as Low Confidentiality / Low Integrity.
fn check_flow(from: &SecurityLabel, to: &SecurityLabel) -> Result<(), String> {
    match (from, to) {
        (SecurityLabel::Secret, SecurityLabel::Public) => Err("Cannot flow Secret data into Public sink".to_string()),
        (SecurityLabel::Secret, SecurityLabel::Tainted) => Err("Cannot flow Secret data into Tainted sink".to_string()),
        (SecurityLabel::Tainted, SecurityLabel::Public) => Err("Cannot flow Tainted data into Public sink".to_string()),
        _ => Ok(()) // Allowed bounds
    }
}

fn join(l1: &SecurityLabel, l2: &SecurityLabel) -> SecurityLabel {
    if l1 == &SecurityLabel::Secret || l2 == &SecurityLabel::Secret {
        SecurityLabel::Secret
    } else if l1 == &SecurityLabel::Tainted || l2 == &SecurityLabel::Tainted {
        SecurityLabel::Tainted
    } else {
        SecurityLabel::Public
    }
}
