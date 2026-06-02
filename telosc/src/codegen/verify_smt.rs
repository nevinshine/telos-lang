use crate::parser::{Program, Function, Stmt, Expr};
use z3::{ast::Ast, Config, Context, Solver};

pub fn verify_program_temporal(program: &Program) -> Result<(), String> {
    let mut cfg = Config::new();
    cfg.set_bool_param_value("unsat_core", true);
    let ctx = Context::new(&cfg);
    
    for func in &program.functions {
        let solver = Solver::new(&ctx);
        verify_function_temporal(func, &ctx, &solver)?;
    }
    
    Ok(())
}

fn verify_function_temporal<'ctx>(func: &Function, ctx: &'ctx Context, solver: &Solver<'ctx>) -> Result<(), String> {
    let mut step = 0;
    
    // Model initial resource state: 0 = CLOSED, 1 = OPEN
    let initial_state = z3::ast::Int::from_i64(ctx, 0);
    
    let end_state = verify_stmts_temporal(&func.body, initial_state, &mut step, ctx, solver)?;
    
    // The invariant: at the end of the function, the resource must be CLOSED (0).
    let constraint = end_state._eq(&z3::ast::Int::from_i64(ctx, 0));
    let marker = z3::ast::Bool::new_const(ctx, "eof_closed_invariant");
    solver.assert_and_track(&constraint, &marker);
    
    let res = solver.check();
    if res == z3::SatResult::Unsat {
        let core = solver.get_unsat_core();
        return Err(format!("LTL Temporal Leak: Function '{}' may exit with an open resource (Ghost I/O). Unsat Core: {:?}", func.name, core));
    }
    
    Ok(())
}

fn verify_stmts_temporal<'ctx>(
    stmts: &[Stmt], 
    mut current_state: z3::ast::Int<'ctx>, 
    step: &mut usize, 
    ctx: &'ctx Context, 
    solver: &Solver<'ctx>
) -> Result<z3::ast::Int<'ctx>, String> {
    for stmt in stmts {
        match stmt {
            Stmt::Expr(Expr::Call(func_name, _)) => {
                if func_name == "socket_open" {
                    *step += 1;
                    let next_state = z3::ast::Int::new_const(ctx, format!("state_{}", step).as_str());
                    let constraint = next_state._eq(&z3::ast::Int::from_i64(ctx, 1)); // Transition to OPEN
                    let marker = z3::ast::Bool::new_const(ctx, format!("socket_open_{}", step).as_str());
                    solver.assert_and_track(&constraint, &marker);
                    current_state = next_state;
                } else if func_name == "socket_close" {
                    *step += 1;
                    let next_state = z3::ast::Int::new_const(ctx, format!("state_{}", step).as_str());
                    let constraint = next_state._eq(&z3::ast::Int::from_i64(ctx, 0)); // Transition to CLOSED
                    let marker = z3::ast::Bool::new_const(ctx, format!("socket_close_{}", step).as_str());
                    solver.assert_and_track(&constraint, &marker);
                    current_state = next_state;
                }
            }
            Stmt::If(_, body) => {
                *step += 1;
                // If we branch, we create an uninterpreted boolean to represent the condition being true or false
                let cond_var = z3::ast::Bool::new_const(ctx, format!("if_cond_{}", step).as_str());
                let state_after_body = verify_stmts_temporal(body, current_state.clone(), step, ctx, solver)?;
                
                let next_state = z3::ast::Int::new_const(ctx, format!("state_{}", step).as_str());
                let constraint = next_state._eq(&cond_var.ite(&state_after_body, &current_state));
                let marker = z3::ast::Bool::new_const(ctx, format!("if_merge_{}", step).as_str());
                solver.assert_and_track(&constraint, &marker);
                
                current_state = next_state;
            }
            Stmt::While(_, body) => {
                *step += 1;
                let cond_var = z3::ast::Bool::new_const(ctx, format!("while_cond_{}", step).as_str());
                let state_after_body = verify_stmts_temporal(body, current_state.clone(), step, ctx, solver)?;
                
                let next_state = z3::ast::Int::new_const(ctx, format!("state_{}", step).as_str());
                let constraint = next_state._eq(&cond_var.ite(&state_after_body, &current_state));
                let marker = z3::ast::Bool::new_const(ctx, format!("while_merge_{}", step).as_str());
                solver.assert_and_track(&constraint, &marker);
                
                current_state = next_state;
            }
            Stmt::Return(_) => {
                *step += 1;
                // Early return must also satisfy the CLOSED invariant
                let constraint = current_state._eq(&z3::ast::Int::from_i64(ctx, 0));
                let marker = z3::ast::Bool::new_const(ctx, format!("early_return_invariant_{}", step).as_str());
                solver.assert_and_track(&constraint, &marker);
                // Return statements diverge control flow, so we just return the current state
                return Ok(current_state);
            }
            Stmt::TryCatch(try_block, catch_block) => {
                *step += 1;
                let try_state = verify_stmts_temporal(try_block, current_state.clone(), step, ctx, solver)?;
                let catch_state = verify_stmts_temporal(catch_block, current_state.clone(), step, ctx, solver)?;
                
                // An exception could happen, branching to catch
                let exc_var = z3::ast::Bool::new_const(ctx, format!("try_exc_{}", step).as_str());
                let next_state = z3::ast::Int::new_const(ctx, format!("state_{}", step).as_str());
                let constraint = next_state._eq(&exc_var.ite(&catch_state, &try_state));
                let marker = z3::ast::Bool::new_const(ctx, format!("try_catch_merge_{}", step).as_str());
                solver.assert_and_track(&constraint, &marker);
                
                current_state = next_state;
            }
            _ => {
                // Other statements do not change the resource state for this simple LTL check
            }
        }
    }
    Ok(current_state)
}
