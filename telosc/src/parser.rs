use chumsky::prelude::*;
use std::str::FromStr;

#[derive(Debug, Clone, PartialEq)]
pub enum CapabilityKind {
    NetConnect,
    NetBind,
    FileOpen,
    FileExecute,
    ProcessFork,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Constraint {
    Host(String),
    Port(u16),
    Path(String),
    Mode(String),
}

#[derive(Debug, Clone, PartialEq)]
pub struct CapabilityDecl {
    pub kind: CapabilityKind,
    pub constraints: Vec<Constraint>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct IntentDecl {
    pub name: String,
    pub capabilities: Vec<CapabilityDecl>,
}

// -- IFC TYPE LATTICE --
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecurityLabel {
    Secret,
    Tainted,
    Public,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Type {
    I64(SecurityLabel),
    String(SecurityLabel),
    Void,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Expr {
    Number(i64),
    StringLiteral(String),
    Var(String),
    Call(String, Vec<Expr>),
    /// declassify(expr, "ALGORITHM") — strips Secret label to Public via cryptographic boundary
    Declassify(Box<Expr>, String),
}

#[derive(Debug, Clone, PartialEq)]
pub enum Stmt {
    Let(String, Type, Expr),
    Assign(String, Expr),
    If(Expr, Vec<Stmt>),
    Expr(Expr),
}

#[derive(Debug, Clone, PartialEq)]
pub struct Function {
    pub name: String,
    pub bound_intent: Option<String>,
    pub args: Vec<(String, Type)>,
    pub ret_type: Type,
    pub body: Vec<Stmt>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Program {
    pub intents: Vec<IntentDecl>,
    pub functions: Vec<Function>,
}

// --- PARSER COMBINATORS ---

pub fn capability_parser() -> impl Parser<char, CapabilityDecl, Error = Simple<char>> {
    let kind_parser = just("Capability::Net::Connect").to(CapabilityKind::NetConnect)
        .or(just("Capability::Net::Bind").to(CapabilityKind::NetBind))
        .or(just("Capability::File::Open").to(CapabilityKind::FileOpen))
        .or(just("Capability::File::Execute").to(CapabilityKind::FileExecute))
        .or(just("Capability::Process::Fork").to(CapabilityKind::ProcessFork))
        .padded();
        
    let string_literal = filter(|&c: &char| c != '"')
        .repeated()
        .delimited_by(just('"'), just('"'))
        .collect::<String>();
        
    let number_literal = text::int(10).try_map(|s: String, span| {
        u16::from_str(&s).map_err(|e| Simple::custom(span, format!("{}", e)))
    });

    // Field parsers
    let host_field = just("host:").padded().ignore_then(string_literal.clone()).map(Constraint::Host);
    let port_field = just("port:").padded().ignore_then(number_literal).map(Constraint::Port);
    let path_field = just("path:").padded().ignore_then(string_literal.clone()).map(Constraint::Path);
    let mode_field = just("mode:").padded().ignore_then(text::ident()).map(Constraint::Mode);
    
    let constraint = host_field
        .or(port_field)
        .or(path_field)
        .or(mode_field)
        .then_ignore(just(',').padded().or_not());
        
    let constraints_block = constraint.repeated().padded()
        .delimited_by(just('{').padded(), just('}').padded());
        
    just("allow").padded()
        .ignore_then(kind_parser)
        .then(constraints_block)
        .map(|(kind, constraints)| CapabilityDecl { kind, constraints })
}

pub fn intent_parser() -> impl Parser<char, IntentDecl, Error = Simple<char>> {
    let ident = text::ident().padded();
    
    just("intent").padded()
        .ignore_then(ident)
        .then(capability_parser().repeated().delimited_by(just('{').padded(), just('}').padded()))
        .map(|(name, capabilities)| IntentDecl { name, capabilities })
}

pub fn type_parser() -> impl Parser<char, Type, Error = Simple<char>> {
    let label = just("Secret").to(SecurityLabel::Secret)
        .or(just("Tainted").to(SecurityLabel::Tainted))
        .or(just("Public").to(SecurityLabel::Public));

    let string_inner = just("String");
    let int_inner = just("I64");

    label
        .then(just('<').padded())
        .then(string_inner.or(int_inner))
        .then(just('>').padded())
        .map(|(((lbl, _), inner_type), _)| {
            if inner_type == "String" {
                Type::String(lbl)
            } else {
                Type::I64(lbl)
            }
        })
}

pub fn expr_parser() -> impl Parser<char, Expr, Error = Simple<char>> {
    let string_literal = filter(|&c: &char| c != '"')
        .repeated()
        .delimited_by(just('"'), just('"'))
        .collect::<String>()
        .map(Expr::StringLiteral);

    let number_literal = text::int(10).try_map(|s: String, span| {
        i64::from_str(&s).map_err(|e| Simple::custom(span, format!("{}", e)))
    }).map(Expr::Number);

    let algorithm_literal = filter(|&c: &char| c != '"')
        .repeated()
        .delimited_by(just('"'), just('"'))
        .collect::<String>();

    let var = text::ident().map(Expr::Var);

    // declassify(var, "AES-GCM")
    let declassify = just("declassify").padded()
        .ignore_then(just('(').padded())
        .ignore_then(text::ident().padded())
        .then_ignore(just(',').padded())
        .then(algorithm_literal.padded())
        .then_ignore(just(')').padded())
        .map(|(var_name, algo)| Expr::Declassify(Box::new(Expr::Var(var_name)), algo));
    
    declassify.or(string_literal).or(number_literal).or(var).padded()
}

pub fn stmt_parser() -> impl Parser<char, Stmt, Error = Simple<char>> {
    let let_stmt = just("let").padded()
        .ignore_then(text::ident().padded())
        .then_ignore(just(':').padded())
        .then(type_parser().padded())
        .then_ignore(just('=').padded())
        .then(expr_parser())
        .then_ignore(just(';').padded())
        .map(|((name, ty), expr)| Stmt::Let(name, ty, expr));
        
    let assign_stmt = text::ident().padded()
        .then_ignore(just('=').padded())
        .then(expr_parser())
        .then_ignore(just(';').padded())
        .map(|(name, expr)| Stmt::Assign(name, expr));
        
    let expr_stmt = expr_parser()
        .then_ignore(just(';').padded())
        .map(Stmt::Expr);

    // Provide recursive placeholder
    let mut stmt = Recursive::declare();

    let if_stmt = just("if").padded()
        .ignore_then(expr_parser().padded())
        .then_ignore(just('{').padded())
        .then(stmt.clone().repeated())
        .then_ignore(just('}').padded())
        .map(|(cond, body)| Stmt::If(cond, body));

    stmt.define(let_stmt.or(assign_stmt).or(if_stmt).or(expr_stmt));
    stmt
}

pub fn function_parser() -> impl Parser<char, Function, Error = Simple<char>> {
    just("fn").padded()
        .ignore_then(text::ident().padded())
        .then_ignore(just("()").padded())
        .then_ignore(just("->").padded())
        .then(just("Void").padded().to(Type::Void))
        .then_ignore(just('{').padded())
        .then(stmt_parser().repeated())
        .then_ignore(just('}').padded())
        .map(|((name, ret_type), body)| Function {
            name,
            bound_intent: None,
            args: vec![],
            ret_type,
            body
        })
}

pub fn program_parser() -> impl Parser<char, Program, Error = Simple<char>> {
    intent_parser().repeated().padded()
        .then(function_parser().repeated().padded())
        .map(|(intents, functions)| Program { intents, functions })
        .then_ignore(end())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_net_connect_intent() {
        let src = r#"
        intent fetch {
            allow Capability::Net::Connect {
                host: "example.com",
                port: 80,
            }
        }
        "#;
        
        let result = intent_parser().parse(src);
        assert!(result.is_ok(), "Failed to parse: {:?}", result.err());
        let decl = result.unwrap();
        
        assert_eq!(decl.name, "fetch");
        assert_eq!(decl.capabilities.len(), 1);
        assert_eq!(decl.capabilities[0].kind, CapabilityKind::NetConnect);
        assert_eq!(decl.capabilities[0].constraints[0], Constraint::Host("example.com".to_string()));
        assert_eq!(decl.capabilities[0].constraints[1], Constraint::Port(80));
    }
}
