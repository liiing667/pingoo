use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    pub id: Uuid,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,

    pub name: String,
    pub description: String,
    pub enabled: bool,
    pub position: i32,
    pub expression: String,
    pub actions: Vec<Action>,

    pub project_id: Option<Uuid>,
    pub ruleset_id: Option<Uuid>,
}

pub type CompiledExpression = bel::Program;
pub type Context<'a> = bel::Context<'a>;

/// Top-level variables available to rules and routes expressions at runtime.
/// Expressions referencing variables outside of this list are rejected when the configuration is loaded.
pub const KNOWN_EXPRESSION_VARIABLES: [&str; 3] = ["http_request", "client", "lists"];

// pub struct CompiledRule {
//     pub id: Uuid,
//     pub updated_at: DateTime<Utc>,
// }

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum Action {
    Block {},
    Captcha {},
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("{0}")]
    Unspecified(String),
    #[error("Expression is not valid: {0}")]
    ExpressionIsNotValid(String),
}

pub fn compile_expression(expression: &str) -> Result<CompiledExpression, Error> {
    validate_expression(expression)?;

    let program = match std::panic::catch_unwind(|| bel::Program::compile(expression)) {
        Ok(Ok(program)) => program,
        Ok(Err(err)) => return Err(Error::ExpressionIsNotValid(err.to_string())),
        Err(_) => return Err(Error::ExpressionIsNotValid("invalid input".to_string())),
    };

    return Ok(program);
}

pub fn validate_expression(expression: &str) -> Result<(), Error> {
    if expression.is_empty() {
        return Err(Error::ExpressionIsNotValid("expression is empty".to_string()));
    }

    let program = match std::panic::catch_unwind(|| bel::Program::compile(expression)) {
        Ok(Ok(program)) => program,
        Ok(Err(err)) => return Err(Error::ExpressionIsNotValid(err.to_string())),
        Err(_) => return Err(Error::ExpressionIsNotValid("invalid input".to_string())),
    };
    let references = program.references();

    // validate functions
    let functions = references.functions();
    if functions.contains(&"@in") {
        return Err(Error::ExpressionIsNotValid("unknown operator: in".to_string()));
    }

    // validate variables
    let mut variables = Vec::new();
    collect_free_variables(program.expression(), &mut Vec::new(), &mut variables);
    for variable in variables {
        if !KNOWN_EXPRESSION_VARIABLES.contains(&variable.as_str()) {
            return Err(Error::ExpressionIsNotValid(format!("unknown reference: {variable}")));
        }
    }

    return Ok(());
}

/// Collects the free (top-level) variables referenced by a compiled expression,
/// excluding the variables bound by comprehension macros such as `map` or `any`.
fn collect_free_variables(
    expression: &bel::common::ast::IdedExpr,
    bound_variables: &mut Vec<String>,
    variables: &mut Vec<String>,
) {
    use bel::common::ast::{EntryExpr, Expr};

    match &expression.expr {
        Expr::Unspecified | Expr::Literal(_) => {}
        Expr::Ident(name) => {
            if !name.starts_with('@') && !bound_variables.contains(name) && !variables.contains(name) {
                variables.push(name.clone());
            }
        }
        Expr::Call(call) => {
            if let Some(target) = &call.target {
                collect_free_variables(target, bound_variables, variables);
            }
            for argument in &call.args {
                collect_free_variables(argument, bound_variables, variables);
            }
        }
        Expr::Comprehension(comprehension) => {
            collect_free_variables(&comprehension.iter_range, bound_variables, variables);
            let bound_variables_count = bound_variables.len();
            bound_variables.push(comprehension.iter_var.clone());
            if let Some(iter_var2) = &comprehension.iter_var2 {
                bound_variables.push(iter_var2.clone());
            }
            bound_variables.push(comprehension.accu_var.clone());
            collect_free_variables(&comprehension.accu_init, bound_variables, variables);
            collect_free_variables(&comprehension.loop_cond, bound_variables, variables);
            collect_free_variables(&comprehension.loop_step, bound_variables, variables);
            collect_free_variables(&comprehension.result, bound_variables, variables);
            bound_variables.truncate(bound_variables_count);
        }
        Expr::List(list) => {
            for element in &list.elements {
                collect_free_variables(element, bound_variables, variables);
            }
        }
        Expr::Map(map) => {
            for entry in &map.entries {
                match &entry.expr {
                    EntryExpr::StructField(field) => collect_free_variables(&field.value, bound_variables, variables),
                    EntryExpr::MapEntry(map_entry) => {
                        collect_free_variables(&map_entry.key, bound_variables, variables);
                        collect_free_variables(&map_entry.value, bound_variables, variables);
                    }
                }
            }
        }
        Expr::Select(select) => collect_free_variables(&select.operand, bound_variables, variables),
        Expr::Struct(struct_expression) => {
            for entry in &struct_expression.entries {
                match &entry.expr {
                    EntryExpr::StructField(field) => collect_free_variables(&field.value, bound_variables, variables),
                    EntryExpr::MapEntry(map_entry) => {
                        collect_free_variables(&map_entry.key, bound_variables, variables);
                        collect_free_variables(&map_entry.value, bound_variables, variables);
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_expression_accepts_known_variables() {
        assert!(validate_expression("http_request.path == \"/admin\"").is_ok());
        assert!(validate_expression("client.asn == 1234").is_ok());
        assert!(validate_expression("http_request.host == \"example.com\" && client.country == \"FR\"").is_ok());
        // comprehension macros bind their iteration variable, which must not be treated as an unknown reference
        assert!(validate_expression("lists[\"allowlist\"].any(ip, ip == client.ip)").is_ok());
    }

    #[test]
    fn validate_expression_rejects_unknown_variables() {
        assert!(validate_expression("htt_request.path == \"/admin\"").is_err());
        assert!(validate_expression("request.path == \"/admin\"").is_err());
        assert!(validate_expression("unknown == 1").is_err());
    }

    #[test]
    fn validate_expression_rejects_empty_expression() {
        assert!(validate_expression("").is_err());
    }

    #[test]
    fn validate_expression_rejects_invalid_syntax() {
        assert!(validate_expression("http_request.path ==").is_err());
    }

    #[test]
    fn validate_expression_rejects_in_operator() {
        assert!(validate_expression("client.ip in lists").is_err());
    }

    #[test]
    fn compile_expression_rejects_unknown_references() {
        assert!(compile_expression("unknown_variable == 1").is_err());
        assert!(compile_expression("http_request.path == \"/admin\"").is_ok());
    }
}
