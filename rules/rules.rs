use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tracing::error;
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

/// Outcome of evaluating a security-relevant expression (rule or route).
///
/// Any situation where the result can not be determined with certainty is
/// represented as [`MatchOutcome::Indeterminate`] instead of being silently
/// treated as a non-match. Callers are expected to fail closed: rules must
/// block and routes must not forward the request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MatchOutcome {
    /// The expression evaluated to the boolean `true`.
    Matched,
    /// The expression evaluated to the boolean `false`.
    NotMatched,
    /// The result can not be determined: the expression returned a non-boolean
    /// value, evaluation returned an error, or the evaluator panicked.
    Indeterminate,
}

/// Stable machine-readable reason explaining why an evaluation was
/// [`MatchOutcome::Indeterminate`]. The strings are part of the audit trail and
/// must remain stable over time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EvaluationErrorReason {
    /// The expression returned a value whose type is not `Bool`.
    NonBooleanResult,
    /// The BEL evaluator returned an [`bel::ExecutionError`].
    ExecutionError,
    /// The BEL evaluator panicked instead of returning normally.
    EvaluatorPanic,
}

impl EvaluationErrorReason {
    pub fn as_str(&self) -> &'static str {
        match self {
            EvaluationErrorReason::NonBooleanResult => "non_boolean_result",
            EvaluationErrorReason::ExecutionError => "execution_error",
            EvaluationErrorReason::EvaluatorPanic => "evaluator_panic",
        }
    }
}

/// Evaluates a compiled expression against `context` without ever failing open.
///
/// All undecidable situations (evaluation errors, non-boolean results and
/// evaluator panics) are collapsed into [`MatchOutcome::Indeterminate`] and an
/// audit log line carrying a stable [`EvaluationErrorReason`].
pub fn evaluate_expression(expression: &CompiledExpression, context: &Context) -> MatchOutcome {
    let resolved = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| expression.execute(context)));

    return match resolved {
        Ok(Ok(bel::Value::Bool(is_match))) => {
            if is_match {
                MatchOutcome::Matched
            } else {
                MatchOutcome::NotMatched
            }
        }
        Ok(Ok(value)) => {
            error!(
                reason = EvaluationErrorReason::NonBooleanResult.as_str(),
                value_type = ?value.type_of(),
                "expression did not return a boolean; failing closed"
            );
            MatchOutcome::Indeterminate
        }
        Ok(Err(err)) => {
            error!(
                reason = EvaluationErrorReason::ExecutionError.as_str(),
                error = %err,
                "expression evaluation failed; failing closed"
            );
            MatchOutcome::Indeterminate
        }
        Err(_) => {
            error!(
                reason = EvaluationErrorReason::EvaluatorPanic.as_str(),
                "expression evaluator panicked; failing closed"
            );
            MatchOutcome::Indeterminate
        }
    };
}

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
    // TODO

    return Ok(());
}

#[cfg(test)]
mod tests {
    use super::*;

    fn context_with_path(path: &str) -> Context<'static> {
        #[derive(serde::Serialize)]
        struct HttpRequest<'a> {
            path: &'a str,
        }

        let mut context = Context::default();
        context
            .add_variable("http_request", HttpRequest { path })
            .expect("context variable must be inserted");
        return context;
    }

    fn evaluate(source: &str, context: &Context) -> MatchOutcome {
        let program = compile_expression(source).expect("expression must compile");
        return evaluate_expression(&program, context);
    }

    #[test]
    fn benign_boolean_expressions_keep_their_normal_semantics() {
        let context = context_with_path("/admin");

        assert_eq!(evaluate("http_request.path == \"/admin\"", &context), MatchOutcome::Matched);
        assert_eq!(evaluate("http_request.path == \"/login\"", &context), MatchOutcome::NotMatched);
        assert_eq!(
            evaluate("http_request.path.starts_with(\"/ad\")", &context),
            MatchOutcome::Matched
        );
        assert_eq!(
            evaluate("http_request.path == \"/admin\" || http_request.path == \"/login\"", &context),
            MatchOutcome::Matched
        );
        assert_eq!(
            evaluate("http_request.path == \"/x\" && http_request.path == \"/y\"", &context),
            MatchOutcome::NotMatched
        );
    }

    #[test]
    fn evaluation_errors_fail_closed() {
        let context = context_with_path("/admin");

        // undeclared variable
        assert_eq!(evaluate("unknown_variable == 1", &context), MatchOutcome::Indeterminate);
        // missing field on a known variable
        assert_eq!(
            evaluate("http_request.missing_field == \"x\"", &context),
            MatchOutcome::Indeterminate
        );
        // operator with no overload for the operand types
        assert_eq!(
            evaluate("http_request.path + 1 == \"x\"", &context),
            MatchOutcome::Indeterminate
        );
        // ordering on non comparable types
        assert_eq!(evaluate("http_request.path > 1", &context), MatchOutcome::Indeterminate);
        // division by zero
        assert_eq!(evaluate("1 / 0 == 1", &context), MatchOutcome::Indeterminate);
    }

    #[test]
    fn non_boolean_results_are_indeterminate() {
        let context = context_with_path("/admin");

        assert_eq!(evaluate("http_request.path", &context), MatchOutcome::Indeterminate);
        assert_eq!(evaluate("1 + 1", &context), MatchOutcome::Indeterminate);
    }

    #[test]
    fn stable_reason_strings_do_not_change() {
        assert_eq!(EvaluationErrorReason::NonBooleanResult.as_str(), "non_boolean_result");
        assert_eq!(EvaluationErrorReason::ExecutionError.as_str(), "execution_error");
        assert_eq!(EvaluationErrorReason::EvaluatorPanic.as_str(), "evaluator_panic");
    }

    #[test]
    fn evaluator_panics_are_caught_and_fail_closed() {
        let mut context = context_with_path("/admin");
        context.add_variable("not_a_list", 42).expect("variable must be inserted");

        // iterating a comprehension over a non-iterable value reaches a `todo!` path in bel;
        // the panic must be contained and reported as indeterminate.
        let program = compile_expression("not_a_list.all(x, x > 0)").expect("expression must compile");
        assert_eq!(evaluate_expression(&program, &context), MatchOutcome::Indeterminate);
    }
}
