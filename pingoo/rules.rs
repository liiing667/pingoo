use std::net::IpAddr;

use http::Uri;
use serde::Serialize;
use tracing::warn;

use crate::{geoip::CountryCode, serde_utils};

#[derive(Debug, Clone)]
pub struct Rule {
    pub name: String,
    pub expression: Option<rules::CompiledExpression>,
    pub actions: Vec<rules::Action>,
}

/// Stable audit reason emitted when a rule can't be evaluated at runtime and the request is blocked (fail closed).
pub const RULE_EVALUATION_ERROR_AUDIT_REASON: &str = "rule_evaluation_error";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleMatch {
    Match,
    NoMatch,
    /// The rule expression could not be evaluated for this request. Callers must fail closed.
    Undetermined,
}

#[derive(Debug, Serialize)]
pub struct RequestData<'a> {
    pub host: &'a str,
    #[serde(serialize_with = "serde_utils::http_uri::serialize")]
    pub url: &'a Uri,
    pub path: &'a str,
    #[serde(serialize_with = "serde_utils::http_method::serialize")]
    pub method: &'a http::Method,
    pub user_agent: &'a str,
}

#[derive(Debug, Clone, Serialize)]
pub struct ClientData {
    pub ip: IpAddr,
    // only signed integers are supported so we can't use an u16
    pub remote_port: i32,
    pub asn: i64,
    pub country: CountryCode,
}

impl Rule {
    pub fn match_request(&self, request_ctx: &rules::Context) -> RuleMatch {
        if let Some(expression) = &self.expression {
            let return_value = match expression.execute(request_ctx) {
                Ok(value) => value,
                Err(err) => {
                    warn!(rule = %self.name, reason = RULE_EVALUATION_ERROR_AUDIT_REASON, "error executing rule: {err}");
                    return RuleMatch::Undetermined;
                }
            };

            if return_value == true.into() {
                return RuleMatch::Match;
            }
            return RuleMatch::NoMatch;
        } else {
            return RuleMatch::Match;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn new_rule(name: &str, expression: Option<&str>) -> Rule {
        Rule {
            name: name.to_string(),
            expression: expression
                .map(|expression| rules::compile_expression(expression).expect("test expression should compile")),
            actions: Vec::new(),
        }
    }

    fn test_context() -> rules::Context<'static> {
        let mut ctx = rules::Context::default();
        let request_data = RequestData {
            host: "example.com",
            url: &http::Uri::from_static("http://example.com/admin"),
            path: "/admin",
            method: &http::Method::GET,
            user_agent: "pingoo-test",
        };
        ctx.add_variable("http_request", request_data)
            .expect("error adding http_request variable");
        ctx
    }

    #[test]
    fn rule_execution_match() {
        let rule = new_rule("match", Some("http_request.path == \"/admin\""));
        assert_eq!(rule.match_request(&test_context()), RuleMatch::Match);
    }

    #[test]
    fn rule_execution_no_match() {
        let rule = new_rule("no_match", Some("http_request.path == \"/login\""));
        assert_eq!(rule.match_request(&test_context()), RuleMatch::NoMatch);
    }

    #[test]
    fn rule_execution_error_is_undetermined() {
        // typo'd field: the expression compiles but can't be evaluated at runtime
        let rule = new_rule("unknown_field", Some("http_request.unknown_field == 1"));
        assert_eq!(rule.match_request(&test_context()), RuleMatch::Undetermined);

        // incompatible types
        let rule = new_rule("type_mismatch", Some("http_request.path + 1 == 2"));
        assert_eq!(rule.match_request(&test_context()), RuleMatch::Undetermined);
    }

    #[test]
    fn rule_execution_without_expression_is_catch_all() {
        let rule = new_rule("catch_all", None);
        assert_eq!(rule.match_request(&test_context()), RuleMatch::Match);
    }
}

// fn serialize_arc_string<S>(value: &Arc<String>, serializer: S) -> Result<S::Ok, S::Error>
// where
//     S: serde::Serializer,
// {
//     serializer.serialize_str(value)
// }
