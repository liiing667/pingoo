use std::net::IpAddr;

use http::Uri;
use serde::Serialize;

use crate::{geoip::CountryCode, serde_utils};

pub use rules::MatchOutcome;

#[derive(Debug, Clone)]
pub struct Rule {
    pub name: String,
    pub expression: Option<rules::CompiledExpression>,
    pub actions: Vec<rules::Action>,
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
    /// Evaluates the rule expression against the request context.
    ///
    /// Rules without an expression always match. Any undecidable evaluation
    /// result is surfaced as [`rules::MatchOutcome::Indeterminate`] so the
    /// caller can fail closed instead of silently letting the request through.
    pub fn match_request(&self, request_ctx: &rules::Context) -> rules::MatchOutcome {
        if let Some(expression) = &self.expression {
            return rules::evaluate_expression(expression, request_ctx);
        }

        return rules::MatchOutcome::Matched;
    }
}

#[cfg(test)]
mod tests {
    use std::{
        net::{IpAddr, Ipv4Addr},
        str::FromStr,
    };

    use http::{Method, Uri};

    use super::*;
    use crate::geoip::CountryCode;

    struct TestContext {
        host: String,
        path: String,
        uri: Uri,
        method: Method,
        user_agent: String,
        client_data: ClientData,
    }

    impl TestContext {
        fn new() -> Self {
            Self {
                host: "example.com".to_string(),
                path: "/admin".to_string(),
                uri: Uri::from_static("http://example.com/admin"),
                method: Method::GET,
                user_agent: "pingoo-test".to_string(),
                client_data: ClientData {
                    ip: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7)),
                    remote_port: 40_123,
                    asn: 64_500,
                    country: CountryCode::from_str("US").expect("valid country code"),
                },
            }
        }

        fn bel_context(&self) -> rules::Context<'_> {
            let request_data = RequestData {
                host: &self.host,
                path: &self.path,
                url: &self.uri,
                method: &self.method,
                user_agent: &self.user_agent,
            };
            let mut context = rules::Context::default();
            context
                .add_variable("http_request", request_data)
                .expect("http_request variable");
            context
                .add_variable("client", &self.client_data)
                .expect("client variable");
            return context;
        }

        fn rule(&self, expression: &str) -> Rule {
            Rule {
                name: "test-rule".to_string(),
                expression: Some(rules::compile_expression(expression).expect("valid expression")),
                actions: vec![rules::Action::Block {}],
            }
        }
    }

    #[test]
    fn benign_rules_keep_normal_match_semantics() {
        let fixture = TestContext::new();
        let context = fixture.bel_context();

        assert_eq!(
            fixture.rule("http_request.path == \"/admin\"").match_request(&context),
            MatchOutcome::Matched
        );
        assert_eq!(
            fixture.rule("http_request.path == \"/other\"").match_request(&context),
            MatchOutcome::NotMatched
        );
        // IP equality on the actual client IP keeps normal boolean semantics
        assert_eq!(
            fixture
                .rule("client.ip == Ip(\"198.51.100.7\")")
                .match_request(&context),
            MatchOutcome::Matched
        );
        assert_eq!(
            fixture.rule("client.ip == Ip(\"10.0.0.1\")").match_request(&context),
            MatchOutcome::NotMatched
        );
    }

    #[test]
    fn expression_errors_are_indeterminate_not_silently_allowed() {
        let fixture = TestContext::new();
        let context = fixture.bel_context();

        // previously returned `false` (non-match) and let the request through
        assert_eq!(
            fixture.rule("unknown_variable == 1").match_request(&context),
            MatchOutcome::Indeterminate
        );
        assert_eq!(
            fixture
                .rule("http_request.nonexistent == \"x\"")
                .match_request(&context),
            MatchOutcome::Indeterminate
        );
        assert_eq!(
            fixture.rule("client.remote_port / 0 == 1").match_request(&context),
            MatchOutcome::Indeterminate
        );
    }

    #[test]
    fn non_boolean_rule_results_are_indeterminate() {
        let fixture = TestContext::new();
        let context = fixture.bel_context();

        assert_eq!(
            fixture.rule("http_request.path").match_request(&context),
            MatchOutcome::Indeterminate
        );
        assert_eq!(fixture.rule("1 + 1").match_request(&context), MatchOutcome::Indeterminate);
    }

    #[test]
    fn rule_without_expression_always_matches() {
        let fixture = TestContext::new();
        let context = fixture.bel_context();
        let rule = Rule {
            name: "expressionless-rule".to_string(),
            expression: None,
            actions: vec![rules::Action::Block {}],
        };

        assert_eq!(rule.match_request(&context), MatchOutcome::Matched);
    }
}

// fn serialize_arc_string<S>(value: &Arc<String>, serializer: S) -> Result<S::Ok, S::Error>
// where
//     S: serde::Serializer,
// {
//     serializer.serialize_str(value)
// }
