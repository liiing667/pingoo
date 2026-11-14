use std::{net::SocketAddr, sync::Arc};

use bytes::Bytes;
use http::{HeaderValue, Request, Response, StatusCode, header};
use http_body_util::{BodyExt, Full, combinators::BoxBody};
use hyper::body::Incoming;
use serde::Serialize;

use crate::{
    config::ServiceConfig,
    geoip::CountryCode,
    service_discovery::service_registry::ServiceRegistry,
    services::{HttpService, http_proxy_service::HttpProxyService, http_static_site_service::StaticSiteService},
};

pub const CACHE_CONTROL_NO_CACHE: HeaderValue =
    HeaderValue::from_static("private, no-cache, no-store, must-revalidate");
pub const CACHE_CONTROL_DYNAMIC: HeaderValue = HeaderValue::from_static("public, no-cache, must-revalidate");

pub const USER_AGENT_MAX_LENGTH: usize = 256;
pub const HOSTNAME_MAX_LENGTH: usize = 256;

#[derive(Debug, Clone)]
pub struct RequestContext {
    pub client_address: SocketAddr,
    pub server_address: SocketAddr,
    pub asn: u32,
    pub country: CountryCode,
    pub geoip_enabled: bool,
    pub tls: bool,
    pub host: heapless::String<HOSTNAME_MAX_LENGTH>,
}

#[derive(Clone)]
pub struct RequestExtensionContext(pub Arc<RequestContext>);

// #[derive(Clone)]
// pub struct ReqExtensionCookies(pub Arc<Vec<Cookie<'static>>>);

#[derive(Debug, Serialize)]
pub struct EmptyJsonBody {}

pub fn new_http_service(config: ServiceConfig, service_registry: Arc<ServiceRegistry>) -> Arc<dyn HttpService> {
    if config.r#static.is_some() {
        return Arc::new(StaticSiteService::new(config));
    } else if config.http_proxy.is_some() {
        return Arc::new(HttpProxyService::new(config, service_registry));
    }

    unreachable!("HTTP service type not handled");
}

pub fn new_internal_error_response_500() -> Response<BoxBody<Bytes, hyper::Error>> {
    const INTERNAL_ERROR_MESSAGE: &[u8] = b"500 Internal Server Error";
    let res_body = Full::new(Bytes::from_static(INTERNAL_ERROR_MESSAGE))
        .map_err(|never| match never {})
        .boxed();
    return Response::builder()
        .status(StatusCode::INTERNAL_SERVER_ERROR)
        .header(header::CACHE_CONTROL, &CACHE_CONTROL_NO_CACHE)
        .body(res_body)
        .expect("error building new_internal_error_response_500");
}

// TODO
pub fn new_bad_gateway_error() -> Response<BoxBody<Bytes, hyper::Error>> {
    const ERROR_MESSAGE: &[u8] = b"502 Bad Gateway";
    let res_body = Full::new(Bytes::from_static(ERROR_MESSAGE))
        .map_err(|never| match never {})
        .boxed();
    return Response::builder()
        .status(StatusCode::BAD_GATEWAY)
        .header(header::CACHE_CONTROL, &CACHE_CONTROL_NO_CACHE)
        .body(res_body)
        .expect("error building new_bad_gateway_error");
}

pub fn new_not_found_error() -> Response<BoxBody<Bytes, hyper::Error>> {
    const NOT_FOUND_ERROR_MESSAGE: &[u8] = b"404 Not Found.";
    let res_body = Full::new(Bytes::from_static(NOT_FOUND_ERROR_MESSAGE))
        .map_err(|never| match never {})
        .boxed();
    return Response::builder()
        .status(StatusCode::NOT_FOUND)
        .header(header::CACHE_CONTROL, &CACHE_CONTROL_NO_CACHE)
        .body(res_body)
        .expect("error building new_not_found_error_404");
}

pub fn new_blocked_response() -> Response<BoxBody<Bytes, hyper::Error>> {
    const ERROR_MESSAGE: &[u8] = b"Permission Denied";
    let res_body = Full::new(Bytes::from_static(ERROR_MESSAGE))
        .map_err(|never| match never {})
        .boxed();
    return Response::builder()
        .status(StatusCode::FORBIDDEN)
        .header(header::CACHE_CONTROL, &CACHE_CONTROL_NO_CACHE)
        .body(res_body)
        .expect("error building blocked_response");
}

pub fn new_method_not_allowed_error() -> Response<BoxBody<Bytes, hyper::Error>> {
    const ERROR_MESSAGE: &[u8] = b"405 Method Not Allowed";
    let res_body = Full::new(Bytes::from_static(ERROR_MESSAGE))
        .map_err(|never| match never {})
        .boxed();
    return Response::builder()
        .status(StatusCode::METHOD_NOT_ALLOWED)
        .header(header::CACHE_CONTROL, &CACHE_CONTROL_NO_CACHE)
        .body(res_body)
        .expect("error building new_method_not_allowed_error");
}

pub fn get_path(req: &Request<Incoming>) -> &str {
    req.uri().path().trim_end_matches('/')
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum PathNormalizationError {
    #[error("path contains an encoded NUL byte")]
    EncodedNul,
    #[error("path contains a dot-segment escaping the root")]
    DotSegmentEscape,
    #[error("path contains an invalid percent-encoding escape")]
    InvalidEscape,
    #[error("path is not valid UTF-8 after percent-decoding")]
    InvalidUtf8,
}

/// Normalize a request path into a canonical, safe view used exclusively for rule matching.
///
/// The upstream server may normalize the path (percent-decoding, collapsing repeated
/// separators, resolving dot-segments) before serving it, so rules must be evaluated
/// against the same normalized view to avoid bypasses such as `/safe/..%2fadmin`.
///
/// The original URI is never modified: the request is forwarded to upstreams untouched.
///
/// The normalization:
/// - percent-decodes the path (hex digits are case-insensitive, e.g. `%2f` == `%2F`)
/// - rejects encoded NUL bytes (`%00`), invalid escapes (e.g. `%zz`, truncated `%2`)
///   and decoded output that is not valid UTF-8
/// - treats both `/` and `\` as separators and collapses repeated separators
/// - resolves `.` and `..` dot-segments, rejecting `..` segments that escape the root
/// - trims trailing separators, so `/` normalizes to an empty string
pub fn normalize_path_for_matching(raw_path: &str) -> Result<String, PathNormalizationError> {
    fn hex_value(byte: u8) -> Result<u8, PathNormalizationError> {
        match byte {
            b'0'..=b'9' => Ok(byte - b'0'),
            b'a'..=b'f' => Ok(byte - b'a' + 10),
            b'A'..=b'F' => Ok(byte - b'A' + 10),
            _ => Err(PathNormalizationError::InvalidEscape),
        }
    }

    let raw_bytes = raw_path.as_bytes();
    let mut decoded_bytes: Vec<u8> = Vec::with_capacity(raw_bytes.len());
    let mut index = 0;
    while index < raw_bytes.len() {
        let byte = raw_bytes[index];
        if byte == b'%' {
            if index + 3 > raw_bytes.len() {
                return Err(PathNormalizationError::InvalidEscape);
            }
            let decoded_byte = hex_value(raw_bytes[index + 1])? * 16 + hex_value(raw_bytes[index + 2])?;
            if decoded_byte == 0 {
                return Err(PathNormalizationError::EncodedNul);
            }
            decoded_bytes.push(decoded_byte);
            index += 3;
        } else {
            decoded_bytes.push(byte);
            index += 1;
        }
    }

    let decoded_path = String::from_utf8(decoded_bytes).map_err(|_| PathNormalizationError::InvalidUtf8)?;

    let mut segments: Vec<&str> = Vec::new();
    for segment in decoded_path.split(['/', '\\']) {
        match segment {
            "" | "." => {}
            ".." => {
                segments.pop().ok_or(PathNormalizationError::DotSegmentEscape)?;
            }
            segment => segments.push(segment),
        }
    }

    let mut normalized_path = String::with_capacity(decoded_path.len());
    for segment in segments {
        normalized_path.push('/');
        normalized_path.push_str(segment);
    }

    return Ok(normalized_path);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_simple_paths() {
        assert_eq!(normalize_path_for_matching("/"), Ok("".to_string()));
        assert_eq!(normalize_path_for_matching("/admin"), Ok("/admin".to_string()));
        assert_eq!(normalize_path_for_matching("/admin/"), Ok("/admin".to_string()));
        assert_eq!(normalize_path_for_matching("/a/b/c"), Ok("/a/b/c".to_string()));
    }

    #[test]
    fn collapses_repeated_separators() {
        assert_eq!(normalize_path_for_matching("//admin"), Ok("/admin".to_string()));
        assert_eq!(normalize_path_for_matching("/a//b///c"), Ok("/a/b/c".to_string()));
        assert_eq!(normalize_path_for_matching("/a/./b/./c"), Ok("/a/b/c".to_string()));
    }

    #[test]
    fn decodes_percent_encoded_characters_case_insensitively() {
        assert_eq!(normalize_path_for_matching("/%61dmin"), Ok("/admin".to_string()));
        assert_eq!(normalize_path_for_matching("/%2Fadmin"), Ok("/admin".to_string()));
        assert_eq!(normalize_path_for_matching("/%2fadmin"), Ok("/admin".to_string()));
        assert_eq!(normalize_path_for_matching("/%2E%2E/admin"), Err(PathNormalizationError::DotSegmentEscape));
        assert_eq!(normalize_path_for_matching("/%2e%2E/admin"), Err(PathNormalizationError::DotSegmentEscape));
    }

    #[test]
    fn resolves_in_bounds_dot_segments() {
        // the canonical WAF bypass: upstreams normalize it to /admin
        assert_eq!(normalize_path_for_matching("/safe/..%2fadmin"), Ok("/admin".to_string()));
        assert_eq!(normalize_path_for_matching("/safe/../admin"), Ok("/admin".to_string()));
        assert_eq!(normalize_path_for_matching("/a/b/../../c"), Ok("/c".to_string()));
    }

    #[test]
    fn rejects_dot_segments_escaping_root() {
        assert_eq!(normalize_path_for_matching("/../admin"), Err(PathNormalizationError::DotSegmentEscape));
        assert_eq!(normalize_path_for_matching("/.."), Err(PathNormalizationError::DotSegmentEscape));
        assert_eq!(normalize_path_for_matching("/a/../../b"), Err(PathNormalizationError::DotSegmentEscape));
    }

    #[test]
    fn rejects_encoded_nul() {
        assert_eq!(normalize_path_for_matching("/admin%00"), Err(PathNormalizationError::EncodedNul));
        assert_eq!(normalize_path_for_matching("/admin%00.html"), Err(PathNormalizationError::EncodedNul));
    }

    #[test]
    fn rejects_invalid_escapes() {
        assert_eq!(normalize_path_for_matching("/admin%zz"), Err(PathNormalizationError::InvalidEscape));
        assert_eq!(normalize_path_for_matching("/admin%2"), Err(PathNormalizationError::InvalidEscape));
        assert_eq!(normalize_path_for_matching("/admin%"), Err(PathNormalizationError::InvalidEscape));
        assert_eq!(normalize_path_for_matching("/admin%a"), Err(PathNormalizationError::InvalidEscape));
    }

    #[test]
    fn rejects_invalid_utf8() {
        assert_eq!(normalize_path_for_matching("/%ff%fe"), Err(PathNormalizationError::InvalidUtf8));
    }

    #[test]
    fn treats_backslash_as_separator() {
        assert_eq!(normalize_path_for_matching("/a\\b"), Ok("/a/b".to_string()));
        assert_eq!(normalize_path_for_matching("/safe\\..\\admin"), Ok("/admin".to_string()));
        assert_eq!(normalize_path_for_matching("/%5cadmin"), Ok("/admin".to_string()));
    }

    #[test]
    fn decodes_valid_utf8() {
        assert_eq!(normalize_path_for_matching("/%e4%b8%ad"), Ok("/中".to_string()));
    }
}
