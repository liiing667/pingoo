use std::{
    os::unix::{ffi::OsStrExt, fs::MetadataExt},
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, UNIX_EPOCH},
};

use aws_lc_rs::digest;
use bytes::Bytes;
use futures::TryStreamExt;
use http::{Method, Request, Response, StatusCode, header};
use http_body_util::{BodyExt, Full, StreamBody, combinators::BoxBody};
use hyper::body::Frame;
use moka::future::Cache;
use tokio::fs::{self, File};
use tokio_util::io::ReaderStream;
use tracing::{debug, error, warn};

use crate::{
    config::{ServiceConfig, StaticSiteServiceConfig},
    services::{
        HttpService,
        http_utils::{
            CACHE_CONTROL_DYNAMIC, new_internal_error_response_500, new_method_not_allowed_error, new_not_found_error,
        },
    },
};

const CACHING_FILE_SIZE_LIMIT: u64 = 500_000; // 500 KB
// only cache the 500 most popular files
const CACHE_CAPACITY: u64 = 500;

pub struct StaticSiteService {
    name: Arc<String>,
    route: Option<rules::CompiledExpression>,
    config: StaticSiteServiceConfig,
    /// canonicalized (symlinks and dot segments resolved) version of `config.root`.
    /// All served files must live under this directory.
    canonical_root: PathBuf,
    /// in-memory cache for popular files
    cache: Cache<PathBuf, Arc<CachedFile>>,
}

#[derive(Clone)]
struct CachedFile {
    /// Unix timestamp (nanoseconds) of the file's last modification
    modified_at: u128,
    /// size in bytes
    size: u64,
    /// content of the file
    data: Bytes,
}

impl StaticSiteService {
    pub fn new(config: ServiceConfig) -> Self {
        let cache = Cache::builder()
            .max_capacity(CACHE_CAPACITY)
            // Time to live (TTL): 1 hour
            .time_to_idle(Duration::from_secs(3600))
            .build();
        let static_config = config.r#static.unwrap();
        let canonical_root = std::fs::canonicalize(&static_config.root).unwrap_or_else(|err| {
            warn!("error canonicalizing static site root {:?}: {err}", static_config.root);
            static_config.root.clone()
        });
        return StaticSiteService {
            config: static_config,
            route: config.route,
            name: Arc::new(config.name),
            canonical_root,
            cache,
        };
    }
}

#[async_trait::async_trait]
impl HttpService for StaticSiteService {
    fn match_request(&self, ctx: &rules::Context) -> bool {
        match &self.route {
            None => true,
            Some(route) => match route.execute(&ctx) {
                Ok(value) => value == true.into(),
                Err(err) => {
                    warn!("error executing route for service {}: {err}", self.name);
                    false
                }
            },
        }
    }

    async fn handle_http_request(&self, req: Request<hyper::body::Incoming>) -> Response<BoxBody<Bytes, hyper::Error>> {
        let url_path = req.uri().path().trim_start_matches('/').trim_end_matches('/').trim();

        if req.method() != Method::GET && req.method() != Method::HEAD {
            return new_method_not_allowed_error();
        }

        // resolve the requested path to a canonical file path, guaranteed to live
        // under the configured root directory. Anything else (dot segments, backslashes,
        // percent-encoded traversal, symlinks escaping the root...) is rejected.
        let Some(file_path) = resolve_path(&self.canonical_root, &self.config.root, url_path).await else {
            debug!("error getting {url_path:?}: path is not valid or not found");
            return new_not_found_error();
        };

        let file_metadata = match fs::metadata(&file_path).await {
            Ok(metadata) if metadata.is_dir() => {
                debug!("error getting {file_path:?}: is a directory");
                return new_not_found_error();
            }
            Ok(metadata) => metadata,
            Err(err) => {
                error!("error getting metadata for static file: {file_path:?}: {err}");
                return new_internal_error_response_500();
            }
        };

        // get the file extension from its content type
        let file_extension = file_path.extension().unwrap_or_default().to_str().unwrap_or_default();
        let content_type = media_type::from_ext(file_extension).first_or_octet_stream().to_string();
        // Unix timestamp (nanoseconds) of the file's last modification time
        let file_size = file_metadata.size();
        let mut res = Response::builder()
            .header(header::CONTENT_LENGTH, file_size.to_string())
            .header(header::CONTENT_TYPE, &content_type)
            .header(header::CACHE_CONTROL, CACHE_CONTROL_DYNAMIC);

        // only files with accessible metadata are eligible for etag and (maybe) caching
        if let Some(file_modified_at) = file_metadata
            .modified()
            .ok()
            .map(|modified| modified.duration_since(UNIX_EPOCH).map(|modified| modified.as_nanos()))
            .and_then(|modified| modified.ok())
        {
            // TODO: using size + modification time for Etag may not be good enough.
            // But, how to compute Etag for files that are too big and thus need to be streamed back?
            // It's these larger files that may benefit the most from ETag caching.
            let mut etag_hasher = digest::Context::new(&digest::SHA256);
            etag_hasher.update(file_path.as_os_str().as_bytes());
            etag_hasher.update(&file_size.to_le_bytes());
            etag_hasher.update(&file_modified_at.to_le_bytes());
            let etag_hash = etag_hasher.finish();
            let etag = format!("\"{}\"", hex::encode(etag_hash.as_ref()));

            res = res.header(header::ETAG, &etag);

            // if the file's etag matches the request's IF_NONE_MATCH header:
            // send back a 304 NOT_MODIFIED response
            if let Some(if_none_match_header) = req.headers().get(header::IF_NONE_MATCH).map(|header| {
                header
                    .to_str()
                    .unwrap_or_default()
                    .trim()
                    .trim_start_matches("W/")
                    .trim_matches('"')
            }) && (req.method() == Method::GET || req.method() == Method::HEAD)
                && etag.trim_matches('"') == if_none_match_header
            {
                let response = match res
                    .status(StatusCode::NOT_MODIFIED)
                    .body(Full::new(Bytes::new()).map_err(|never| match never {}).boxed())
                {
                    Ok(response) => response,
                    Err(err) => {
                        error!("error building HTTP response for NOT_MODIFIED file: {err:?}");
                        new_internal_error_response_500()
                    }
                };
                return response;
            }

            // if the file is of reasonnable size, cache it in memory
            if file_size <= CACHING_FILE_SIZE_LIMIT {
                // if a cache entry is available for this file
                if let Some(cached_file) = self.cache.get(&file_path).await {
                    if cached_file.modified_at == file_modified_at && cached_file.size == file_size {
                        // otherwise send back the entire file from cache
                        let response = match res.status(StatusCode::OK).body(
                            Full::new(cached_file.data.clone())
                                .map_err(|never| match never {})
                                .boxed(),
                        ) {
                            Ok(response) => response,
                            Err(err) => {
                                error!("error building HTTP response for cached static file: {err:?}");
                                new_internal_error_response_500()
                            }
                        };
                        return response;
                    } else {
                        // file is cached but has been modified: remove it from the cache.
                        self.cache.remove(&file_path).await;
                    }
                }

                // file is eligible for caching but not cached yet: read it and cache it
                let file_content = match fs::read(&file_path).await {
                    Ok(file) => Bytes::from_owner(file),
                    Err(err) => {
                        error!("error reading static file: {file_path:?}: {err:?}");
                        return new_internal_error_response_500();
                    }
                };

                let file_to_cache = CachedFile {
                    modified_at: file_modified_at,
                    size: file_size,
                    data: file_content.clone(), // cloning Bytes is cheap
                };
                self.cache.insert(file_path, Arc::new(file_to_cache)).await;

                let response = match res
                    .status(StatusCode::OK)
                    .body(Full::new(file_content).map_err(|_| unreachable!()).boxed())
                {
                    Ok(response) => response,
                    Err(err) => {
                        error!("error building HTTP response for cached static file: {err:?}");
                        new_internal_error_response_500()
                    }
                };
                return response;
            }
        }

        // file is not eligible for caching: send a streaming response from the filesystem
        let file = match File::open(&file_path).await {
            Ok(file) => file,
            Err(err) => {
                error!("error opening static file: {file_path:?}: {err:?}");
                return new_internal_error_response_500();
            }
        };

        // Wrap to a tokio_util::io::ReaderStream and convert to http_body_util::BoxBody
        let stream_body = StreamBody::new(ReaderStream::new(file).map_ok(Frame::data).map_err(|_| unreachable!()));
        let response = match res.status(StatusCode::OK).body(stream_body.boxed()) {
            Ok(response) => response,
            Err(err) => {
                error!("error building HTTP response for static file: {file_path:?}: {err:?}");
                return new_internal_error_response_500();
            }
        };
        return response;
    }
}

/// Percent-decode a URL path and convert it to a relative filesystem path.
///
/// Returns `None` for anything that could escape or confuse the filesystem
/// resolution: invalid percent-encoding, NUL bytes, backslashes (path
/// separators on some platforms) and `.` / `..` segments.
fn sanitize_url_path(url_path: &str) -> Option<PathBuf> {
    // reject malformed percent-encoded sequences: every '%' must be
    // followed by exactly two hexadecimal digits
    let bytes = url_path.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            if index + 2 >= bytes.len()
                || !bytes[index + 1].is_ascii_hexdigit()
                || !bytes[index + 2].is_ascii_hexdigit()
            {
                return None;
            }
            index += 3;
        } else {
            index += 1;
        }
    }

    let decoded = percent_encoding::percent_decode_str(url_path).decode_utf8().ok()?;
    if decoded.contains(['\\', '\0']) {
        return None;
    }

    let mut relative_path = PathBuf::new();
    for segment in decoded.split('/') {
        match segment {
            // skip empty segments (e.g. from "//") and current-directory segments
            "" | "." => {}
            // never allow parent-directory segments, even if they would stay
            // inside the root: reject them uniformly
            ".." => return None,
            segment => relative_path.push(segment),
        }
    }
    Some(relative_path)
}

/// Canonicalize `candidate` (resolving symlinks and dot segments) and return it
/// only if the resulting path stays within `canonical_root`.
async fn canonicalize_within_root(canonical_root: &Path, candidate: &Path) -> Option<PathBuf> {
    let canonical_path = fs::canonicalize(candidate).await.ok()?;
    if canonical_path.starts_with(canonical_root) {
        Some(canonical_path)
    } else {
        None
    }
}

/// Resolve a request URL path to an existing file inside `canonical_root`.
///
/// Directories resolve to their `index.html` file, and extension-less paths
/// fall back to `path.html` to prettify URLs. Returns `None` if the path is
/// invalid, escapes the root, or doesn't match any file.
async fn resolve_path(canonical_root: &Path, root: &Path, url_path: &str) -> Option<PathBuf> {
    let relative_path = sanitize_url_path(url_path)?;
    let candidate = root.join(&relative_path);

    if let Some(canonical_path) = canonicalize_within_root(canonical_root, &candidate).await {
        let metadata = fs::metadata(&canonical_path).await.ok()?;
        if metadata.is_dir() {
            // if it's a directory, we try the directory/index.html file
            return canonicalize_within_root(canonical_root, &canonical_path.join("index.html")).await;
        }
        return Some(canonical_path);
    }

    // prettify URLs
    // if the path has no extension and was not found, we try path + ".html"
    // e.g. /page -> /page.html
    if candidate.extension().is_none() {
        let candidate_with_extension = candidate.with_extension("html");
        return canonicalize_within_root(canonical_root, &candidate_with_extension).await;
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEST_DIR_COUNTER: AtomicU64 = AtomicU64::new(0);

    /// Create a temporary directory structure for path resolution tests:
    /// ```text
    /// base/
    /// ├── secret.txt              <- outside of the served root
    /// └── www/                    <- served root
    ///     ├── index.html
    ///     ├── page.html
    ///     ├── sub/
    ///     │   ├── index.html
    ///     │   └── file.txt
    ///     ├── link_inside         -> sub/file.txt
    ///     └── link_outside        -> ../secret.txt
    /// ```
    struct TestSite {
        base: PathBuf,
        root: PathBuf,
        canonical_root: PathBuf,
    }

    impl TestSite {
        fn new() -> TestSite {
            let unique = TEST_DIR_COUNTER.fetch_add(1, Ordering::Relaxed);
            let base = std::env::temp_dir().join(format!("pingoo-static-site-test-{}-{unique}", std::process::id()));
            let root = base.join("www");
            let sub = root.join("sub");
            std::fs::create_dir_all(&sub).expect("error creating test directories");

            std::fs::write(base.join("secret.txt"), "secret").expect("error writing test file");
            std::fs::write(root.join("index.html"), "index").expect("error writing test file");
            std::fs::write(root.join("page.html"), "page").expect("error writing test file");
            std::fs::write(sub.join("index.html"), "sub index").expect("error writing test file");
            std::fs::write(sub.join("file.txt"), "file").expect("error writing test file");
            std::os::unix::fs::symlink("sub/file.txt", root.join("link_inside")).expect("error creating symlink");
            std::os::unix::fs::symlink("../secret.txt", root.join("link_outside")).expect("error creating symlink");

            let canonical_root = std::fs::canonicalize(&root).expect("error canonicalizing test root");
            TestSite {
                base,
                root,
                canonical_root,
            }
        }

        async fn resolve(&self, url_path: &str) -> Option<PathBuf> {
            resolve_path(&self.canonical_root, &self.root, url_path).await
        }
    }

    impl Drop for TestSite {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.base);
        }
    }

    #[test]
    fn test_sanitize_url_path() {
        assert_eq!(sanitize_url_path("index.html"), Some(PathBuf::from("index.html")));
        assert_eq!(sanitize_url_path(""), Some(PathBuf::new()));
        // empty and "." segments are normalized away
        assert_eq!(sanitize_url_path("a//b/./c"), Some(PathBuf::from("a/b/c")));
        // percent-decoding is applied before checks
        assert_eq!(sanitize_url_path("a%20b.txt"), Some(PathBuf::from("a b.txt")));
        assert_eq!(sanitize_url_path("%2e%2e%2fsecret"), None);
        assert_eq!(sanitize_url_path("..%2fsecret"), None);
        // dot-dot segments are rejected
        assert_eq!(sanitize_url_path("../secret"), None);
        assert_eq!(sanitize_url_path("a/../../secret"), None);
        // backslashes are rejected
        assert_eq!(sanitize_url_path("..\\secret"), None);
        assert_eq!(sanitize_url_path("a\\b"), None);
        // invalid percent-encoding and NUL bytes are rejected
        assert_eq!(sanitize_url_path("%zz"), None);
        assert_eq!(sanitize_url_path("a%00b"), None);
    }

    #[tokio::test]
    async fn test_resolve_regular_files() {
        let site = TestSite::new();

        let index = site.resolve("index.html").await.expect("index.html should resolve");
        assert_eq!(index, site.canonical_root.join("index.html"));

        // empty path resolves to the root's index.html
        let index = site.resolve("").await.expect("root should resolve to index.html");
        assert_eq!(index, site.canonical_root.join("index.html"));

        // directories resolve to their index.html
        let index = site.resolve("sub").await.expect("sub should resolve to sub/index.html");
        assert_eq!(index, site.canonical_root.join("sub/index.html"));

        // extension-less paths fall back to .html
        let page = site.resolve("page").await.expect("page should resolve to page.html");
        assert_eq!(page, site.canonical_root.join("page.html"));

        // symlinks staying inside the root resolve to their canonical target
        let link = site.resolve("link_inside").await.expect("link_inside should resolve");
        assert_eq!(link, site.canonical_root.join("sub/file.txt"));

        // normalized equivalent paths resolve to the same canonical file
        let file = site.resolve("sub/./file.txt").await.expect("path should resolve");
        assert_eq!(file, site.canonical_root.join("sub/file.txt"));
    }

    #[tokio::test]
    async fn test_resolve_rejects_paths_outside_root() {
        let site = TestSite::new();

        // plain, percent-encoded and mixed dot-dot traversal
        assert_eq!(site.resolve("../secret.txt").await, None);
        assert_eq!(site.resolve("%2e%2e/secret.txt").await, None);
        assert_eq!(site.resolve("..%2fsecret.txt").await, None);
        assert_eq!(site.resolve("sub/../../secret.txt").await, None);
        // backslash traversal
        assert_eq!(site.resolve("..\\secret.txt").await, None);
        // symlink escaping the root
        assert_eq!(site.resolve("link_outside").await, None);
        // non-existent files
        assert_eq!(site.resolve("nope.txt").await, None);
        assert_eq!(site.resolve("nope").await, None);
    }
}
