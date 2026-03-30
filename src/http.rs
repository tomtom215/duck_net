// SPDX-License-Identifier: MIT
// Copyright 2026 Tom F. <tomf@tomtomtech.net> (https://github.com/tomtom215)

use std::io::Read as _;
use std::sync::LazyLock;
use std::time::Duration;

use ureq::tls::{RootCerts, TlsConfig};
use ureq::Agent;

/// Maximum response body size: 256 MiB.
/// Prevents OOM from unbounded response buffering (CWE-400).
const MAX_RESPONSE_BODY_BYTES: u64 = 256 * 1024 * 1024;

/// Maximum number of redirects to follow before giving up (CWE-601).
/// Prevents redirect loops and limits exposure during redirect chains.
const MAX_REDIRECTS: usize = 10;

/// Default global timeout per request (connect + transfer).
const DEFAULT_TIMEOUT_SECS: u64 = 30;

/// Default maximum retry attempts (0 = no retries).
const DEFAULT_MAX_RETRIES: u32 = 0;

/// Default base backoff delay in milliseconds.
const DEFAULT_RETRY_BACKOFF_MS: u64 = 1000;

/// Default backoff multiplier (exponential).
const DEFAULT_RETRY_BACKOFF_FACTOR: f64 = 2.0;

/// HTTP status codes that are retryable by default.
const DEFAULT_RETRYABLE_STATUSES: &[u16] = &[429, 500, 502, 503, 504];

// ===== User-configurable globals =====

static GLOBAL_MAX_RETRIES: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
static GLOBAL_RETRY_BACKOFF_MS: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(1000);
static GLOBAL_TIMEOUT_SECS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(30);
static GLOBAL_RETRY_STATUSES: std::sync::LazyLock<std::sync::Mutex<Vec<u16>>> =
    std::sync::LazyLock::new(|| std::sync::Mutex::new(DEFAULT_RETRYABLE_STATUSES.to_vec()));

pub fn set_max_retries(n: u32) {
    GLOBAL_MAX_RETRIES.store(n, std::sync::atomic::Ordering::Relaxed);
}
pub fn get_max_retries() -> u32 {
    GLOBAL_MAX_RETRIES.load(std::sync::atomic::Ordering::Relaxed)
}

pub fn set_retry_backoff_ms(ms: u64) {
    GLOBAL_RETRY_BACKOFF_MS.store(ms, std::sync::atomic::Ordering::Relaxed);
}
pub fn get_retry_backoff_ms() -> u64 {
    GLOBAL_RETRY_BACKOFF_MS.load(std::sync::atomic::Ordering::Relaxed)
}

pub fn set_timeout_secs(s: u64) {
    GLOBAL_TIMEOUT_SECS.store(s, std::sync::atomic::Ordering::Relaxed);
}
pub fn get_timeout_secs() -> u64 {
    GLOBAL_TIMEOUT_SECS.load(std::sync::atomic::Ordering::Relaxed)
}

pub fn set_retry_statuses(statuses: Vec<u16>) {
    *GLOBAL_RETRY_STATUSES.lock().unwrap() = statuses;
}
pub fn get_retry_statuses() -> Vec<u16> {
    GLOBAL_RETRY_STATUSES.lock().unwrap().clone()
}

pub static AGENT: LazyLock<Agent> = LazyLock::new(|| {
    // Use the platform's native certificate verifier so we trust the OS CA store.
    // This is critical for environments with corporate proxies or custom CAs.
    let tls = TlsConfig::builder()
        .root_certs(RootCerts::PlatformVerifier)
        .build();

    Agent::config_builder()
        .tls_config(tls)
        .http_status_as_error(false)
        // Disable automatic redirects: we implement our own redirect following
        // with per-hop SSRF validation so redirect chains can't escape to
        // private/internal networks (CWE-918 / redirect-based SSRF).
        .max_redirects(0)
        .timeout_global(Some(Duration::from_secs(DEFAULT_TIMEOUT_SECS)))
        .build()
        .into()
});

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Method {
    Get = 0,
    Post = 1,
    Put = 2,
    Patch = 3,
    Delete = 4,
    Head = 5,
    Options = 6,
}

impl Method {
    pub fn from_str(s: &str) -> Option<Self> {
        if s.eq_ignore_ascii_case("GET") {
            Some(Self::Get)
        } else if s.eq_ignore_ascii_case("POST") {
            Some(Self::Post)
        } else if s.eq_ignore_ascii_case("PUT") {
            Some(Self::Put)
        } else if s.eq_ignore_ascii_case("PATCH") {
            Some(Self::Patch)
        } else if s.eq_ignore_ascii_case("DELETE") {
            Some(Self::Delete)
        } else if s.eq_ignore_ascii_case("HEAD") {
            Some(Self::Head)
        } else if s.eq_ignore_ascii_case("OPTIONS") {
            Some(Self::Options)
        } else {
            None
        }
    }
}

pub struct HttpResponse {
    pub status: u16,
    pub reason: String,
    pub headers: Vec<(String, String)>,
    pub body: String,
}

/// Retry configuration for HTTP requests.
#[derive(Debug, Clone)]
pub struct RetryConfig {
    pub max_retries: u32,
    pub backoff_ms: u64,
    pub backoff_factor: f64,
    pub retryable_statuses: Vec<u16>,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_retries: DEFAULT_MAX_RETRIES,
            backoff_ms: DEFAULT_RETRY_BACKOFF_MS,
            backoff_factor: DEFAULT_RETRY_BACKOFF_FACTOR,
            retryable_statuses: DEFAULT_RETRYABLE_STATUSES.to_vec(),
        }
    }
}

impl RetryConfig {
    fn should_retry(&self, attempt: u32, status: u16) -> bool {
        if attempt >= self.max_retries {
            return false;
        }
        // Status 0 = network error, always retryable
        status == 0 || self.retryable_statuses.contains(&status)
    }

    fn delay_for_attempt(&self, attempt: u32) -> Duration {
        let delay_ms = self.backoff_ms as f64 * self.backoff_factor.powi(attempt as i32);
        // Cap at 60 seconds to prevent excessive blocking
        let capped_ms = delay_ms.min(60_000.0) as u64;
        Duration::from_millis(capped_ms)
    }
}

/// Validate URL scheme and check for SSRF (CWE-918).
/// Only allows http:// and https://, and blocks private/reserved IPs when
/// SSRF protection is enabled.
fn validate_url(url: &str) -> Result<(), String> {
    let lower = url.to_ascii_lowercase();
    if !lower.starts_with("http://") && !lower.starts_with("https://") {
        return Err(format!(
            "Invalid URL scheme: only http:// and https:// are allowed, got: {}",
            url.split("://").next().unwrap_or("(none)")
        ));
    }
    // SSRF protection: block requests to private/reserved IP addresses
    crate::security::validate_no_ssrf(url)?;
    Ok(())
}

/// Follow an HTTP redirect response, performing SSRF validation on each hop.
///
/// Returns `Some(HttpResponse)` if the redirect chain completes successfully,
/// or `None` if the original response is not a redirect.
/// Emits a security warning if a redirect from HTTPS downgrades to HTTP.
fn follow_redirect(
    original_method: Method,
    original_url: &str,
    original_headers: &[(String, String)],
    original_body: Option<&str>,
    first_response: HttpResponse,
) -> HttpResponse {
    // 3xx redirect codes that we follow
    let is_redirect = matches!(first_response.status, 301 | 302 | 303 | 307 | 308);
    if !is_redirect {
        return first_response;
    }

    let mut current_response = first_response;
    let mut current_url = original_url.to_string();
    let mut hops = 0usize;

    loop {
        if !matches!(current_response.status, 301 | 302 | 303 | 307 | 308) {
            return current_response;
        }

        if hops >= MAX_REDIRECTS {
            return HttpResponse {
                status: 0,
                reason: format!(
                    "Redirect limit ({MAX_REDIRECTS}) exceeded. \
                     Use duck_net_set_ssrf_protection(false) to allow longer chains."
                ),
                headers: vec![],
                body: String::new(),
            };
        }

        // Find Location header
        let location = current_response
            .headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("location"))
            .map(|(_, v)| v.clone());

        let redirect_url = match location {
            Some(loc) => {
                // Resolve relative URLs against the current URL
                if loc.starts_with("http://") || loc.starts_with("https://") {
                    loc
                } else if loc.starts_with("//") {
                    // Protocol-relative
                    let scheme = if current_url.starts_with("https://") {
                        "https:"
                    } else {
                        "http:"
                    };
                    format!("{}{}", scheme, loc)
                } else if loc.starts_with('/') {
                    // Absolute path, keep scheme+host
                    let host_end = current_url[8..]
                        .find('/')
                        .map(|p| p + 8)
                        .unwrap_or(current_url.len());
                    format!("{}{}", &current_url[..host_end], loc)
                } else {
                    loc
                }
            }
            None => {
                return HttpResponse {
                    status: 0,
                    reason: "Redirect response missing Location header".to_string(),
                    headers: vec![],
                    body: String::new(),
                };
            }
        };

        // Validate the redirect target URL (SSRF check on each hop)
        if let Err(e) = validate_url(&redirect_url) {
            return HttpResponse {
                status: 0,
                reason: format!("Redirect blocked by SSRF protection: {e}"),
                headers: vec![],
                body: String::new(),
            };
        }

        // Warn on HTTPS → HTTP downgrade
        if current_url.starts_with("https://") && redirect_url.starts_with("http://") {
            crate::security_warnings::warn_http_redirect_downgrade();
        }

        // Determine method for the redirect: 303 always becomes GET; 307/308 preserve
        let redirect_method = match current_response.status {
            303 => Method::Get,
            301 | 302 => {
                if original_method == Method::Post {
                    Method::Get
                } else {
                    original_method
                }
            }
            _ => original_method, // 307, 308 preserve method
        };

        // 303 and method-changes strip the body
        let redirect_body = if redirect_method == Method::Get || redirect_method == Method::Head {
            None
        } else {
            original_body
        };

        hops += 1;
        current_url = redirect_url.clone();

        let resp = execute_inner(
            redirect_method,
            &redirect_url,
            original_headers,
            redirect_body,
        );
        current_response = match resp {
            Ok(r) => r,
            Err(e) => HttpResponse {
                status: 0,
                reason: format!("Request failed on redirect hop {hops}: {e}"),
                headers: vec![],
                body: String::new(),
            },
        };
    }
}

/// Read a response body with a size limit to prevent OOM (CWE-400).
fn read_body_limited(body: &mut ureq::Body) -> Result<String, String> {
    let mut buf = Vec::new();
    body.as_reader()
        .take(MAX_RESPONSE_BODY_BYTES)
        .read_to_end(&mut buf)
        .map_err(|e| format!("Failed to read response body: {e}"))?;
    String::from_utf8(buf).map_err(|e| format!("Response body is not valid UTF-8: {e}"))
}

/// Execute an arbitrary HTTP method (for WebDAV PROPFIND/MKCOL/REPORT etc).
pub fn execute_raw_method(
    method_str: &str,
    url: &str,
    headers: &[(String, String)],
    body: Option<&str>,
) -> HttpResponse {
    crate::rate_limit::acquire_for_url(url);

    if let Err(msg) = validate_url(url) {
        return HttpResponse {
            status: 0,
            reason: msg,
            headers: vec![],
            body: String::new(),
        };
    }
    if let Err(msg) = crate::security::validate_headers(headers) {
        return HttpResponse {
            status: 0,
            reason: format!("Invalid header: {msg}"),
            headers: vec![],
            body: String::new(),
        };
    }

    // Build an http::Request with the custom method and pass it to Agent::run()
    let mut builder = ureq::http::Request::builder().method(method_str).uri(url);

    for (key, value) in headers {
        builder = builder.header(key.as_str(), value.as_str());
    }

    let request = match builder.body(body.unwrap_or("").to_string()) {
        Ok(r) => r,
        Err(e) => {
            return HttpResponse {
                status: 0,
                reason: format!("Invalid request: {e}"),
                headers: vec![],
                body: String::new(),
            };
        }
    };

    match AGENT.run(request) {
        Ok(mut response) => {
            let status = response.status().as_u16();
            let reason = response
                .status()
                .canonical_reason()
                .unwrap_or("")
                .to_string();
            let resp_headers: Vec<(String, String)> = response
                .headers()
                .iter()
                .map(|(name, value)| {
                    let (name, value): (&ureq::http::HeaderName, &ureq::http::HeaderValue) =
                        (name, value);
                    (
                        name.as_str().to_string(),
                        value.to_str().unwrap_or("").to_string(),
                    )
                })
                .collect();
            let resp_body = read_body_limited(response.body_mut())
                .unwrap_or_else(|e| format!("[body read error: {e}]"));
            HttpResponse {
                status,
                reason,
                headers: resp_headers,
                body: resp_body,
            }
        }
        Err(e) => HttpResponse {
            status: 0,
            reason: format!("Request failed: {e}"),
            headers: vec![],
            body: String::new(),
        },
    }
}

pub fn execute(
    method: Method,
    url: &str,
    headers: &[(String, String)],
    body: Option<&str>,
) -> HttpResponse {
    // Apply rate limiting before making the request
    crate::rate_limit::acquire_for_url(url);
    let config = RetryConfig {
        max_retries: get_max_retries(),
        backoff_ms: get_retry_backoff_ms(),
        backoff_factor: DEFAULT_RETRY_BACKOFF_FACTOR,
        retryable_statuses: get_retry_statuses(),
    };
    execute_with_retry(method, url, headers, body, &config)
}

pub fn execute_with_retry(
    method: Method,
    url: &str,
    headers: &[(String, String)],
    body: Option<&str>,
    retry: &RetryConfig,
) -> HttpResponse {
    if let Err(msg) = validate_url(url) {
        return HttpResponse {
            status: 0,
            reason: msg,
            headers: vec![],
            body: String::new(),
        };
    }
    // Validate headers for CRLF injection before making any request (CWE-113)
    if let Err(msg) = crate::security::validate_headers(headers) {
        return HttpResponse {
            status: 0,
            reason: format!("Invalid header: {msg}"),
            headers: vec![],
            body: String::new(),
        };
    }

    let mut attempt = 0u32;
    loop {
        let resp = execute_inner(method, url, headers, body);
        let raw = match resp {
            Ok(r) => r,
            Err(e) => HttpResponse {
                status: 0,
                reason: format!("Request failed: {e}"),
                headers: vec![],
                body: String::new(),
            },
        };

        // Follow redirects with per-hop SSRF validation
        let result = follow_redirect(method, url, headers, body, raw);

        if retry.should_retry(attempt, result.status) {
            let delay = retry.delay_for_attempt(attempt);
            std::thread::sleep(delay);
            attempt += 1;
            continue;
        }

        return result;
    }
}

fn execute_inner(
    method: Method,
    url: &str,
    headers: &[(String, String)],
    body: Option<&str>,
) -> Result<HttpResponse, ureq::Error> {
    let mut response = match method {
        Method::Post | Method::Put | Method::Patch => {
            let mut b = match method {
                Method::Post => AGENT.post(url),
                Method::Put => AGENT.put(url),
                _ => AGENT.patch(url),
            };
            for (key, value) in headers {
                b = b.header(key.as_str(), value.as_str());
            }
            b.send(body.unwrap_or(""))?
        }
        _ => {
            let mut b = match method {
                Method::Get => AGENT.get(url),
                Method::Delete => AGENT.delete(url),
                Method::Head => AGENT.head(url),
                _ => AGENT.options(url),
            };
            for (key, value) in headers {
                b = b.header(key.as_str(), value.as_str());
            }
            b.call()?
        }
    };

    let status = response.status().as_u16();
    let reason = response
        .status()
        .canonical_reason()
        .unwrap_or("")
        .to_string();

    let resp_headers: Vec<(String, String)> = response
        .headers()
        .iter()
        .map(|(name, value)| {
            let (name, value): (&ureq::http::HeaderName, &ureq::http::HeaderValue) = (name, value);
            (
                name.as_str().to_string(),
                value.to_str().unwrap_or("").to_string(),
            )
        })
        .collect();

    let resp_body = match method {
        Method::Head => String::new(),
        _ => read_body_limited(response.body_mut())
            .unwrap_or_else(|e| format!("[body read error: {e}]")),
    };

    Ok(HttpResponse {
        status,
        reason,
        headers: resp_headers,
        body: resp_body,
    })
}

// ===== Multipart/Form-Data =====

pub fn execute_multipart(
    url: &str,
    headers: &[(String, String)],
    form_fields: &[(String, String)],
    file_fields: &[(String, String)],
) -> HttpResponse {
    if let Err(msg) = validate_url(url) {
        return HttpResponse {
            status: 0,
            reason: msg,
            headers: vec![],
            body: String::new(),
        };
    }
    if let Err(msg) = crate::security::validate_headers(headers) {
        return HttpResponse {
            status: 0,
            reason: format!("Invalid header: {msg}"),
            headers: vec![],
            body: String::new(),
        };
    }

    match execute_multipart_inner(url, headers, form_fields, file_fields) {
        Ok(resp) => resp,
        Err(msg) => HttpResponse {
            status: 0,
            reason: msg,
            headers: vec![],
            body: String::new(),
        },
    }
}

fn execute_multipart_inner(
    url: &str,
    headers: &[(String, String)],
    form_fields: &[(String, String)],
    file_fields: &[(String, String)],
) -> Result<HttpResponse, String> {
    use ureq::unversioned::multipart::Form;

    let mut form = Form::new();

    for (name, value) in form_fields {
        form = form.text(name.as_str(), value.as_str());
    }

    for (name, path) in file_fields {
        form = form
            .file(name.as_str(), path.as_str())
            .map_err(|e| format!("Failed to read file '{path}': {e}"))?;
    }

    let mut builder = AGENT.post(url);
    for (key, value) in headers {
        builder = builder.header(key.as_str(), value.as_str());
    }

    let mut response = builder
        .send(form)
        .map_err(|e| format!("Request failed: {e}"))?;

    let status = response.status().as_u16();
    let reason = response
        .status()
        .canonical_reason()
        .unwrap_or("")
        .to_string();

    let resp_headers: Vec<(String, String)> = response
        .headers()
        .iter()
        .map(|(name, value)| {
            let (name, value): (&ureq::http::HeaderName, &ureq::http::HeaderValue) = (name, value);
            (
                name.as_str().to_string(),
                value.to_str().unwrap_or("").to_string(),
            )
        })
        .collect();

    let resp_body = read_body_limited(response.body_mut())
        .unwrap_or_else(|e| format!("[body read error: {e}]"));

    Ok(HttpResponse {
        status,
        reason,
        headers: resp_headers,
        body: resp_body,
    })
}
