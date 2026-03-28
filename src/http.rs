use std::io::Read as _;
use std::sync::LazyLock;
use std::time::Duration;

use ureq::Agent;
use ureq::tls::{RootCerts, TlsConfig};

/// Maximum response body size: 256 MiB.
/// Prevents OOM from unbounded response buffering (CWE-400).
const MAX_RESPONSE_BODY_BYTES: u64 = 256 * 1024 * 1024;

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

static AGENT: LazyLock<Agent> = LazyLock::new(|| {
    // Use the platform's native certificate verifier so we trust the OS CA store.
    // This is critical for environments with corporate proxies or custom CAs.
    let tls = TlsConfig::builder()
        .root_certs(RootCerts::PlatformVerifier)
        .build();

    Agent::config_builder()
        .tls_config(tls)
        .http_status_as_error(false)
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
        let delay_ms =
            self.backoff_ms as f64 * self.backoff_factor.powi(attempt as i32);
        // Cap at 60 seconds to prevent excessive blocking
        let capped_ms = delay_ms.min(60_000.0) as u64;
        Duration::from_millis(capped_ms)
    }
}

/// Validate URL scheme. Only allow http:// and https:// (CWE-918 SSRF mitigation).
fn validate_url(url: &str) -> Result<(), String> {
    let lower = url.to_ascii_lowercase();
    if lower.starts_with("http://") || lower.starts_with("https://") {
        Ok(())
    } else {
        Err(format!(
            "Invalid URL scheme: only http:// and https:// are allowed, got: {}",
            url.split("://").next().unwrap_or("(none)")
        ))
    }
}

/// Read a response body with a size limit to prevent OOM (CWE-400).
fn read_body_limited(body: &mut ureq::Body) -> Result<String, String> {
    let mut buf = Vec::new();
    body.as_reader()
        .take(MAX_RESPONSE_BODY_BYTES)
        .read_to_end(&mut buf)
        .map_err(|e| format!("Failed to read response body: {e}"))?;
    String::from_utf8(buf)
        .map_err(|e| format!("Response body is not valid UTF-8: {e}"))
}

pub fn execute(
    method: Method,
    url: &str,
    headers: &[(String, String)],
    body: Option<&str>,
) -> HttpResponse {
    // Apply rate limiting before making the request
    crate::rate_limit::acquire_for_url(url);
    execute_with_retry(method, url, headers, body, &RetryConfig::default())
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

    let mut attempt = 0u32;
    loop {
        let resp = execute_inner(method, url, headers, body);
        let result = match resp {
            Ok(r) => r,
            Err(e) => HttpResponse {
                status: 0,
                reason: format!("Request failed: {e}"),
                headers: vec![],
                body: String::new(),
            },
        };

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

    let mut response = builder.send(form).map_err(|e| format!("Request failed: {e}"))?;

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
