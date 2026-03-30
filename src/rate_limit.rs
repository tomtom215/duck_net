// SPDX-License-Identifier: MIT
// Copyright 2026 Tom F. <tomf@tomtomtech.net> (https://github.com/tomtom215)

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use std::sync::LazyLock;

static LIMITERS: LazyLock<Mutex<HashMap<String, TokenBucket>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// Global rate limit (requests per second). 0 = unlimited.
static GLOBAL_RPS: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);

/// Per-domain rate limits: domain -> RPS.
static DOMAIN_LIMITS: LazyLock<Mutex<HashMap<String, u32>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

pub fn set_global_rps(rps: u32) {
    GLOBAL_RPS.store(rps, std::sync::atomic::Ordering::Relaxed);
}

pub fn get_global_rps() -> u32 {
    GLOBAL_RPS.load(std::sync::atomic::Ordering::Relaxed)
}

/// Set per-domain rate limits from a JSON-like config string.
/// Format: `{"domain1": rps1, "domain2": rps2}` or `domain1=rps1,domain2=rps2`.
pub fn set_domain_limits(config: &str) -> Result<String, String> {
    let mut limits = DOMAIN_LIMITS.lock().unwrap_or_else(|p| p.into_inner());
    limits.clear();

    let config = config.trim();
    if config.is_empty() {
        return Ok("Per-domain rate limits cleared".to_string());
    }

    // Parse JSON-like format: {"domain": rps, ...}
    if config.starts_with('{') {
        let inner = config.trim_start_matches('{').trim_end_matches('}');
        for pair in inner.split(',') {
            let pair = pair.trim();
            if pair.is_empty() {
                continue;
            }
            let parts: Vec<&str> = pair.splitn(2, ':').collect();
            if parts.len() != 2 {
                return Err(format!("Invalid domain limit entry: {pair}"));
            }
            let domain = parts[0].trim().trim_matches('"').trim_matches('\'');
            let rps: u32 = parts[1]
                .trim()
                .parse()
                .map_err(|_| format!("Invalid RPS value for {domain}: {}", parts[1].trim()))?;
            limits.insert(domain.to_string(), rps);
        }
    } else {
        // Simple format: domain1=rps1,domain2=rps2
        for pair in config.split(',') {
            let pair = pair.trim();
            if pair.is_empty() {
                continue;
            }
            let parts: Vec<&str> = pair.splitn(2, '=').collect();
            if parts.len() != 2 {
                return Err(format!("Invalid domain limit entry: {pair}"));
            }
            let domain = parts[0].trim();
            let rps: u32 = parts[1]
                .trim()
                .parse()
                .map_err(|_| format!("Invalid RPS value for {domain}: {}", parts[1].trim()))?;
            limits.insert(domain.to_string(), rps);
        }
    }

    let count = limits.len();
    Ok(format!("Set rate limits for {count} domain(s)"))
}

struct TokenBucket {
    tokens: f64,
    max_tokens: f64,
    refill_rate: f64,
    last_refill: Instant,
}

impl TokenBucket {
    fn new(rps: f64) -> Self {
        Self {
            tokens: rps,
            max_tokens: rps,
            refill_rate: rps,
            last_refill: Instant::now(),
        }
    }

    fn refill(&mut self) {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        self.tokens = (self.tokens + elapsed * self.refill_rate).min(self.max_tokens);
        self.last_refill = now;
    }

    fn acquire(&mut self) -> Duration {
        self.refill();
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            Duration::ZERO
        } else {
            let wait_secs = (1.0 - self.tokens) / self.refill_rate;
            self.tokens = 0.0;
            Duration::from_secs_f64(wait_secs)
        }
    }
}

/// Extract the domain from a URL for rate limiting purposes.
fn domain_from_url(url: &str) -> Option<&str> {
    let after_scheme = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))?;
    Some(after_scheme.split('/').next().unwrap_or(after_scheme))
}

/// Determine the effective RPS for a domain.
/// Priority: per-domain config > global config > unlimited.
fn effective_rps(domain: &str) -> u32 {
    // Check per-domain limits first
    if let Ok(limits) = DOMAIN_LIMITS.lock() {
        if let Some(&rps) = limits.get(domain) {
            return rps;
        }
        // Check wildcard patterns (e.g., "*.example.com")
        for (pattern, &rps) in limits.iter() {
            if pattern.starts_with("*.") {
                let suffix = &pattern[1..]; // ".example.com"
                if domain.ends_with(suffix) {
                    return rps;
                }
            }
        }
    }
    // Fall back to global
    get_global_rps()
}

/// Maximum number of tracked domains to prevent unbounded memory growth.
const MAX_TRACKED_DOMAINS: usize = 10_000;

/// Evict stale buckets that have not been used for over 5 minutes.
fn evict_stale_buckets(limiters: &mut HashMap<String, TokenBucket>) {
    if limiters.len() <= MAX_TRACKED_DOMAINS / 2 {
        return;
    }
    let cutoff = std::time::Instant::now() - std::time::Duration::from_secs(300);
    limiters.retain(|_, bucket| bucket.last_refill > cutoff);
}

/// Acquire a rate limit token for a raw hostname (non-HTTP protocols).
///
/// Use this for protocols that don't have a full URL: SMTP, FTP, SFTP, LDAP,
/// Redis, MQTT, AMQP, Kafka, NATS, gRPC, ZeroMQ, Memcached, etc.
/// The hostname is used directly as the rate-limit key (same as `acquire_for_url`
/// would extract from an HTTP URL).
pub fn acquire_for_host(host: &str) {
    if host.is_empty() {
        return;
    }
    // Strip port if present: "redis.example.com:6379" → "redis.example.com"
    let host = if let Some(colon) = host.rfind(':') {
        let after = &host[colon + 1..];
        if after.chars().all(|c| c.is_ascii_digit()) {
            &host[..colon]
        } else {
            host
        }
    } else {
        host
    };

    let rps = effective_rps(host);
    if rps == 0 {
        return;
    }

    let wait = {
        let mut limiters = LIMITERS.lock().unwrap_or_else(|p| p.into_inner());
        if limiters.len() >= MAX_TRACKED_DOMAINS {
            evict_stale_buckets(&mut limiters);
        }
        let bucket = limiters
            .entry(host.to_string())
            .or_insert_with(|| TokenBucket::new(rps as f64));
        if (bucket.max_tokens - rps as f64).abs() > 0.01 {
            bucket.max_tokens = rps as f64;
            bucket.refill_rate = rps as f64;
        }
        bucket.acquire()
    };

    if !wait.is_zero() {
        std::thread::sleep(wait);
    }
}

/// Acquire a rate limit token for the given URL. Blocks if necessary.
pub fn acquire_for_url(url: &str) {
    let domain = match domain_from_url(url) {
        Some(d) => d.to_string(),
        None => return,
    };

    let rps = effective_rps(&domain);
    if rps == 0 {
        return;
    }

    let wait = {
        let mut limiters = LIMITERS.lock().unwrap_or_else(|p| p.into_inner());
        // Evict stale entries to prevent unbounded memory growth (CWE-400)
        if limiters.len() >= MAX_TRACKED_DOMAINS {
            evict_stale_buckets(&mut limiters);
        }
        let bucket = limiters
            .entry(domain)
            .or_insert_with(|| TokenBucket::new(rps as f64));
        // Update if config changed
        if (bucket.max_tokens - rps as f64).abs() > 0.01 {
            bucket.max_tokens = rps as f64;
            bucket.refill_rate = rps as f64;
        }
        bucket.acquire()
    };

    if !wait.is_zero() {
        std::thread::sleep(wait);
    }
}
