use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use std::sync::LazyLock;

static LIMITERS: LazyLock<Mutex<HashMap<String, TokenBucket>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// Global rate limit (requests per second). 0 = unlimited.
static GLOBAL_RPS: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);

pub fn set_global_rps(rps: u32) {
    GLOBAL_RPS.store(rps, std::sync::atomic::Ordering::Relaxed);
}

pub fn get_global_rps() -> u32 {
    GLOBAL_RPS.load(std::sync::atomic::Ordering::Relaxed)
}

struct TokenBucket {
    tokens: f64,
    max_tokens: f64,
    refill_rate: f64, // tokens per second
    last_refill: Instant,
}

impl TokenBucket {
    fn new(rps: f64) -> Self {
        Self {
            tokens: rps, // start full
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
    let after_scheme = url.strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))?;
    Some(after_scheme.split('/').next().unwrap_or(after_scheme))
}

/// Acquire a rate limit token for the given URL. Blocks if necessary.
/// Returns immediately if no rate limit is configured.
pub fn acquire_for_url(url: &str) {
    let rps = get_global_rps();
    if rps == 0 {
        return;
    }

    let domain = match domain_from_url(url) {
        Some(d) => d.to_string(),
        None => return,
    };

    let wait = {
        let mut limiters = LIMITERS.lock().unwrap();
        let bucket = limiters
            .entry(domain)
            .or_insert_with(|| TokenBucket::new(rps as f64));
        // Update max if global config changed
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
