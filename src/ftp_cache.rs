use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use std::sync::LazyLock;

use suppaftp::FtpStream;

/// Cache key: (host, port, username)
type CacheKey = (String, u16, String);

/// TTL for cached FTP connections (60 seconds of inactivity).
const CACHE_TTL: Duration = Duration::from_secs(60);

struct CachedFtp {
    stream: FtpStream,
    last_used: Instant,
}

static FTP_CACHE: LazyLock<Mutex<HashMap<CacheKey, CachedFtp>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// Evict expired entries from the cache.
fn evict_expired(cache: &mut HashMap<CacheKey, CachedFtp>) {
    let now = Instant::now();
    cache.retain(|_, entry| now.duration_since(entry.last_used) < CACHE_TTL);
}

/// Get a cached FTP connection or create a new one.
/// The returned stream is removed from the cache (exclusive access).
/// Call `return_to_cache` when done.
pub fn get_or_connect(
    host: &str,
    port: u16,
    username: &str,
    password: &str,
) -> Result<FtpStream, String> {
    let key = (host.to_string(), port, username.to_string());

    // Try to get from cache
    {
        let mut cache = FTP_CACHE.lock().unwrap();
        evict_expired(&mut cache);

        if let Some(entry) = cache.remove(&key) {
            // Verify connection is still alive with a NOOP
            let mut stream = entry.stream;
            if stream.noop().is_ok() {
                return Ok(stream);
            }
            // Connection dead, fall through to create new one
        }
    }

    // Create new connection
    let addr = format!("{host}:{port}");
    let mut ftp =
        FtpStream::connect(&addr).map_err(|e| format!("FTP connection failed to {addr}: {e}"))?;
    ftp.login(username, password)
        .map_err(|e| format!("FTP login failed: {e}"))?;

    Ok(ftp)
}

/// Return a connection to the cache for reuse.
pub fn return_to_cache(host: &str, port: u16, username: &str, stream: FtpStream) {
    let key = (host.to_string(), port, username.to_string());
    let mut cache = FTP_CACHE.lock().unwrap();
    evict_expired(&mut cache);
    // Limit cache size to prevent unbounded growth
    if cache.len() < 32 {
        cache.insert(
            key,
            CachedFtp {
                stream,
                last_used: Instant::now(),
            },
        );
    }
}
