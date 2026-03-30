// SPDX-License-Identifier: MIT
// Copyright 2026 Tom F. <tomf@tomtomtech.net> (https://github.com/tomtom215)

use std::io::{BufReader, Write};
use std::net::TcpStream;
use std::time::Duration;

/// Connection timeout in seconds.
const CONNECT_TIMEOUT_SECS: u64 = 10;

/// Read/write timeout in seconds.
const IO_TIMEOUT_SECS: u64 = 10;

pub struct RedisResult {
    pub success: bool,
    pub value: String,
}

pub struct RedisKeysResult {
    pub success: bool,
    pub keys: Vec<String>,
    pub message: String,
}

/// Validate Redis host to prevent SSRF/injection.
fn is_valid_host(host: &str) -> bool {
    if host.is_empty() || host.len() > 253 {
        return false;
    }
    host.chars()
        .all(|c| c.is_alphanumeric() || matches!(c, '.' | '-' | ':' | '[' | ']'))
}

/// Parse a Redis URL: redis://[password@]host[:port][/db]
/// Returns (host, port, password, db).
fn parse_url(url: &str) -> Result<(String, u16, Option<String>, Option<u32>), String> {
    // Emit security warning for plaintext Redis (CWE-319)
    if !url.starts_with("rediss://") {
        crate::security_warnings::warn_plaintext(
            "Redis",
            "PLAINTEXT_REDIS",
            "rediss:// (Redis over TLS)",
        );
    }

    let rest = url
        .strip_prefix("redis://")
        .ok_or("URL must start with redis://")?;

    let (auth, hostpath) = if let Some(at) = rest.rfind('@') {
        (Some(&rest[..at]), &rest[at + 1..])
    } else {
        (None, rest)
    };

    let password = auth.map(|a| a.to_string());

    let (hostport, db) = if let Some(slash) = hostpath.find('/') {
        let db_str = &hostpath[slash + 1..];
        let db = if db_str.is_empty() {
            None
        } else {
            Some(
                db_str
                    .parse::<u32>()
                    .map_err(|_| format!("Invalid database number: {db_str}"))?,
            )
        };
        (&hostpath[..slash], db)
    } else {
        (hostpath, None)
    };

    let (host, port) = if let Some(colon) = hostport.rfind(':') {
        let port: u16 = hostport[colon + 1..]
            .parse()
            .map_err(|_| "Invalid port number")?;
        (hostport[..colon].to_string(), port)
    } else {
        (hostport.to_string(), 6379)
    };

    if !is_valid_host(&host) {
        return Err(format!("Invalid host: {host}"));
    }

    Ok((host, port, password, db))
}

/// Scrub credentials from a Redis URL for safe inclusion in error messages (CWE-532).
fn scrub_url(url: &str) -> String {
    crate::security::scrub_url(url)
}

/// Connect to Redis and optionally authenticate + select database.
fn connect(url: &str) -> Result<BufReader<TcpStream>, String> {
    let (host, port, password, db) = parse_url(url)?;

    // SSRF protection: block connections to private/reserved IPs (CWE-918)
    crate::security::validate_no_ssrf_host(&host)?;

    // Rate limiting: apply per-host token bucket (honours global + per-domain config)
    crate::rate_limit::acquire_for_host(&host);

    let addr = format!("{host}:{port}");
    let stream = TcpStream::connect_timeout(
        &addr
            .parse()
            .map_err(|e| format!("Invalid address {addr}: {e}"))?,
        Duration::from_secs(CONNECT_TIMEOUT_SECS),
    )
    .map_err(|e| format!("Redis connection failed: {}", scrub_url(&e.to_string())))?;

    // Post-connect SSRF check: validate actual peer IP to prevent DNS rebinding (CWE-918)
    crate::security::validate_tcp_peer(&stream)?;

    stream
        .set_read_timeout(Some(Duration::from_secs(IO_TIMEOUT_SECS)))
        .map_err(|e| format!("Failed to set read timeout: {e}"))?;
    stream
        .set_write_timeout(Some(Duration::from_secs(IO_TIMEOUT_SECS)))
        .map_err(|e| format!("Failed to set write timeout: {e}"))?;

    let mut reader = BufReader::new(stream);

    // AUTH if password provided
    if let Some(ref pass) = password {
        send_command(reader.get_mut(), &["AUTH", pass])?;
        let resp = read_response(&mut reader)?;
        if !resp.starts_with('+') {
            return Err(format!("Redis AUTH failed: {resp}"));
        }
    }

    // SELECT database if specified
    if let Some(db_num) = db {
        let db_str = db_num.to_string();
        send_command(reader.get_mut(), &["SELECT", &db_str])?;
        let resp = read_response(&mut reader)?;
        if !resp.starts_with('+') {
            return Err(format!("Redis SELECT failed: {resp}"));
        }
    }

    Ok(reader)
}

/// Encode and send a RESP command array.
fn send_command(stream: &mut TcpStream, args: &[&str]) -> Result<(), String> {
    let mut cmd = format!("*{}\r\n", args.len());
    for arg in args {
        cmd.push_str(&format!("${}\r\n{}\r\n", arg.len(), arg));
    }
    stream
        .write_all(cmd.as_bytes())
        .map_err(|e| format!("Redis write failed: {e}"))
}

/// Read a single RESP response (delegates to redis_resp module).
fn read_response(reader: &mut BufReader<TcpStream>) -> Result<String, String> {
    crate::redis_resp::read_response(reader)
}

/// GET a key from Redis.
pub fn get(url: &str, key: &str) -> RedisResult {
    if key.is_empty() {
        return RedisResult {
            success: false,
            value: "Key cannot be empty".to_string(),
        };
    }

    match connect(url) {
        Ok(mut reader) => {
            if let Err(e) = send_command(reader.get_mut(), &["GET", key]) {
                return RedisResult {
                    success: false,
                    value: e,
                };
            }
            match read_response(&mut reader) {
                Ok(v) if v == "$-1" => RedisResult {
                    success: true,
                    value: String::new(), // Key not found
                },
                Ok(v) => RedisResult {
                    success: true,
                    value: v,
                },
                Err(e) => RedisResult {
                    success: false,
                    value: e,
                },
            }
        }
        Err(e) => RedisResult {
            success: false,
            value: e,
        },
    }
}

/// SET a key in Redis.
pub fn set(url: &str, key: &str, value: &str) -> RedisResult {
    if key.is_empty() {
        return RedisResult {
            success: false,
            value: "Key cannot be empty".to_string(),
        };
    }

    match connect(url) {
        Ok(mut reader) => {
            if let Err(e) = send_command(reader.get_mut(), &["SET", key, value]) {
                return RedisResult {
                    success: false,
                    value: e,
                };
            }
            match read_response(&mut reader) {
                Ok(v) if v.starts_with('+') => RedisResult {
                    success: true,
                    value: v[1..].to_string(),
                },
                Ok(v) => RedisResult {
                    success: false,
                    value: v,
                },
                Err(e) => RedisResult {
                    success: false,
                    value: e,
                },
            }
        }
        Err(e) => RedisResult {
            success: false,
            value: e,
        },
    }
}

/// SET a key in Redis with TTL (seconds).
pub fn set_ex(url: &str, key: &str, value: &str, ttl_secs: i64) -> RedisResult {
    if key.is_empty() {
        return RedisResult {
            success: false,
            value: "Key cannot be empty".to_string(),
        };
    }
    if ttl_secs <= 0 {
        return RedisResult {
            success: false,
            value: "TTL must be positive".to_string(),
        };
    }

    match connect(url) {
        Ok(mut reader) => {
            let ttl_str = ttl_secs.to_string();
            if let Err(e) = send_command(reader.get_mut(), &["SET", key, value, "EX", &ttl_str]) {
                return RedisResult {
                    success: false,
                    value: e,
                };
            }
            match read_response(&mut reader) {
                Ok(v) if v.starts_with('+') => RedisResult {
                    success: true,
                    value: v[1..].to_string(),
                },
                Ok(v) => RedisResult {
                    success: false,
                    value: v,
                },
                Err(e) => RedisResult {
                    success: false,
                    value: e,
                },
            }
        }
        Err(e) => RedisResult {
            success: false,
            value: e,
        },
    }
}

/// KEYS pattern scan. Returns matching keys.
pub fn keys(url: &str, pattern: &str) -> RedisKeysResult {
    if pattern.is_empty() {
        return RedisKeysResult {
            success: false,
            keys: vec![],
            message: "Pattern cannot be empty".to_string(),
        };
    }

    match connect(url) {
        Ok(mut reader) => {
            if let Err(e) = send_command(reader.get_mut(), &["KEYS", pattern]) {
                return RedisKeysResult {
                    success: false,
                    keys: vec![],
                    message: e,
                };
            }
            match read_response(&mut reader) {
                Ok(v) if v == "*-1" || v.is_empty() => RedisKeysResult {
                    success: true,
                    keys: vec![],
                    message: "OK".to_string(),
                },
                Ok(v) => {
                    let keys: Vec<String> = v.lines().map(|s| s.to_string()).collect();
                    RedisKeysResult {
                        success: true,
                        keys,
                        message: "OK".to_string(),
                    }
                }
                Err(e) => RedisKeysResult {
                    success: false,
                    keys: vec![],
                    message: e,
                },
            }
        }
        Err(e) => RedisKeysResult {
            success: false,
            keys: vec![],
            message: e,
        },
    }
}

/// DEL a key from Redis. Returns the count of deleted keys.
pub fn del(url: &str, key: &str) -> RedisResult {
    if key.is_empty() {
        return RedisResult {
            success: false,
            value: "Key cannot be empty".to_string(),
        };
    }

    match connect(url) {
        Ok(mut reader) => {
            if let Err(e) = send_command(reader.get_mut(), &["DEL", key]) {
                return RedisResult {
                    success: false,
                    value: e,
                };
            }
            match read_response(&mut reader) {
                Ok(v) if v.starts_with(':') => RedisResult {
                    success: true,
                    value: v[1..].to_string(),
                },
                Ok(v) => RedisResult {
                    success: false,
                    value: format!("Unexpected response from DEL: {v}"),
                },
                Err(e) => RedisResult {
                    success: false,
                    value: e,
                },
            }
        }
        Err(e) => RedisResult {
            success: false,
            value: e,
        },
    }
}

/// Set a TTL (in seconds) on a key. Returns "1" if timeout was set, "0" if key does not exist.
pub fn expire(url: &str, key: &str, ttl_secs: i64) -> RedisResult {
    if key.is_empty() {
        return RedisResult {
            success: false,
            value: "Key cannot be empty".to_string(),
        };
    }
    if ttl_secs <= 0 {
        return RedisResult {
            success: false,
            value: "TTL must be positive".to_string(),
        };
    }

    match connect(url) {
        Ok(mut reader) => {
            let ttl_str = ttl_secs.to_string();
            if let Err(e) = send_command(reader.get_mut(), &["EXPIRE", key, &ttl_str]) {
                return RedisResult {
                    success: false,
                    value: e,
                };
            }
            match read_response(&mut reader) {
                Ok(v) if v.starts_with(':') => RedisResult {
                    success: true,
                    value: v[1..].to_string(),
                },
                Ok(v) => RedisResult {
                    success: false,
                    value: format!("Unexpected response from EXPIRE: {v}"),
                },
                Err(e) => RedisResult {
                    success: false,
                    value: e,
                },
            }
        }
        Err(e) => RedisResult {
            success: false,
            value: e,
        },
    }
}

/// HGET a field from a Redis hash.
pub fn hget(url: &str, key: &str, field: &str) -> RedisResult {
    if key.is_empty() {
        return RedisResult {
            success: false,
            value: "Key cannot be empty".to_string(),
        };
    }
    if field.is_empty() {
        return RedisResult {
            success: false,
            value: "Field cannot be empty".to_string(),
        };
    }

    match connect(url) {
        Ok(mut reader) => {
            if let Err(e) = send_command(reader.get_mut(), &["HGET", key, field]) {
                return RedisResult {
                    success: false,
                    value: e,
                };
            }
            match read_response(&mut reader) {
                Ok(v) if v == "$-1" => RedisResult {
                    success: true,
                    value: String::new(), // Field not found
                },
                Ok(v) => RedisResult {
                    success: true,
                    value: v,
                },
                Err(e) => RedisResult {
                    success: false,
                    value: e,
                },
            }
        }
        Err(e) => RedisResult {
            success: false,
            value: e,
        },
    }
}

/// HSET a field in a Redis hash. Returns "1" if field was created, "0" if updated.
pub fn hset(url: &str, key: &str, field: &str, value: &str) -> RedisResult {
    if key.is_empty() {
        return RedisResult {
            success: false,
            value: "Key cannot be empty".to_string(),
        };
    }
    if field.is_empty() {
        return RedisResult {
            success: false,
            value: "Field cannot be empty".to_string(),
        };
    }

    match connect(url) {
        Ok(mut reader) => {
            if let Err(e) = send_command(reader.get_mut(), &["HSET", key, field, value]) {
                return RedisResult {
                    success: false,
                    value: e,
                };
            }
            match read_response(&mut reader) {
                Ok(v) if v.starts_with(':') => RedisResult {
                    success: true,
                    value: v[1..].to_string(),
                },
                Ok(v) => RedisResult {
                    success: false,
                    value: format!("Unexpected response from HSET: {v}"),
                },
                Err(e) => RedisResult {
                    success: false,
                    value: e,
                },
            }
        }
        Err(e) => RedisResult {
            success: false,
            value: e,
        },
    }
}
