// SPDX-License-Identifier: MIT
// Copyright 2026 Tom F. <tomf@tomtomtech.net> (https://github.com/tomtom215)

//! RESP (REdis Serialization Protocol) parser for duck_net.
//!
//! Handles parsing of RESP2 responses with safety bounds:
//! - Maximum response size limit (CWE-400)
//! - Maximum recursion depth limit (CWE-674)
//! - Maximum array element count

use std::io::{BufRead, BufReader, Read};
use std::net::TcpStream;

/// Maximum response size: 16 MiB.
/// Prevents OOM from unbounded response buffering (CWE-400).
pub const MAX_RESPONSE_BYTES: usize = 16 * 1024 * 1024;

/// Maximum recursion depth for RESP array parsing.
/// Prevents stack overflow from malicious deeply-nested responses (CWE-674).
pub const MAX_RESP_DEPTH: usize = 8;

/// Maximum number of array elements in a single RESP array.
/// Prevents memory exhaustion from extremely large arrays (CWE-400).
pub const MAX_ARRAY_ELEMENTS: i64 = 100_000;

/// Read a single RESP response from the reader.
pub fn read_response(reader: &mut BufReader<TcpStream>) -> Result<String, String> {
    read_response_depth(reader, 0)
}

/// Read a single RESP response with depth tracking to prevent stack overflow.
fn read_response_depth(reader: &mut BufReader<TcpStream>, depth: usize) -> Result<String, String> {
    if depth > MAX_RESP_DEPTH {
        return Err(format!("RESP nesting too deep (max {MAX_RESP_DEPTH})"));
    }

    let mut line = String::new();
    reader
        .read_line(&mut line)
        .map_err(|e| format!("Redis read failed: {e}"))?;

    if line.is_empty() {
        return Err("Redis: empty response".to_string());
    }

    let line = line.trim_end_matches(&['\r', '\n'] as &[char]);

    match line.as_bytes().first() {
        Some(b'+') => Ok(line.to_string()), // Simple string
        Some(b'-') => Ok(line.to_string()), // Error
        Some(b':') => Ok(line.to_string()), // Integer
        Some(b'$') => {
            // Bulk string
            let len: i64 = line[1..]
                .parse()
                .map_err(|_| format!("Invalid bulk string length: {}", &line[1..]))?;
            if len < 0 {
                return Ok("$-1".to_string()); // Null bulk string
            }
            // Validate length before cast to prevent issues on 32-bit systems
            if len > MAX_RESPONSE_BYTES as i64 {
                return Err(format!(
                    "Response too large: {len} bytes (max {MAX_RESPONSE_BYTES})"
                ));
            }
            let len = len as usize;
            let mut buf = vec![0u8; len + 2]; // +2 for \r\n
            reader
                .read_exact(&mut buf)
                .map_err(|e| format!("Redis read bulk failed: {e}"))?;
            let data = &buf[..len];
            Ok(String::from_utf8_lossy(data).to_string())
        }
        Some(b'*') => {
            // Array - read count and then each element
            let count: i64 = line[1..]
                .parse()
                .map_err(|_| format!("Invalid array length: {}", &line[1..]))?;
            if count < 0 {
                return Ok("*-1".to_string()); // Null array
            }
            if count > MAX_ARRAY_ELEMENTS {
                return Err(format!(
                    "Array too large: {count} elements (max {MAX_ARRAY_ELEMENTS})"
                ));
            }
            let mut elements = Vec::new();
            for _ in 0..count {
                let elem = read_response_depth(reader, depth + 1)?;
                elements.push(elem);
            }
            // Return as newline-separated values
            Ok(elements.join("\n"))
        }
        _ => Err(format!("Unknown RESP response type: {line}")),
    }
}
