// SPDX-License-Identifier: MIT
// Copyright 2026 Tom F. <tomf@tomtomtech.net> (https://github.com/tomtom215)

/// Extract a string value from JSON by key name.
/// Handles: `"key": "value"` and `"key":"value"` (with/without spaces).
/// Returns the unescaped string value, or None if not found.
/// Does NOT handle nested objects or arrays - only top-level string fields.
pub fn extract_string<'a>(json: &'a str, key: &str) -> Option<&'a str> {
    let needle = format!("\"{key}\"");
    let mut search_from = 0;

    while let Some(key_start) = json[search_from..].find(&needle) {
        let after_key = search_from + key_start + needle.len();
        let rest = json[after_key..].trim_start();

        if !rest.starts_with(':') {
            search_from = after_key;
            continue;
        }

        let after_colon = rest[1..].trim_start();
        if !after_colon.starts_with('"') {
            search_from = after_key;
            continue;
        }

        let value_start_abs = json.len() - after_colon.len() + 1;
        // Find the closing unescaped quote
        let value_content = &json[value_start_abs..];
        let mut end = 0;
        let bytes = value_content.as_bytes();
        while end < bytes.len() {
            if bytes[end] == b'\\' {
                // Skip escaped character; guard against trailing backslash
                // at end-of-input (CWE-125).
                if end + 1 < bytes.len() {
                    end += 2;
                } else {
                    break;
                }
            } else if bytes[end] == b'"' {
                return Some(&json[value_start_abs..value_start_abs + end]);
            } else {
                end += 1;
            }
        }
        return None;
    }
    None
}

/// Extract a string value using a simple dot-path like "$.field" or "$.field.subfield".
/// Navigates through nested JSON objects by finding each key in sequence.
pub fn dot_path<'a>(json: &'a str, path: &str) -> Option<&'a str> {
    let path = path.strip_prefix("$.").unwrap_or(path);
    let parts: Vec<&str> = path.split('.').collect();

    if parts.is_empty() {
        return None;
    }

    // For single-level path, just extract directly
    if parts.len() == 1 {
        return extract_string(json, parts[0]);
    }

    // For multi-level, find each nested object
    let mut current = json;
    for (i, part) in parts.iter().enumerate() {
        if i == parts.len() - 1 {
            return extract_string(current, part);
        }
        // Find "key": { and narrow the search scope
        let needle = format!("\"{part}\"");
        let key_pos = current.find(&needle)?;
        let after_key = &current[key_pos + needle.len()..].trim_start();
        if !after_key.starts_with(':') {
            return None;
        }
        let after_colon = after_key[1..].trim_start();
        if after_colon.starts_with('{') {
            current = after_colon;
        } else if after_colon.starts_with('"') {
            // It's a string value at intermediate level
            return None;
        } else {
            current = after_colon;
        }
    }
    None
}

/// Extract an unquoted numeric value from JSON by key name.
/// Handles: `"key": 1234` (integer literals, with/without spaces).
/// Returns the raw numeric string, or None if not found or value is not numeric.
pub fn extract_number<'a>(json: &'a str, key: &str) -> Option<&'a str> {
    let needle = format!("\"{key}\"");
    let mut search_from = 0;

    while let Some(key_start) = json[search_from..].find(&needle) {
        let after_key = search_from + key_start + needle.len();
        let rest = json[after_key..].trim_start();

        if !rest.starts_with(':') {
            search_from = after_key;
            continue;
        }

        let after_colon = rest[1..].trim_start();
        // Must start with a digit or minus sign (not a quote — that's a string)
        let first = after_colon.chars().next()?;
        if !first.is_ascii_digit() && first != '-' {
            search_from = after_key;
            continue;
        }

        let value_start_abs = json.len() - after_colon.len();
        let end = after_colon
            .find(|c: char| !c.is_ascii_digit() && c != '-' && c != '.')
            .unwrap_or(after_colon.len());

        return Some(&json[value_start_abs..value_start_abs + end]);
    }
    None
}

/// Minimal percent-encoding for form URL encoding.
pub fn form_urlencode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            b' ' => out.push('+'),
            _ => {
                out.push('%');
                out.push(char::from(b"0123456789ABCDEF"[(b >> 4) as usize]));
                out.push(char::from(b"0123456789ABCDEF"[(b & 0x0F) as usize]));
            }
        }
    }
    out
}
