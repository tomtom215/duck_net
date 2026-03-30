// SPDX-License-Identifier: MIT
// Copyright 2026 Tom F. <tomf@tomtomtech.net> (https://github.com/tomtom215)

/// Maximum token response size.
const MAX_RESPONSE_BYTES: u64 = 64 * 1024;

pub struct OAuth2TokenResult {
    pub success: bool,
    pub access_token: String,
    pub token_type: String,
    pub expires_in: i64,
    pub scope: String,
    pub message: String,
}

/// Obtain an OAuth2 access token using the client_credentials grant flow.
///
/// Posts to `token_url` with Basic auth (client_id:client_secret) and
/// `grant_type=client_credentials`. The optional `scope` parameter restricts
/// the requested permissions.
pub fn client_credentials(
    token_url: &str,
    client_id: &str,
    client_secret: &str,
    scope: &str,
) -> OAuth2TokenResult {
    match client_credentials_inner(token_url, client_id, client_secret, scope) {
        Ok(r) => r,
        Err(e) => OAuth2TokenResult {
            success: false,
            access_token: String::new(),
            token_type: String::new(),
            expires_in: -1,
            scope: String::new(),
            message: e,
        },
    }
}

fn client_credentials_inner(
    token_url: &str,
    client_id: &str,
    client_secret: &str,
    scope: &str,
) -> Result<OAuth2TokenResult, String> {
    // Validate inputs
    if client_id.is_empty() {
        return Err("client_id must not be empty".to_string());
    }
    if client_secret.is_empty() {
        return Err("client_secret must not be empty".to_string());
    }

    // Only allow https:// for token endpoints to prevent credential exposure (CWE-319)
    let lower = token_url.to_ascii_lowercase();
    if !lower.starts_with("https://") {
        return Err(
            "Token URL must use https:// to protect credentials in transit (CWE-319)".to_string(),
        );
    }

    // SSRF protection
    crate::security::validate_no_ssrf(token_url)?;

    // Build form body
    let mut body = format!("grant_type=client_credentials&client_id={}&client_secret={}",
        url_encode(client_id),
        url_encode(client_secret),
    );
    if !scope.is_empty() {
        body.push_str(&format!("&scope={}", url_encode(scope)));
    }

    use std::io::Read as _;
    let agent = crate::http::get_agent();
    let response = agent
        .post(token_url)
        .header("content-type", "application/x-www-form-urlencoded")
        .header("accept", "application/json")
        .send(body)
        .map_err(|e| format!("OAuth2 request failed: {e}"))?;

    let status = response.status().as_u16();

    let mut resp_body = response.into_body();
    let mut buf = Vec::new();
    resp_body
        .as_reader()
        .take(MAX_RESPONSE_BYTES)
        .read_to_end(&mut buf)
        .map_err(|e| format!("Failed to read token response: {e}"))?;

    let body_str =
        String::from_utf8(buf).map_err(|_| "Token response is not valid UTF-8".to_string())?;

    if status != 200 {
        return Err(format!("OAuth2 token endpoint returned HTTP {status}: {body_str}"));
    }

    // Parse JSON response
    let access_token = extract_json_string(&body_str, "access_token")
        .ok_or_else(|| "access_token not found in token response".to_string())?;

    let token_type = extract_json_string(&body_str, "token_type").unwrap_or_default();
    let expires_in = extract_json_number(&body_str, "expires_in").unwrap_or(-1);
    let resp_scope = extract_json_string(&body_str, "scope").unwrap_or_default();

    Ok(OAuth2TokenResult {
        success: true,
        access_token,
        token_type,
        expires_in,
        scope: resp_scope,
        message: String::new(),
    })
}

/// Minimal URL-encoding for OAuth2 form fields.
/// Encodes the characters that are not unreserved per RFC 3986.
fn url_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            _ => {
                out.push('%');
                out.push(char::from_digit((b >> 4) as u32, 16).unwrap_or('0').to_ascii_uppercase());
                out.push(char::from_digit((b & 0xF) as u32, 16).unwrap_or('0').to_ascii_uppercase());
            }
        }
    }
    out
}

/// Minimal JSON string field extractor (no external dep).
fn extract_json_string(json: &str, key: &str) -> Option<String> {
    let needle = format!("\"{}\"", key);
    let pos = json.find(&needle)?;
    let after_key = &json[pos + needle.len()..];
    let colon_pos = after_key.find(':')? + 1;
    let after_colon = after_key[colon_pos..].trim_start();
    if !after_colon.starts_with('"') {
        return None;
    }
    let inner = &after_colon[1..];
    let end = find_string_end(inner)?;
    Some(unescape_json_string(&inner[..end]))
}

/// Minimal JSON number field extractor.
fn extract_json_number(json: &str, key: &str) -> Option<i64> {
    let needle = format!("\"{}\"", key);
    let pos = json.find(&needle)?;
    let after_key = &json[pos + needle.len()..];
    let colon_pos = after_key.find(':')? + 1;
    let after_colon = after_key[colon_pos..].trim_start();
    let end = after_colon
        .find(|c: char| !c.is_ascii_digit() && c != '-')
        .unwrap_or(after_colon.len());
    after_colon[..end].parse().ok()
}

/// Find the end of a JSON string (index of the closing unescaped `"`).
fn find_string_end(s: &str) -> Option<usize> {
    let mut escaped = false;
    for (i, c) in s.char_indices() {
        if escaped {
            escaped = false;
        } else if c == '\\' {
            escaped = true;
        } else if c == '"' {
            return Some(i);
        }
    }
    None
}

fn unescape_json_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.next() {
                Some('"') => out.push('"'),
                Some('\\') => out.push('\\'),
                Some('/') => out.push('/'),
                Some('n') => out.push('\n'),
                Some('r') => out.push('\r'),
                Some('t') => out.push('\t'),
                Some(other) => {
                    out.push('\\');
                    out.push(other);
                }
                None => {}
            }
        } else {
            out.push(c);
        }
    }
    out
}
