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
    let mut body = format!(
        "grant_type=client_credentials&client_id={}&client_secret={}",
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
        return Err(format!(
            "OAuth2 token endpoint returned HTTP {status}: {body_str}"
        ));
    }

    // Parse JSON response using serde_json for correctness and safety.
    // The manual parser previously used was vulnerable to key-name ambiguity,
    // did not handle Unicode escapes (\uXXXX), and could misparse valid JSON
    // responses that use non-standard formatting (CWE-116).
    let json: serde_json::Value = serde_json::from_str(&body_str)
        .map_err(|e| format!("Failed to parse token response as JSON: {e}"))?;

    let obj = json
        .as_object()
        .ok_or_else(|| "Token response JSON is not an object".to_string())?;

    let access_token = obj
        .get("access_token")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "access_token not found in token response".to_string())?
        .to_string();

    let token_type = obj
        .get("token_type")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    // expires_in may be a JSON number or a quoted string depending on the AS.
    let expires_in = obj
        .get("expires_in")
        .and_then(|v| v.as_i64().or_else(|| v.as_str().and_then(|s| s.parse().ok())))
        .unwrap_or(-1);

    let resp_scope = obj
        .get("scope")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    Ok(OAuth2TokenResult {
        success: true,
        access_token,
        token_type,
        expires_in,
        scope: resp_scope,
        message: String::new(),
    })
}

/// URL-encoding for OAuth2 form fields (RFC 3986 unreserved characters).
fn url_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            _ => {
                out.push('%');
                out.push(
                    char::from_digit((b >> 4) as u32, 16)
                        .unwrap_or('0')
                        .to_ascii_uppercase(),
                );
                out.push(
                    char::from_digit((b & 0xF) as u32, 16)
                        .unwrap_or('0')
                        .to_ascii_uppercase(),
                );
            }
        }
    }
    out
}
