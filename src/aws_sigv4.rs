// SPDX-License-Identifier: MIT
// Copyright 2026 Tom F. <tomf@tomtomtech.net> (https://github.com/tomtom215)

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

type HmacSha256 = Hmac<Sha256>;

/// AWS SigV4 signed request result including any extra required headers.
pub struct SignedRequest {
    pub authorization: String,
    pub x_amz_date: String,
    pub x_amz_content_sha256: String,
    /// Present when a session token was provided (STS temporary credentials).
    pub x_amz_security_token: Option<String>,
}

/// Sign an HTTP request using AWS Signature Version 4.
///
/// `session_token` is required when using temporary credentials obtained from
/// AWS STS (e.g., assumed roles, instance metadata). Pass `None` for permanent
/// IAM credentials.
///
/// Returns the Authorization header value and required X-Amz-* headers.
///
/// # Security notes
///
/// - **Replay window**: Every call generates a fresh `X-Amz-Date` timestamp
///   via [`amz_datetime`]. AWS enforces a 15-minute validity window on SigV4
///   signatures at the server side, so even if a caller caches and replays
///   a signed request, AWS will reject it outside that window. duck_net
///   therefore does not attempt to implement a nonce; the timestamp + server
///   enforcement is the canonical mitigation.
/// - **Constant-time comparison**: duck_net is only a *producer* of SigV4
///   signatures — it never verifies remote signatures — so there is no
///   attacker-observable secret-dependent comparison in this module. For
///   comparisons elsewhere (e.g. authentication tokens), use
///   [`crate::security::constant_time_eq`].
/// - **HMAC key lifetime**: The derived signing key is held only for the
///   duration of one call. Upstream AWS docs recommend caching it across
///   requests to the same date/region/service, but we prioritise memory
///   hygiene over throughput. A session-level cache could be added behind
///   `zeroize::Zeroizing` if profiling shows it is a bottleneck.
#[allow(clippy::too_many_arguments)]
pub fn sign(
    method: &str,
    url: &str,
    headers: &[(String, String)],
    body: &str,
    access_key: &str,
    secret_key: &str,
    region: &str,
    service: &str,
) -> Result<SignedRequest, String> {
    sign_with_token(
        method, url, headers, body, access_key, secret_key, region, service, None,
    )
}

/// Sign an HTTP request using AWS Signature Version 4 with an optional session token.
#[allow(clippy::too_many_arguments)]
pub fn sign_with_token(
    method: &str,
    url: &str,
    headers: &[(String, String)],
    body: &str,
    access_key: &str,
    secret_key: &str,
    region: &str,
    service: &str,
    session_token: Option<&str>,
) -> Result<SignedRequest, String> {
    let (host, path, query) = parse_url(url)?;
    let datetime = amz_datetime();
    let date = &datetime[..8];

    // Step 1: Create canonical request
    let payload_hash = hex_sha256(body.as_bytes());

    let mut signed_headers_list: Vec<(String, String)> = headers
        .iter()
        .map(|(k, v)| (k.to_ascii_lowercase(), v.trim().to_string()))
        .collect();
    signed_headers_list.push(("host".to_string(), host.clone()));
    signed_headers_list.push(("x-amz-date".to_string(), datetime.clone()));
    signed_headers_list.push(("x-amz-content-sha256".to_string(), payload_hash.clone()));
    // Include the security token in the canonical signed headers when present
    if let Some(token) = session_token {
        signed_headers_list.push(("x-amz-security-token".to_string(), token.to_string()));
    }
    signed_headers_list.sort_by(|a, b| a.0.cmp(&b.0));

    let canonical_headers: String = signed_headers_list
        .iter()
        .map(|(k, v)| format!("{k}:{v}\n"))
        .collect();
    let signed_headers: String = signed_headers_list
        .iter()
        .map(|(k, _)| k.as_str())
        .collect::<Vec<_>>()
        .join(";");

    let canonical_request =
        format!("{method}\n{path}\n{query}\n{canonical_headers}\n{signed_headers}\n{payload_hash}");

    // Step 2: Create string to sign
    let credential_scope = format!("{date}/{region}/{service}/aws4_request");
    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{datetime}\n{credential_scope}\n{}",
        hex_sha256(canonical_request.as_bytes())
    );

    // Step 3: Calculate signature
    let signing_key = derive_signing_key(secret_key, date, region, service);
    let signature = hex_hmac_sha256(&signing_key, string_to_sign.as_bytes());

    // Step 4: Build Authorization header
    let authorization = format!(
        "AWS4-HMAC-SHA256 Credential={access_key}/{credential_scope}, \
         SignedHeaders={signed_headers}, Signature={signature}"
    );

    Ok(SignedRequest {
        authorization,
        x_amz_date: datetime,
        x_amz_content_sha256: payload_hash,
        x_amz_security_token: session_token.map(|s| s.to_string()),
    })
}

fn derive_signing_key(secret_key: &str, date: &str, region: &str, service: &str) -> Vec<u8> {
    let k_secret = format!("AWS4{secret_key}");
    let k_date = hmac_sha256(k_secret.as_bytes(), date.as_bytes());
    let k_region = hmac_sha256(&k_date, region.as_bytes());
    let k_service = hmac_sha256(&k_region, service.as_bytes());
    hmac_sha256(&k_service, b"aws4_request")
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC key length is always valid");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

fn hex_hmac_sha256(key: &[u8], data: &[u8]) -> String {
    let result = hmac_sha256(key, data);
    hex_encode(&result)
}

fn hex_sha256(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex_encode(&hasher.finalize())
}

fn hex_encode(data: &[u8]) -> String {
    data.iter().map(|b| format!("{b:02x}")).collect()
}

fn amz_datetime() -> String {
    let dur = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = dur.as_secs();
    let days = secs / 86400;
    let tod = secs % 86400;
    let (y, m, d) = days_to_ymd(days);
    format!(
        "{y:04}{m:02}{d:02}T{:02}{:02}{:02}Z",
        tod / 3600,
        (tod % 3600) / 60,
        tod % 60
    )
}

fn days_to_ymd(days: u64) -> (u64, u64, u64) {
    let z = days + 719468;
    let era = z / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

fn parse_url(url: &str) -> Result<(String, String, String), String> {
    // Strip scheme
    let rest = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
        .ok_or_else(|| format!("URL must start with http:// or https://: {url}"))?;

    let (host_and_path, _) = rest.split_once('#').unwrap_or((rest, ""));
    let (host_part, path_and_query) = if let Some(pos) = host_and_path.find('/') {
        (&host_and_path[..pos], &host_and_path[pos..])
    } else {
        (host_and_path, "/")
    };

    let (path, query) = path_and_query
        .split_once('?')
        .unwrap_or((path_and_query, ""));

    Ok((host_part.to_string(), path.to_string(), query.to_string()))
}
