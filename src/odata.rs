// SPDX-License-Identifier: MIT
// Copyright 2026 Tom F. <tomf@tomtomtech.net> (https://github.com/tomtom215)

use crate::http::{self, HttpResponse, Method};
use crate::json;

/// Build an OData query URL with system query options.
pub fn build_url(
    base_url: &str,
    filter: Option<&str>,
    select: Option<&str>,
    top: Option<i64>,
    skip: Option<i64>,
    orderby: Option<&str>,
    expand: Option<&str>,
) -> String {
    let mut params = Vec::new();

    if let Some(f) = filter {
        if !f.is_empty() {
            params.push(format!("$filter={}", crate::json::form_urlencode(f)));
        }
    }
    if let Some(s) = select {
        if !s.is_empty() {
            params.push(format!("$select={}", crate::json::form_urlencode(s)));
        }
    }
    if let Some(t) = top {
        if t > 0 {
            params.push(format!("$top={t}"));
        }
    }
    if let Some(s) = skip {
        if s > 0 {
            params.push(format!("$skip={s}"));
        }
    }
    if let Some(o) = orderby {
        if !o.is_empty() {
            params.push(format!("$orderby={}", crate::json::form_urlencode(o)));
        }
    }
    if let Some(e) = expand {
        if !e.is_empty() {
            params.push(format!("$expand={}", crate::json::form_urlencode(e)));
        }
    }

    if params.is_empty() {
        base_url.to_string()
    } else {
        let sep = if base_url.contains('?') { "&" } else { "?" };
        format!("{base_url}{sep}{}", params.join("&"))
    }
}

/// Execute an OData query and return the response.
#[allow(clippy::too_many_arguments)]
pub fn query(
    base_url: &str,
    filter: Option<&str>,
    select: Option<&str>,
    top: Option<i64>,
    skip: Option<i64>,
    orderby: Option<&str>,
    expand: Option<&str>,
    headers: &[(String, String)],
) -> HttpResponse {
    let url = build_url(base_url, filter, select, top, skip, orderby, expand);

    let mut all_headers: Vec<(String, String)> = headers.to_vec();
    if !all_headers
        .iter()
        .any(|(k, _)| k.eq_ignore_ascii_case("accept"))
    {
        all_headers.push(("Accept".into(), "application/json".into()));
    }

    http::execute(Method::Get, &url, &all_headers, None)
}

/// Extract the next-page URL from a response body for pagination.
///
/// Checks the following keys in order:
/// - `@odata.nextLink` — OData v4 standard
/// - `odata.nextLink`  — OData v4 (unescaped variant found in some implementations)
/// - `__next`          — OData v2 JSON responses
pub fn extract_next_link(body: &str) -> Option<&str> {
    json::extract_string(body, "@odata.nextLink")
        .or_else(|| json::extract_string(body, "odata.nextLink"))
        .or_else(|| json::extract_string(body, "__next"))
}

/// Extract the server-reported total record count from a response body.
///
/// Checks the following keys in order:
/// - `@odata.count` — OData v4 (unquoted integer: `"@odata.count": 1234`)
/// - `odata.count`  — OData v4 unescaped variant
/// - `__count`      — OData v2 JSON (quoted string: `"__count": "1234"`)
///
/// OData v4 services must be queried with `$count=true` to include this field.
/// OData v2 services must be queried with `$inlinecount=allpages`.
pub fn extract_total_count(body: &str) -> Option<i64> {
    // v4: unquoted integer
    let raw = json::extract_number(body, "@odata.count")
        .or_else(|| json::extract_number(body, "odata.count"))
        // v2: quoted string (parse the string value as integer)
        .or_else(|| json::extract_string(body, "__count"))?;
    raw.parse::<i64>().ok()
}

/// Extract the `value` array count (rough — counts commas between top-level array elements).
#[allow(dead_code)]
pub fn extract_value_count(body: &str) -> Option<usize> {
    // Find "value": [ and count items
    let needle = "\"value\"";
    let pos = body.find(needle)?;
    let after = &body[pos + needle.len()..].trim_start();
    if !after.starts_with(':') {
        return None;
    }
    let after_colon = after[1..].trim_start();
    if !after_colon.starts_with('[') {
        return None;
    }
    if after_colon.starts_with("[]") {
        return Some(0);
    }

    // Count top-level elements
    let mut depth = 0;
    let mut count = 1usize;
    for ch in after_colon.chars().skip(1) {
        match ch {
            '[' | '{' => depth += 1,
            ']' if depth == 0 => break,
            ']' | '}' => depth -= 1,
            ',' if depth == 0 => count += 1,
            _ => {}
        }
    }
    Some(count)
}

/// Paginated OData query state.
pub struct ODataPaginateState {
    pub next_url: Option<String>,
    pub current_page: i64,
    pub done: bool,
}

impl ODataPaginateState {
    pub fn new() -> Self {
        Self {
            next_url: None,
            current_page: 0,
            done: false,
        }
    }
}

/// Fetch the next page of OData results.
#[allow(clippy::too_many_arguments)]
pub fn fetch_next_page(
    base_url: &str,
    filter: Option<&str>,
    select: Option<&str>,
    top: Option<i64>,
    orderby: Option<&str>,
    expand: Option<&str>,
    headers: &[(String, String)],
    state: &mut ODataPaginateState,
    max_pages: i64,
) -> Option<(i64, HttpResponse)> {
    if state.done || state.current_page >= max_pages {
        return None;
    }

    let url = if let Some(ref next) = state.next_url {
        next.clone()
    } else if state.current_page == 0 {
        build_url(base_url, filter, select, top, None, orderby, expand)
    } else {
        state.done = true;
        return None;
    };

    let mut all_headers: Vec<(String, String)> = headers.to_vec();
    if !all_headers
        .iter()
        .any(|(k, _)| k.eq_ignore_ascii_case("accept"))
    {
        all_headers.push(("Accept".into(), "application/json".into()));
    }

    let resp = http::execute(Method::Get, &url, &all_headers, None);
    state.current_page += 1;

    if resp.status == 200 {
        match extract_next_link(&resp.body) {
            Some(next) => state.next_url = Some(next.to_string()),
            None => state.done = true,
        }
    } else {
        state.done = true;
    }

    Some((state.current_page, resp))
}
