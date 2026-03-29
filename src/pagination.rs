// SPDX-License-Identifier: MIT
// Copyright 2026 Tom F. <tomf@tomtomtech.net> (https://github.com/tomtom215)

use crate::http::{self, HttpResponse, Method};
use crate::json;

pub enum PaginationStrategy {
    PageNumber {
        param_name: String,
        start: i64,
        increment: i64,
    },
    NextUrl {
        json_path: Option<String>,
        use_link_header: bool,
    },
}

pub struct PaginateConfig {
    pub base_url: String,
    pub strategy: PaginationStrategy,
    pub max_pages: i64,
    pub headers: Vec<(String, String)>,
}

pub struct PaginateState {
    pub current_page: i64,
    pub next_url: Option<String>,
    pub done: bool,
    seen_urls: std::collections::HashSet<String>,
}

impl PaginateState {
    /// Create a placeholder state (will be initialized on first scan).
    pub fn empty() -> Self {
        Self {
            current_page: 0,
            next_url: None,
            done: false,
            seen_urls: std::collections::HashSet::new(),
        }
    }
}

impl PaginateState {
    pub fn new(config: &PaginateConfig) -> Self {
        let next_url = match &config.strategy {
            PaginationStrategy::PageNumber {
                param_name, start, ..
            } => Some(build_page_url(&config.base_url, param_name, *start)),
            PaginationStrategy::NextUrl { .. } => Some(config.base_url.clone()),
        };
        Self {
            current_page: 0,
            next_url,
            done: false,
            seen_urls: std::collections::HashSet::new(),
        }
    }
}

fn build_page_url(template: &str, param_name: &str, page: i64) -> String {
    let placeholder = format!("{{{param_name}}}");
    template.replace(&placeholder, &page.to_string())
}

/// Fetch the next page. Returns (page_number, response) or None if done.
pub fn fetch_next(
    config: &PaginateConfig,
    state: &mut PaginateState,
) -> Option<(i64, HttpResponse)> {
    if state.done {
        return None;
    }

    let url = state.next_url.take()?;

    // Infinite loop protection: reject URLs we've already fetched
    if !state.seen_urls.insert(url.clone()) {
        state.done = true;
        return None;
    }

    state.current_page += 1;
    let page_num = state.current_page;

    if page_num > config.max_pages {
        state.done = true;
        return None;
    }

    let resp = http::execute(Method::Get, &url, &config.headers, None);

    // Determine next URL
    if resp.status == 0 || resp.status >= 400 {
        state.done = true;
        return Some((page_num, resp));
    }

    match &config.strategy {
        PaginationStrategy::PageNumber {
            param_name,
            start,
            increment,
        } => {
            let next_page_val = start + page_num * increment;
            let next = build_page_url(&config.base_url, param_name, next_page_val);
            state.next_url = Some(next);
        }
        PaginationStrategy::NextUrl {
            json_path,
            use_link_header,
        } => {
            let mut found = false;

            // Try JSON path first
            if let Some(path) = json_path {
                if let Some(next) = json::dot_path(&resp.body, path) {
                    if !next.is_empty() {
                        state.next_url = Some(next.to_string());
                        found = true;
                    }
                }
            }

            // Try Link header
            if !found && *use_link_header {
                if let Some(next) = parse_link_header_next(&resp.headers) {
                    state.next_url = Some(next);
                    found = true;
                }
            }

            if !found {
                state.done = true;
            }
        }
    }

    // If response body is empty, we're done
    if resp.body.is_empty() || resp.body == "[]" || resp.body == "{}" {
        state.done = true;
    }

    Some((page_num, resp))
}

/// Parse RFC 8288 Link header to find rel="next" URL.
fn parse_link_header_next(headers: &[(String, String)]) -> Option<String> {
    for (name, value) in headers {
        if !name.eq_ignore_ascii_case("link") {
            continue;
        }
        // Parse: <URL>; rel="next", <URL2>; rel="last"
        for part in value.split(',') {
            let part = part.trim();
            if !part.contains("rel=\"next\"") && !part.contains("rel=next") {
                continue;
            }
            // Extract URL from <...>
            if let Some(start) = part.find('<') {
                if let Some(end) = part[start..].find('>') {
                    return Some(part[start + 1..start + end].to_string());
                }
            }
        }
    }
    None
}
