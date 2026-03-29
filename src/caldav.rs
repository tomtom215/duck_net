// SPDX-License-Identifier: MIT
// Copyright 2026 Tom F. <tomf@tomtomtech.net> (https://github.com/tomtom215)

use crate::http::{self, HttpResponse};

/// A calendar event returned by CalDAV REPORT.
pub struct CalDavEvent {
    pub href: String,
    pub etag: String,
    pub data: String,
}

/// A contact entry returned by CardDAV REPORT.
pub struct CardDavContact {
    pub href: String,
    pub etag: String,
    pub data: String,
}

/// List calendar events via CalDAV REPORT.
pub fn list_events(
    url: &str,
    headers: &[(String, String)],
    time_range_start: Option<&str>,
    time_range_end: Option<&str>,
) -> Result<Vec<CalDavEvent>, String> {
    let body = build_calendar_query(time_range_start, time_range_end);

    let mut all_headers: Vec<(String, String)> = headers.to_vec();
    all_headers.push((
        "Content-Type".into(),
        "application/xml; charset=utf-8".into(),
    ));
    all_headers.push(("Depth".into(), "1".into()));

    let resp = execute_report(url, &all_headers, &body)?;
    Ok(parse_calendar_multistatus(&resp.body))
}

/// List contacts via CardDAV REPORT.
pub fn list_contacts(
    url: &str,
    headers: &[(String, String)],
) -> Result<Vec<CardDavContact>, String> {
    let body = r#"<?xml version="1.0" encoding="UTF-8"?>
<card:addressbook-query xmlns:d="DAV:" xmlns:card="urn:ietf:params:xml:ns:carddav">
  <d:prop>
    <d:getetag/>
    <card:address-data/>
  </d:prop>
</card:addressbook-query>"#;

    let mut all_headers: Vec<(String, String)> = headers.to_vec();
    all_headers.push((
        "Content-Type".into(),
        "application/xml; charset=utf-8".into(),
    ));
    all_headers.push(("Depth".into(), "1".into()));

    let resp = execute_report(url, &all_headers, body)?;
    Ok(parse_carddav_multistatus(&resp.body))
}

/// Discover CalDAV/CardDAV principal and collection URLs.
#[allow(dead_code)]
pub fn discover(url: &str, headers: &[(String, String)]) -> Result<Vec<String>, String> {
    let body = r#"<?xml version="1.0" encoding="UTF-8"?>
<d:propfind xmlns:d="DAV:" xmlns:c="urn:ietf:params:xml:ns:caldav">
  <d:prop>
    <d:current-user-principal/>
    <c:calendar-home-set/>
  </d:prop>
</d:propfind>"#;

    let mut all_headers: Vec<(String, String)> = headers.to_vec();
    all_headers.push((
        "Content-Type".into(),
        "application/xml; charset=utf-8".into(),
    ));
    all_headers.push(("Depth".into(), "0".into()));

    let resp = execute_propfind(url, &all_headers, body)?;
    let hrefs = extract_all_hrefs(&resp.body);
    Ok(hrefs)
}

fn build_calendar_query(start: Option<&str>, end: Option<&str>) -> String {
    let time_range = match (start, end) {
        (Some(s), Some(e)) => format!(
            "\n    <c:filter>\n      <c:comp-filter name=\"VCALENDAR\">\n        \
             <c:comp-filter name=\"VEVENT\">\n          \
             <c:time-range start=\"{s}\" end=\"{e}\"/>\n        \
             </c:comp-filter>\n      </c:comp-filter>\n    </c:filter>"
        ),
        (Some(s), None) => format!(
            "\n    <c:filter>\n      <c:comp-filter name=\"VCALENDAR\">\n        \
             <c:comp-filter name=\"VEVENT\">\n          \
             <c:time-range start=\"{s}\"/>\n        \
             </c:comp-filter>\n      </c:comp-filter>\n    </c:filter>"
        ),
        _ => String::from(
            "\n    <c:filter>\n      <c:comp-filter name=\"VCALENDAR\"/>\n    </c:filter>",
        ),
    };

    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <c:calendar-query xmlns:d=\"DAV:\" xmlns:c=\"urn:ietf:params:xml:ns:caldav\">\n\
         \x20\x20<d:prop>\n\
         \x20\x20\x20\x20<d:getetag/>\n\
         \x20\x20\x20\x20<c:calendar-data/>\n\
         \x20\x20</d:prop>{time_range}\n\
         </c:calendar-query>"
    )
}

fn execute_report(
    url: &str,
    headers: &[(String, String)],
    body: &str,
) -> Result<HttpResponse, String> {
    let resp = http::execute_raw_method("REPORT", url, headers, Some(body));
    if resp.status != 207 && resp.status != 200 && resp.status != 0 {
        return Err(format!("REPORT failed: {} {}", resp.status, resp.reason));
    }
    if resp.status == 0 {
        return Err(resp.reason);
    }
    Ok(resp)
}

fn execute_propfind(
    url: &str,
    headers: &[(String, String)],
    body: &str,
) -> Result<HttpResponse, String> {
    let resp = http::execute_raw_method("PROPFIND", url, headers, Some(body));
    if resp.status == 0 {
        return Err(resp.reason);
    }
    Ok(resp)
}

fn parse_calendar_multistatus(xml: &str) -> Vec<CalDavEvent> {
    let mut events = Vec::new();
    let responses = split_responses(xml);

    for chunk in responses {
        let href = extract_xml_content(&chunk, "href").unwrap_or_default();
        let etag = extract_xml_content(&chunk, "getetag").unwrap_or_default();
        let data = extract_xml_content(&chunk, "calendar-data").unwrap_or_default();

        if !data.is_empty() {
            events.push(CalDavEvent { href, etag, data });
        }
    }

    events
}

fn parse_carddav_multistatus(xml: &str) -> Vec<CardDavContact> {
    let mut contacts = Vec::new();
    let responses = split_responses(xml);

    for chunk in responses {
        let href = extract_xml_content(&chunk, "href").unwrap_or_default();
        let etag = extract_xml_content(&chunk, "getetag").unwrap_or_default();
        let data = extract_xml_content(&chunk, "address-data").unwrap_or_default();

        if !data.is_empty() {
            contacts.push(CardDavContact { href, etag, data });
        }
    }

    contacts
}

fn split_responses(xml: &str) -> Vec<String> {
    let mut results = Vec::new();
    for prefix in &["d:", "D:", ""] {
        let open = format!("<{prefix}response");
        let close = format!("</{prefix}response>");
        let mut search_from = 0;
        while let Some(start) = xml[search_from..].find(&open) {
            let abs_start = search_from + start;
            if let Some(end) = xml[abs_start..].find(&close) {
                let abs_end = abs_start + end + close.len();
                results.push(xml[abs_start..abs_end].to_string());
                search_from = abs_end;
            } else {
                break;
            }
        }
        if !results.is_empty() {
            break;
        }
    }
    results
}

fn extract_xml_content(xml: &str, tag: &str) -> Option<String> {
    for prefix in &["d:", "D:", "c:", "C:", "card:", ""] {
        let open = format!("<{prefix}{tag}>");
        let close = format!("</{prefix}{tag}>");
        if let Some(start) = xml.find(&open) {
            let content_start = start + open.len();
            if let Some(end) = xml[content_start..].find(&close) {
                return Some(xml[content_start..content_start + end].trim().to_string());
            }
        }
        // Handle tag with attributes
        let open_attr = format!("<{prefix}{tag} ");
        if let Some(start) = xml.find(&open_attr) {
            let after = &xml[start + open_attr.len()..];
            if let Some(gt) = after.find('>') {
                let content_start = start + open_attr.len() + gt + 1;
                if let Some(end) = xml[content_start..].find(&close) {
                    return Some(xml[content_start..content_start + end].trim().to_string());
                }
            }
        }
    }
    None
}

fn extract_all_hrefs(xml: &str) -> Vec<String> {
    let mut hrefs = Vec::new();
    for prefix in &["d:", "D:", ""] {
        let open = format!("<{prefix}href>");
        let close = format!("</{prefix}href>");
        let mut pos = 0;
        while let Some(start) = xml[pos..].find(&open) {
            let abs_start = pos + start + open.len();
            if let Some(end) = xml[abs_start..].find(&close) {
                hrefs.push(xml[abs_start..abs_start + end].trim().to_string());
                pos = abs_start + end + close.len();
            } else {
                break;
            }
        }
        if !hrefs.is_empty() {
            break;
        }
    }
    hrefs
}
