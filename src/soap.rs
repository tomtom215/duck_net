// SPDX-License-Identifier: MIT
// Copyright 2026 Tom F. <tomf@tomtomtech.net> (https://github.com/tomtom215)

use crate::http::{self, HttpResponse, Method};

#[derive(Debug, Clone, Copy)]
pub enum SoapVersion {
    V1_1,
    V1_2,
}

pub fn build_envelope(body_xml: &str, header_xml: Option<&str>, version: SoapVersion) -> String {
    let ns = match version {
        SoapVersion::V1_1 => "http://schemas.xmlsoap.org/soap/envelope/",
        SoapVersion::V1_2 => "http://www.w3.org/2003/05/soap-envelope",
    };
    let header_block = match header_xml {
        Some(h) if !h.is_empty() => format!("\n  <soap:Header>\n    {h}\n  </soap:Header>"),
        _ => String::new(),
    };
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <soap:Envelope xmlns:soap=\"{ns}\">{header_block}\n\
         \x20\x20<soap:Body>\n\
         \x20\x20\x20\x20{body_xml}\n\
         \x20\x20</soap:Body>\n\
         </soap:Envelope>"
    )
}

pub fn send_request(
    url: &str,
    action: &str,
    body_xml: &str,
    header_xml: Option<&str>,
    custom_headers: &[(String, String)],
    version: SoapVersion,
) -> HttpResponse {
    let envelope = build_envelope(body_xml, header_xml, version);

    let mut headers: Vec<(String, String)> = custom_headers.to_vec();

    match version {
        SoapVersion::V1_1 => {
            headers.push(("Content-Type".into(), "text/xml; charset=utf-8".into()));
            headers.push(("SOAPAction".into(), format!("\"{action}\"")));
        }
        SoapVersion::V1_2 => {
            headers.push((
                "Content-Type".into(),
                format!("application/soap+xml; charset=utf-8; action=\"{action}\""),
            ));
        }
    }

    http::execute(Method::Post, url, &headers, Some(&envelope))
}

/// Extract content from `<soap:Body>...</soap:Body>` with various namespace prefixes.
pub fn extract_body(xml: &str) -> Option<&str> {
    const PATTERNS: &[(&str, &str)] = &[
        ("<soap:Body>", "</soap:Body>"),
        ("<SOAP-ENV:Body>", "</SOAP-ENV:Body>"),
        ("<soapenv:Body>", "</soapenv:Body>"),
        ("<Body>", "</Body>"),
        ("<s:Body>", "</s:Body>"),
        ("<S:Body>", "</S:Body>"),
    ];

    for &(open, close) in PATTERNS {
        if let Some(start) = xml.find(open) {
            let content_start = start + open.len();
            if let Some(end) = xml[content_start..].find(close) {
                return Some(xml[content_start..content_start + end].trim());
            }
        }
    }
    None
}

/// Check if a SOAP response contains a fault.
pub fn is_fault(xml: &str) -> bool {
    xml.contains("<soap:Fault")
        || xml.contains("<SOAP-ENV:Fault")
        || xml.contains("<soapenv:Fault")
        || xml.contains("<Fault")
        || xml.contains("<s:Fault")
        || xml.contains("<S:Fault")
}

/// Extract the fault string from a SOAP fault response.
pub fn fault_string(xml: &str) -> Option<&str> {
    // SOAP 1.1: <faultstring>...</faultstring>
    // SOAP 1.2: <soap:Reason><soap:Text>...</soap:Text></soap:Reason>
    const PATTERNS: &[(&str, &str)] = &[
        ("<faultstring>", "</faultstring>"),
        ("<soap:Text", "</soap:Text>"),
        ("<SOAP-ENV:Text", "</SOAP-ENV:Text>"),
        ("<soapenv:Text", "</soapenv:Text>"),
        ("<s:Text", "</s:Text>"),
        ("<S:Text", "</S:Text>"),
    ];

    for &(open_prefix, close) in PATTERNS {
        if let Some(start) = xml.find(open_prefix) {
            // Handle the opening tag which may have attributes (e.g. xml:lang="en")
            let after_open = start + open_prefix.len();
            let tag_end = if open_prefix.ends_with('>') {
                after_open
            } else {
                // Find the closing > of the opening tag
                match xml[after_open..].find('>') {
                    Some(pos) => after_open + pos + 1,
                    None => continue,
                }
            };
            if let Some(end) = xml[tag_end..].find(close) {
                return Some(xml[tag_end..tag_end + end].trim());
            }
        }
    }
    None
}
