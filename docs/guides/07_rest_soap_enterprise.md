# Implementation Guide: Enterprise REST and SOAP Support

## The Reality

### REST

REST is an architectural pattern over HTTP. duck_net is already a REST client. The gap is not "add REST support" — it's "finish the HTTP enhancements that make REST usage production-grade."

Completing Guides 01-03 (retry, pagination, auth) closes this gap entirely:

| Enterprise REST Need | Solution |
|---------------------|----------|
| Call any endpoint | `http_get`, `http_post`, etc. — done |
| Custom headers/auth | MAP parameter — done |
| JSON bodies | VARCHAR with DuckDB JSON functions — done |
| File upload | `http_post_multipart` — done |
| Pagination | Guide 02 (`http_paginate` table function) |
| Auth (Basic/Bearer/OAuth2) | Guide 03 (`http_basic_auth`, `http_oauth2_token`) |
| Retry/backoff | Guide 01 (configurable retry) |
| Rate limiting | New — see below |

The only net-new REST work is **rate limiting** — everything else is already built or planned.

### SOAP

SOAP is XML-based RPC over HTTP. It can be called today via `http_post` with manual XML construction, but that's painful. The value-add is **envelope helpers** that eliminate boilerplate while staying pragmatic — not a full WSDL-driven client (which would be thousands of lines for diminishing returns).

## New Functions to Implement

### Rate Limiting (REST)

```sql
-- Configure per-domain rate limits
SET duck_net_rate_limit = '{"api.example.com": 10, "*.slow-api.com": 2}';
-- Values are max requests per second per domain

-- Or simpler: global rate limit
SET duck_net_requests_per_second = 10;

-- All HTTP functions automatically respect rate limits
SELECT http_get('https://api.example.com/users/' || id)
FROM generate_series(1, 1000) AS t(id);
-- Automatically throttled to 10 req/s
```

#### Implementation

Token bucket or sliding window per domain, stored in a global `Mutex<HashMap<String, RateLimiter>>`.

```rust
struct RateLimiter {
    tokens: f64,
    max_tokens: f64,
    refill_rate: f64,     // tokens per second
    last_refill: Instant,
}

impl RateLimiter {
    fn acquire(&mut self) -> Duration {
        self.refill();
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            Duration::ZERO
        } else {
            let wait = Duration::from_secs_f64((1.0 - self.tokens) / self.refill_rate);
            self.tokens = 0.0;
            wait
        }
    }
}
```

Called in `http::execute()` before making the request. If `acquire()` returns a non-zero duration, `thread::sleep()` before proceeding.

**Estimated scope**: ~80 lines for rate limiter + ~20 lines for config reading.

### SOAP Envelope Helper

```sql
-- Build and send a SOAP request in one call
SELECT soap_request(
    'https://soap.example.com/AccountService',          -- endpoint
    'http://example.com/GetAccount',                     -- SOAPAction
    '<GetAccount xmlns="http://example.com/">
       <AccountId>12345</AccountId>
     </GetAccount>'                                      -- body XML (inner content only)
);
-- Returns same STRUCT as http_post: (status, reason, headers, body)
-- Body contains the full SOAP response XML
```

This wraps the user's XML fragment in a proper SOAP envelope, sets the correct headers, and sends it. The user only writes the operation-specific XML, not the boilerplate.

#### What it does internally

```rust
fn build_soap_envelope(body_xml: &str, soap_version: SoapVersion) -> String {
    match soap_version {
        SoapVersion::V1_1 => format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    {body_xml}
  </soap:Body>
</soap:Envelope>"#
        ),
        SoapVersion::V1_2 => format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope">
  <soap:Body>
    {body_xml}
  </soap:Body>
</soap:Envelope>"#
        ),
    }
}
```

Then calls `http::execute(Method::Post, url, headers, Some(&envelope))` with:
- `Content-Type: text/xml; charset=utf-8` (SOAP 1.1) or `application/soap+xml; charset=utf-8` (SOAP 1.2)
- `SOAPAction: <action>` header (SOAP 1.1 only)

#### Overloads

```sql
-- Minimal: endpoint, action, body XML
soap_request(url VARCHAR, action VARCHAR, body_xml VARCHAR)

-- With custom headers (e.g., WS-Security tokens, custom auth)
soap_request(url VARCHAR, action VARCHAR, body_xml VARCHAR, headers MAP(VARCHAR, VARCHAR))

-- With SOAP header block (for WS-Addressing, WS-Security, etc.)
soap_request(url VARCHAR, action VARCHAR, body_xml VARCHAR, soap_header VARCHAR)

-- Full: custom HTTP headers + SOAP header block
soap_request(url VARCHAR, action VARCHAR, body_xml VARCHAR, soap_header VARCHAR, headers MAP(VARCHAR, VARCHAR))

-- SOAP 1.2 variant (uses application/soap+xml, no SOAPAction header)
soap12_request(url VARCHAR, action VARCHAR, body_xml VARCHAR)
soap12_request(url VARCHAR, action VARCHAR, body_xml VARCHAR, soap_header VARCHAR)
soap12_request(url VARCHAR, action VARCHAR, body_xml VARCHAR, soap_header VARCHAR, headers MAP(VARCHAR, VARCHAR))
```

#### SOAP Header Support

Many enterprise SOAP services require WS-Security or WS-Addressing headers:

```sql
SELECT soap_request(
    'https://bank.example.com/PaymentService',
    'urn:ProcessPayment',
    '<ProcessPayment>
       <Amount>1000.00</Amount>
       <Currency>USD</Currency>
     </ProcessPayment>',
    '<wsse:Security xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
       <wsse:UsernameToken>
         <wsse:Username>svc_account</wsse:Username>
         <wsse:Password>password123</wsse:Password>
       </wsse:UsernameToken>
     </wsse:Security>'
);
```

The soap_header XML is inserted into `<soap:Header>...</soap:Header>` in the envelope.

```rust
fn build_soap_envelope_with_header(
    body_xml: &str,
    header_xml: Option<&str>,
    version: SoapVersion,
) -> String {
    let ns = match version {
        SoapVersion::V1_1 => "http://schemas.xmlsoap.org/soap/envelope/",
        SoapVersion::V1_2 => "http://www.w3.org/2003/05/soap-envelope",
    };
    let header_block = match header_xml {
        Some(h) => format!("\n  <soap:Header>\n    {h}\n  </soap:Header>"),
        None => String::new(),
    };
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope xmlns:soap="{ns}">{header_block}
  <soap:Body>
    {body_xml}
  </soap:Body>
</soap:Envelope>"#
    )
}
```

### SOAP Response Parsing Helper

The raw SOAP response is XML. DuckDB doesn't have built-in XML parsing. To make the response usable:

```sql
-- Extract the body content from a SOAP response
SELECT soap_extract_body(
    (soap_request('https://...', 'urn:GetAccount', '<GetAccount/>')).body
);
-- Returns: the XML content inside <soap:Body>...</soap:Body>
-- Strips the envelope, leaving only the operation response
```

#### Implementation

Simple string extraction — find `<soap:Body>` and `</soap:Body>` (or `<Body>` with various namespace prefixes), return everything between them.

```rust
fn extract_soap_body(xml: &str) -> Option<&str> {
    // Find opening Body tag (handles namespace prefixes)
    let body_patterns = [
        ("<soap:Body>", "</soap:Body>"),
        ("<SOAP-ENV:Body>", "</SOAP-ENV:Body>"),
        ("<Body>", "</Body>"),
        ("<soapenv:Body>", "</soapenv:Body>"),
    ];

    for (open, close) in body_patterns {
        if let Some(start) = xml.find(open) {
            let content_start = start + open.len();
            if let Some(end) = xml[content_start..].find(close) {
                return Some(xml[content_start..content_start + end].trim());
            }
        }
    }
    None
}
```

No XML parser dependency needed. This covers the vast majority of real SOAP responses. Users who need full XML parsing can use DuckDB's JSON functions after converting XML→JSON externally, or a future XML extension.

### SOAP Fault Detection

```sql
-- Check if a SOAP response is a fault
SELECT soap_is_fault(response_body);
-- Returns: BOOLEAN

-- Extract fault details
SELECT soap_fault_string(response_body);
-- Returns: VARCHAR (the fault string/reason, or NULL if not a fault)
```

Simple string matching for `<soap:Fault>` or `<Fault>` presence.

## What We Deliberately Do NOT Build

| Feature | Why not |
|---------|---------|
| WSDL parsing / code generation | Enormous complexity. WSDL→function mapping is a build-time tool, not a runtime SQL feature. Users who have WSDLs already know their message structures. |
| XML Schema validation | Would require a full XML parser + schema engine. Out of scope for a database extension. |
| WS-Security signing (X.509, SAML) | Crypto complexity. Users pass pre-signed headers or use the username token pattern shown above. |
| MTOM binary attachments | Very niche. Use `http_post_multipart` with appropriate MIME types instead. |
| Automatic XML→table conversion | Requires a full XML parser. Recommend external XML→JSON conversion or a dedicated XML extension. |

## Registration

### SOAP functions use only simple types — quack-rs builders work

All SOAP functions take VARCHAR parameters and return either VARCHAR or the existing response STRUCT. The response STRUCT has a MAP (same as `http_post`), so use the same raw registration pattern.

Actually: `soap_request` returns the same `STRUCT(status, reason, headers, body)` as all HTTP functions. Reuse `create_response_type()` from scalars.rs.

`soap_extract_body`, `soap_is_fault`, `soap_fault_string` return VARCHAR or BOOLEAN — trivially registered via quack-rs builders.

## File Structure

```
src/
  soap.rs           # SOAP envelope construction + response parsing (no DuckDB deps)
  ffi/
    soap.rs         # SOAP function callbacks + registration
```

The SOAP module is thin — it's string formatting + string searching. The actual HTTP call reuses `http::execute()`.

## Dependencies

**None.** SOAP support is entirely string manipulation + reusing the existing HTTP client. Zero new crates.

## Estimated Scope

| Component | Lines (approx) |
|-----------|----------------|
| `soap.rs` (envelope building, body extraction, fault detection) | 120 |
| `ffi/soap.rs` (callbacks + registration for ~8 function overloads) | 200 |
| Rate limiter (REST) | 100 |
| **Total** | **~420** |

## Testing

### SOAP

- Unit tests for envelope construction (SOAP 1.1 and 1.2, with/without headers)
- Unit tests for body extraction (various namespace prefixes, malformed XML)
- Unit tests for fault detection
- Integration tests against public SOAP services (e.g., http://www.dneonline.com/calculator.asmx)

### Rate Limiter

- Unit tests: token bucket refill, acquire timing
- Integration tests: verify throttled request rate matches configured limit
