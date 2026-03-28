# Implementation Guide: SMTP Send

## Goal

Send emails from SQL queries. Primary use case: alerting on query results (threshold violations, anomaly detection, report delivery).

## SQL Interface

```sql
-- Simple send
SELECT smtp_send(
    'smtp://mail.example.com:587',    -- SMTP server
    'alerts@example.com',              -- from
    'ops-team@example.com',            -- to
    'Alert: High Error Rate',          -- subject
    'Error rate exceeded 5% threshold at 2026-03-28 14:00 UTC.'  -- body
);
-- Returns: STRUCT(success BOOLEAN, message VARCHAR)

-- With TLS (STARTTLS on port 587 or implicit TLS on port 465)
SELECT smtp_send(
    'smtps://mail.example.com:465',
    'alerts@example.com',
    'ops@example.com',
    'Daily Report',
    'See attached metrics summary.'
);

-- With authentication
SELECT smtp_send(
    'smtp://mail.example.com:587',
    'alerts@example.com',
    'ops@example.com',
    'Subject',
    'Body',
    username := 'alerts@example.com',
    password := 'app-password-here'
);

-- Practical: send alert based on query results
SELECT smtp_send(
    'smtp://mail.internal:587',
    'monitor@company.com',
    'oncall@company.com',
    'ALERT: ' || metric_name || ' is ' || current_value,
    'Threshold: ' || threshold || ', Current: ' || current_value || ', Time: ' || now()
)
FROM metrics
WHERE current_value > threshold;
```

## Function Signature

```
smtp_send(
    server VARCHAR,         -- smtp://host:port or smtps://host:port
    from_addr VARCHAR,
    to_addr VARCHAR,
    subject VARCHAR,
    body VARCHAR,
    [username VARCHAR],     -- named parameter, optional
    [password VARCHAR]      -- named parameter, optional
) -> STRUCT(success BOOLEAN, message VARCHAR)
```

## Architecture

### File Structure

```
src/
  smtp.rs           # Pure SMTP logic (no DuckDB deps)
  ffi/
    mod.rs          # Updated: register SMTP functions
    smtp.rs         # SMTP scalar function callback + registration
```

### SMTP Implementation

**Option A: Use a crate (lettre)**
```toml
lettre = { version = "0.11", default-features = false, features = ["smtp-transport", "rustls-tls"] }
```
- Pro: Full SMTP support, STARTTLS, authentication, MIME
- Con: Heavy dependency (adds tokio or equivalent async runtime)

**Option B: Minimal raw SMTP over TCP**

SMTP is a simple text protocol. For basic email sending:

```
EHLO duck_net
AUTH LOGIN <base64_user> <base64_pass>     (if credentials provided)
MAIL FROM:<from@example.com>
RCPT TO:<to@example.com>
DATA
From: from@example.com
To: to@example.com
Subject: Alert
Date: Sat, 28 Mar 2026 14:00:00 +0000
Content-Type: text/plain; charset=utf-8

Body text here.
.
QUIT
```

This is ~100 lines of TCP socket code. For TLS, use rustls (already in our dependency tree via ureq).

**Recommendation**: Implement raw SMTP. The protocol is simple enough that a dependency isn't justified. We already have rustls for TLS. A minimal implementation covers:
- EHLO handshake
- STARTTLS upgrade (reuse rustls)
- AUTH LOGIN or AUTH PLAIN
- Single recipient (MAIL FROM, RCPT TO, DATA)
- Proper message formatting (RFC 5322 headers, dot-stuffing)

### Raw SMTP Client

```rust
use std::io::{BufRead, BufReader, Write};
use std::net::TcpStream;

pub struct SmtpResult {
    pub success: bool,
    pub message: String,
}

pub fn send_email(
    server: &str,     // "smtp://host:port" or "smtps://host:port"
    from: &str,
    to: &str,
    subject: &str,
    body: &str,
    username: Option<&str>,
    password: Option<&str>,
) -> SmtpResult {
    // 1. Parse server URL (scheme, host, port)
    // 2. Connect TCP
    // 3. If smtps://, wrap in TLS immediately (implicit TLS)
    // 4. Read greeting (220)
    // 5. Send EHLO, parse capabilities
    // 6. If smtp:// and server supports STARTTLS, upgrade to TLS
    // 7. If credentials, AUTH LOGIN
    // 8. MAIL FROM, RCPT TO, DATA, message, QUIT
    // 9. Return success/failure
}
```

### TLS Integration

rustls is already in our dependency tree. For SMTP TLS:

```rust
use std::sync::Arc;
use rustls::{ClientConfig, ClientConnection, StreamOwned};

fn upgrade_to_tls(stream: TcpStream, hostname: &str) -> Result<StreamOwned<ClientConnection, TcpStream>, ...> {
    let config = ClientConfig::builder()
        .with_webpki_roots()  // or with_native_roots()
        .with_no_client_auth();
    let server_name = hostname.try_into()?;
    let conn = ClientConnection::new(Arc::new(config), server_name)?;
    Ok(StreamOwned::new(conn, stream))
}
```

**Note**: Check if rustls is accessible as a direct dependency or only transitively via ureq. If transitive-only, we may need to add it as an explicit dependency or use ureq's TLS connector.

Actually, for SMTP TLS, the simplest approach may be to NOT implement it ourselves but use `native-tls` or just require that the SMTP server is on the same network (no TLS needed for internal alerting). Evaluate at implementation time.

### Registration

Return type is `STRUCT(success BOOLEAN, message VARCHAR)` — this is a simple struct with only TypeId members. quack-rs `LogicalType::struct_type` CAN handle this:

```rust
con.register_scalar(
    ScalarFunctionBuilder::new("smtp_send")
        .param(TypeId::Varchar)  // server
        .param(TypeId::Varchar)  // from
        .param(TypeId::Varchar)  // to
        .param(TypeId::Varchar)  // subject
        .param(TypeId::Varchar)  // body
        .returns_logical(LogicalType::struct_type(&[
            ("success", TypeId::Boolean),
            ("message", TypeId::Varchar),
        ]))
        .function(smtp_send_callback),
)?;
```

For the variant with username/password: either a separate overload with 7 params, or named parameters (check if quack-rs ScalarFunctionBuilder supports named params — it likely doesn't, as named params are a table function feature).

Simplest approach: two overloads via ScalarFunctionSetBuilder:
1. `(server, from, to, subject, body)` — no auth
2. `(server, from, to, subject, body, username, password)` — with auth

## Dependencies

Ideally none new. Raw SMTP over TCP + rustls (already in tree).

If rustls is not directly accessible, consider adding:
```toml
rustls = { version = "0.23", default-features = false }
```

Or skip TLS for v1 and only support unencrypted SMTP (for internal/trusted networks). Add TLS in a follow-up.

## Estimated Scope

- URL parsing (smtp:// scheme): ~20 lines
- Raw SMTP client: ~150 lines (connect, EHLO, auth, send, quit)
- TLS upgrade: ~30 lines (if using rustls directly)
- Message formatting (RFC 5322): ~30 lines
- `ffi/smtp.rs`: ~80 lines (callback, registration)
- Total: ~310 lines

## Security Considerations

- **Credential exposure**: Username/password appear in SQL query text, which may be logged. Document this prominently.
- **Abuse potential**: An SMTP function could be used to send spam. Consider:
  - Rate limiting (max N emails per query)
  - Requiring explicit enable via a DuckDB setting: `SET duck_net_enable_smtp = true`
  - Logging all send attempts
- **Injection**: Subject and body could contain SMTP injection sequences (CRLF injection). The DATA section is terminated by `\r\n.\r\n`, so dot-stuff any lines starting with `.` in the body. Sanitize MAIL FROM/RCPT TO to prevent header injection.
- **Network access**: SMTP requires outbound TCP to port 25/587/465. May be blocked by firewalls. Document that this requires network access to the SMTP server.

## Testing

- Unit tests: mock TCP server that validates SMTP protocol sequence
- Integration tests: send to a local test SMTP server (e.g., MailHog or smtp4dev running in a container)
- Security tests: CRLF injection attempts, oversized subjects, null bytes in addresses
