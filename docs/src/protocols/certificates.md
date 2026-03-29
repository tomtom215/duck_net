# Certificates (TLS Inspect / OCSP / CalDAV / CardDAV)

duck_net provides functions for TLS certificate inspection, OCSP revocation checking, and CalDAV/CardDAV access.

## Functions

### TLS Inspection

| Function | Parameters | Returns |
|----------|-----------|---------|
| `tls_inspect` | `(hostname)` | VARCHAR (JSON certificate details) |
| `tls_inspect` | `(hostname, port)` | VARCHAR (JSON certificate details) |

### OCSP

| Function | Parameters | Returns |
|----------|-----------|---------|
| `ocsp_check` | `(hostname)` | VARCHAR (JSON revocation status) |
| `ocsp_check` | `(hostname, port)` | VARCHAR (JSON revocation status) |

### CalDAV / CardDAV

| Function | Parameters | Returns |
|----------|-----------|---------|
| `caldav_events` | `(url)` with named params | Table: uid, summary, dtstart, dtend, location, description |
| `carddav_contacts` | `(url)` | Table: uid, fn, email, tel, org |

## TLS Inspection

Inspect the TLS certificate of any server:

```sql
-- Inspect a website's certificate
SELECT tls_inspect('example.com');

-- Inspect a specific port
SELECT tls_inspect('mail.example.com', 993);
```

The result includes subject, issuer, validity dates, serial number, and SANs (Subject Alternative Names).

## OCSP Revocation Check

Check whether a server's TLS certificate has been revoked:

```sql
-- Check certificate revocation status
SELECT ocsp_check('example.com');

-- Check on a specific port
SELECT ocsp_check('mail.example.com', 465);
```

## CalDAV

Read calendar events from a CalDAV server:

```sql
-- List all events
FROM caldav_events('https://caldav.example.com/calendars/user/default/');

-- Filter by time range
FROM caldav_events(
    'https://caldav.example.com/calendars/user/default/',
    time_start := '2026-03-01T00:00:00Z',
    time_end := '2026-03-31T23:59:59Z'
);
```

## CardDAV

Read contacts from a CardDAV server:

```sql
-- List all contacts
FROM carddav_contacts('https://carddav.example.com/addressbooks/user/default/');
```

## Practical Examples

```sql
-- Check certificate expiry for multiple domains
SELECT
    domain,
    json_extract_string(tls_inspect(domain), '$.not_after') AS expires
FROM (VALUES ('google.com'), ('github.com'), ('duckdb.org')) AS t(domain);

-- Find expiring certificates
SELECT domain, tls_inspect(domain) AS cert
FROM (VALUES ('example.com'), ('expired.badssl.com')) AS t(domain);
```

## Security Considerations

- TLS inspection connects to the target but does not send application data.
- OCSP queries contact the CA's OCSP responder, which may log the checked domain.
- CalDAV/CardDAV servers typically require authentication; pass credentials via HTTP headers or use Basic auth.
- All hostnames are validated against [SSRF rules](../security/ssrf.md).
