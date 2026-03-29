# Time (NTP / PTP)

duck_net provides functions for querying network time servers using NTP and PTP protocols.

## Functions

| Function | Parameters | Returns |
|----------|-----------|---------|
| `ntp_query` | `(server)` | VARCHAR (JSON with time and offset) |
| `sntp_query` | `(server)` | VARCHAR (JSON with time and offset) |
| `ptp_probe` | `(host)` | VARCHAR (JSON with PTP info) |
| `ptp_probe` | `(host, port)` | VARCHAR (JSON with PTP info) |

## NTP

Query an NTP server for the current time and clock offset:

```sql
-- Query a public NTP server
SELECT ntp_query('pool.ntp.org');

-- Query a specific NTP server
SELECT ntp_query('time.google.com');
```

## SNTP

Simplified NTP query (same protocol, lighter implementation):

```sql
SELECT sntp_query('pool.ntp.org');
```

## PTP (Precision Time Protocol)

Probe a PTP grandmaster clock for synchronization information:

```sql
-- Probe default PTP port (319)
SELECT ptp_probe('ptp.example.com');

-- Probe a specific port
SELECT ptp_probe('ptp.example.com', 319);
```

## Practical Examples

```sql
-- Compare time from multiple NTP servers
SELECT
    'pool.ntp.org' AS server, ntp_query('pool.ntp.org') AS result
UNION ALL
SELECT
    'time.google.com', ntp_query('time.google.com');

-- Check clock drift
SELECT ntp_query('pool.ntp.org');
```

## Security Considerations

- NTP transmit timestamps use cryptographic randomness to prevent spoofing.
- NTP/PTP server hostnames are validated against [SSRF rules](../security/ssrf.md).
- These functions are read-only queries and do not modify system time.
