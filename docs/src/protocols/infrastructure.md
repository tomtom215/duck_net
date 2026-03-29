# Infrastructure (SNMP / Syslog / IPMI / RADIUS)

duck_net provides functions for infrastructure management protocols commonly used in network operations and data center environments.

## Functions

### SNMP

| Function | Parameters | Returns |
|----------|-----------|---------|
| `snmp_get` | `(host, community, oid)` | VARCHAR (value) |
| `snmp_walk` | `(host, community, oid)` with named params | Table: oid, value |
| `snmp_get_secret` | `(secret_name, host, oid)` | VARCHAR (value) |

### Syslog

| Function | Parameters | Returns |
|----------|-----------|---------|
| `syslog_send` | `(host, facility, severity, message)` | VARCHAR (status) |
| `syslog_send` | `(host, port, facility, severity, hostname, app_name, message)` | VARCHAR (status) |

### IPMI

| Function | Parameters | Returns |
|----------|-----------|---------|
| `ipmi_device_id` | `(host)` | VARCHAR (JSON device info) |
| `ipmi_chassis_status` | `(host)` | VARCHAR (JSON chassis status) |
| `ipmi_chassis_control` | `(host, command)` | VARCHAR (status) |

### RADIUS

| Function | Parameters | Returns |
|----------|-----------|---------|
| `radius_auth` | `(host, secret, username, password)` | VARCHAR (result) |
| `radius_auth` | `(host, port, secret, username, password)` | VARCHAR (result) |
| `radius_auth_secret` | `(secret_name, host, username, password)` | VARCHAR (result) |

## SNMP

```sql
-- Get a single OID value (e.g., system description)
SELECT snmp_get('192.168.1.1', 'public', '1.3.6.1.2.1.1.1.0');

-- Walk an OID subtree
FROM snmp_walk('192.168.1.1', 'public', '1.3.6.1.2.1.1');

-- Walk with entry limit
FROM snmp_walk('192.168.1.1', 'public', '1.3.6.1.2.1.2.2', max_entries := 100);

-- Using secrets
SELECT duck_net_add_secret('switch', 'snmp', '{"community": "private"}');
SELECT snmp_get_secret('switch', '192.168.1.1', '1.3.6.1.2.1.1.1.0');
```

## Syslog

```sql
-- Send a simple syslog message (UDP, RFC 3164)
SELECT syslog_send('syslog.example.com', 'local0', 'info', 'Database backup completed');

-- Send with full RFC 5424 parameters
SELECT syslog_send(
    'syslog.example.com', 514,
    'local0', 'warning',
    'db-server-01', 'backup-agent',
    'Backup took longer than expected: 45 minutes'
);
```

## IPMI

```sql
-- Get device identification
SELECT ipmi_device_id('192.168.1.100');

-- Check chassis power status
SELECT ipmi_chassis_status('192.168.1.100');

-- Power control (power_on, power_off, power_cycle, hard_reset)
SELECT ipmi_chassis_control('192.168.1.100', 'power_cycle');
```

## RADIUS

```sql
-- Authenticate a user against a RADIUS server
SELECT radius_auth('radius.example.com', 'shared-secret', 'alice', 'password123');

-- With explicit port
SELECT radius_auth('radius.example.com', 1812, 'shared-secret', 'alice', 'password123');

-- Using secrets
SELECT duck_net_add_secret('radius', 'radius', '{"shared_secret": "my-secret"}');
SELECT radius_auth_secret('radius', 'radius.example.com', 'alice', 'password123');
```

## Security Considerations

- SNMP community strings are credentials; use the [secrets manager](../security/secrets.md) with the `snmp` type.
- RADIUS authenticators use cryptographic randomness (16 bytes from OS CSPRNG).
- RADIUS shared secrets should never be hardcoded; use the `radius` [secret type](../security/secrets.md).
- Syslog over UDP is unencrypted; consider network-level controls.
- IPMI is inherently insecure over the network; restrict access by firewall.
- All infrastructure hostnames pass through [SSRF validation](../security/ssrf.md).
