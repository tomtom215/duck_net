# Security Warnings

duck_net proactively warns about potentially insecure configurations. Warnings are informational -- they **never block operations** -- ensuring CI pipelines, airgapped systems, and development environments continue to work.

## Viewing Warnings

```sql
-- View all warnings from the current session
FROM duck_net_security_warnings();

-- Returns: code, severity, cwe, protocol, message
```

## Warning Codes

### CRITICAL Severity

| Code | Protocol | Description |
|------|----------|-------------|
| `TOKEN_OVER_HTTP_CONSUL` | Consul | Auth token sent over plaintext HTTP |
| `TOKEN_OVER_HTTP_VAULT` | Vault | Auth token sent over plaintext HTTP |
| `TOKEN_OVER_HTTP_INFLUXDB` | InfluxDB | Auth token sent over plaintext HTTP |
| `TOKEN_OVER_HTTP_ES` | Elasticsearch | Auth token sent over plaintext HTTP |

### HIGH Severity

| Code | Protocol | Description |
|------|----------|-------------|
| `PLAINTEXT_MQTT` | MQTT | Plaintext MQTT connection (use `mqtts://`) |
| `PLAINTEXT_REDIS` | Redis | Plaintext Redis connection (use `rediss://`) |
| `PLAINTEXT_FTP` | FTP | Plaintext FTP connection (use `ftps://`) |
| `PLAINTEXT_LDAP` | LDAP | Plaintext LDAP connection (use `ldaps://`) |
| `PLAINTEXT_LDAP_BIND` | LDAP | Credentials sent over plaintext LDAP bind |
| `PLAINTEXT_IMAP` | IMAP | Plaintext IMAP connection (use `imaps://`) |
| `PLAINTEXT_AMQP` | AMQP | Plaintext AMQP connection (use `amqps://`) |
| `PLAINTEXT_KAFKA` | Kafka | Plaintext Kafka connection |
| `PLAINTEXT_NATS` | NATS | Plaintext NATS connection (use `nats+tls://`) |
| `PLAINTEXT_WEBSOCKET` | WebSocket | Plaintext WebSocket (use `wss://`) |
| `PLAINTEXT_ZEROMQ` | ZeroMQ | NULL security mechanism (no encryption) |
| `PLAINTEXT_SYSLOG` | Syslog | UDP plaintext syslog |
| `NO_AUTH_MEMCACHED` | Memcached | No built-in authentication |
| `NO_AUTH_ZEROMQ` | ZeroMQ | No built-in authentication |

### MEDIUM Severity

| Code | Protocol | Description |
|------|----------|-------------|
| `SNMPV2C_WEAK_AUTH` | SNMP | SNMPv2c plaintext community strings |
| `IPMI_V15_NO_AUTH` | IPMI | IPMI v1.5 with no authentication |
| `TOFU_SSH` | SSH | Trust-On-First-Use host key verification |
| `PERSISTENT_SECRET_UNENCRYPTED` | Secrets | DuckDB persistent secrets stored unencrypted |

## Suppressing Warnings

For CI pipelines or environments where warnings are not actionable:

```sql
-- Suppress all security warnings
SELECT duck_net_set_security_warnings(false);

-- Re-enable (recommended for production)
SELECT duck_net_set_security_warnings(true);

-- Clear accumulated warnings
SELECT duck_net_clear_security_warnings();
```

## Warning Properties

- **Deduplicated**: Each warning code is emitted only once per session
- **Non-blocking**: Warnings never prevent operations from completing
- **Auditable**: All warnings can be queried via the table function
- **Suppressible**: Global toggle for environments where warnings are not needed

## Using Warnings in Production

Best practice is to review warnings after each session:

```sql
-- Check for any warnings after your workflow
FROM duck_net_security_warnings();

-- Check complete security posture
SELECT duck_net_security_status();
```

Address all `CRITICAL` warnings before deploying to production. `HIGH` warnings should be reviewed and either mitigated (by switching to TLS) or accepted with documented justification.
