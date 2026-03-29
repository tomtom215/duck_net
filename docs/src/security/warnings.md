# Security Warnings

duck_net proactively warns about potentially insecure configurations. Warnings are informational — they **never block operations** — ensuring CI pipelines, airgapped systems, and development environments continue to work.

## Viewing Warnings

```sql
-- View all warnings from the current session
FROM duck_net_security_warnings();

-- Returns: code, severity, cwe, protocol, message
```

## Warning Codes

| Code | Severity | Protocol | Description |
|------|----------|----------|-------------|
| `PLAINTEXT_MQTT` | HIGH | MQTT | Plaintext MQTT connection (use mqtts://) |
| `PLAINTEXT_REDIS` | HIGH | Redis | Plaintext Redis connection (use rediss://) |
| `PLAINTEXT_FTP` | HIGH | FTP | Plaintext FTP connection (use ftps://) |
| `PLAINTEXT_LDAP` | HIGH | LDAP | Plaintext LDAP connection (use ldaps://) |
| `PLAINTEXT_AMQP` | HIGH | AMQP | Plaintext AMQP connection (use amqps://) |
| `PLAINTEXT_KAFKA` | HIGH | Kafka | Plaintext Kafka connection |
| `PLAINTEXT_NATS` | HIGH | NATS | Plaintext NATS connection (use nats+tls://) |
| `PLAINTEXT_WEBSOCKET` | HIGH | WebSocket | Plaintext WebSocket (use wss://) |
| `PLAINTEXT_ZEROMQ` | HIGH | ZeroMQ | NULL security mechanism (no encryption) |
| `PLAINTEXT_SYSLOG` | HIGH | Syslog | UDP plaintext syslog |
| `NO_AUTH_MEMCACHED` | HIGH | Memcached | No built-in authentication |
| `TOKEN_OVER_HTTP_CONSUL` | CRITICAL | Consul | Auth token sent over plaintext HTTP |
| `TOKEN_OVER_HTTP_VAULT` | CRITICAL | Vault | Auth token sent over plaintext HTTP |
| `SNMPV2C_WEAK_AUTH` | MEDIUM | SNMP | SNMPv2c plaintext community strings |
| `IPMI_V15_NO_AUTH` | MEDIUM | IPMI | IPMI v1.5 with no authentication |
| `TOFU_SSH` | MEDIUM | SSH | Trust-On-First-Use host key verification |
| `PERSISTENT_SECRET_UNENCRYPTED` | MEDIUM | Secrets | DuckDB persistent secrets stored unencrypted |

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
