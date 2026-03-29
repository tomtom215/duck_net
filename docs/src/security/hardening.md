# Hardening Guide

This guide covers best practices for deploying duck_net securely in production environments.

## Checklist

- [ ] SSRF protection is enabled (default)
- [ ] SSH strict mode is enabled (default)
- [ ] All secrets use `duck_net_add_secret()` instead of inline credentials
- [ ] TLS variants used for all protocols (ftps://, ldaps://, imaps://, etc.)
- [ ] Security warnings reviewed: `FROM duck_net_security_warnings();`
- [ ] Rate limiting configured for external APIs
- [ ] Timeouts configured appropriately

## Protocol-Specific Hardening

### HTTP / HTTPS
- Always use `https://` for production endpoints
- Use `duck_net_set_timeout()` to prevent hanging connections
- Configure retries with `duck_net_set_retries()` for resilience
- Use rate limiting: `duck_net_set_rate_limit()` and `duck_net_set_domain_rate_limits()`

### SSH
- Keep strict mode enabled: `SELECT duck_net_set_ssh_strict(true);`
- Pre-populate `~/.ssh/known_hosts` to avoid TOFU vulnerabilities
- Use key-based authentication over password authentication
- Use the secret-aware `ssh_exec_secret()` to avoid credentials in queries

### Email (SMTP / IMAP)
- Always use `smtps://` or STARTTLS (enforced by duck_net)
- Always use `imaps://` for IMAP connections
- Store credentials with `duck_net_add_secret()` of type `smtp` or `imap`

### Redis
- Use `rediss://` (Redis over TLS) in production
- Always set a password: `redis://password@host:6379`
- Store credentials with `duck_net_add_secret()` of type `redis`

### LDAP
- Always use `ldaps://` in production
- Bind with a dedicated service account, not admin credentials
- Use the secret-aware `ldap_search_secret()` function

### S3 / Cloud Storage
- Prefer DuckDB's native `CREATE SECRET (TYPE s3)` for S3 credentials
- Use scoped secrets for multi-account environments
- Enable SSE-KMS via the `KMS_KEY_ID` option for server-side encryption

### Messaging (MQTT, Kafka, AMQP, NATS)
- Use TLS variants: `mqtts://`, `amqps://`, `nats+tls://`
- Configure authentication for all messaging brokers
- Kafka: Use a dedicated Kafka extension with SASL/TLS for production

### Infrastructure (SNMP, Syslog, IPMI)
- SNMP: SNMPv2c community strings are sent in plaintext; use for read-only monitoring only
- Syslog: UDP syslog has no encryption; route through a TLS-capable syslog relay
- IPMI: v1.5 has no authentication; restrict network access to BMC interfaces

### Memcached
- Memcached has **no built-in authentication**; only deploy on trusted networks
- Consider using Redis with auth as an alternative

## Network Segmentation

For maximum security, deploy duck_net in an environment where:
1. SSRF protection remains enabled (blocks private IPs)
2. Outbound network access is restricted to known endpoints
3. DNS resolution is controlled (prevents DNS rebinding)
4. Monitoring tracks unusual protocol usage patterns
