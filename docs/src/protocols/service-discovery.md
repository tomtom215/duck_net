# Service Discovery (Consul / etcd / Vault)

duck_net provides functions for interacting with Consul KV, etcd KV, and HashiCorp Vault for secrets management and health checks.

## Functions

### Consul KV

| Function | Parameters | Returns |
|----------|-----------|---------|
| `consul_get` | `(url, key, token)` | VARCHAR (value) |
| `consul_set` | `(url, key, value, token)` | VARCHAR (status) |
| `consul_delete` | `(url, key, token)` | VARCHAR (status) |
| `consul_get_secret` | `(secret_name, url, key)` | VARCHAR (value) |

### etcd

| Function | Parameters | Returns |
|----------|-----------|---------|
| `etcd_get` | `(url, key)` | VARCHAR (value) |
| `etcd_put` | `(url, key, value)` | VARCHAR (status) |

### Vault

| Function | Parameters | Returns |
|----------|-----------|---------|
| `vault_read` | `(url, path, token)` | VARCHAR (JSON secret data) |
| `vault_write` | `(url, path, token, data_json)` | VARCHAR (status) |
| `vault_list` | `(url, path, token)` | VARCHAR (JSON key list) |
| `vault_health` | `(url)` | VARCHAR (JSON health status) |

## Consul KV

```sql
-- Read a value from Consul KV
SELECT consul_get('http://consul:8500', 'config/db/host', 'my-consul-token');

-- Write a value
SELECT consul_set('http://consul:8500', 'config/db/host', 'db.example.com', 'my-consul-token');

-- Delete a key
SELECT consul_delete('http://consul:8500', 'config/db/host', 'my-consul-token');

-- Using secrets
SELECT duck_net_add_secret('consul', 'consul', '{"token": "my-consul-token"}');
SELECT consul_get_secret('consul', 'http://consul:8500', 'config/db/host');
```

## etcd

```sql
-- Read a key from etcd
SELECT etcd_get('http://etcd:2379', '/config/app/version');

-- Write a key
SELECT etcd_put('http://etcd:2379', '/config/app/version', '2.1.0');
```

## Vault Secrets

```sql
-- Read a secret from Vault KV v2
SELECT vault_read('https://vault.example.com:8200', 'secret/data/myapp', 'hvs.EXAMPLE');

-- Write a secret
SELECT vault_write(
    'https://vault.example.com:8200',
    'secret/data/myapp',
    'hvs.EXAMPLE',
    '{"data": {"api_key": "sk-...", "db_password": "secret"}}'
);

-- List secrets at a path
SELECT vault_list('https://vault.example.com:8200', 'secret/metadata/', 'hvs.EXAMPLE');

-- Health check (no auth required)
SELECT vault_health('https://vault.example.com:8200');
```

## Using Vault Secrets

```sql
SELECT duck_net_add_secret('vault', 'vault', '{"token": "hvs.EXAMPLE"}');
```

## Security Considerations

- Use HTTPS for Vault connections; Vault over plaintext triggers a [security warning](../security/warnings.md).
- Vault tokens are sensitive; store them using the [secrets manager](../security/secrets.md) with the `vault` type.
- Consul ACL tokens should follow least-privilege principles.
- All service discovery URLs are validated against [SSRF rules](../security/ssrf.md).
