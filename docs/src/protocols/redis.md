# Redis

duck_net provides Redis functions for key-value operations, key listing, expiration, and hash field access.

## Functions

| Function | Parameters | Returns |
|----------|-----------|---------|
| `redis_get` | `(url, key)` | STRUCT(success BOOLEAN, value VARCHAR) |
| `redis_set` | `(url, key, value)` | STRUCT(success, value) |
| `redis_set` | `(url, key, value, ttl_secs)` | STRUCT(success, value) |
| `redis_del` | `(url, key)` | STRUCT(success, value) |
| `redis_keys` | `(url, pattern)` | STRUCT(success BOOLEAN, keys VARCHAR[], message VARCHAR) |
| `redis_expire` | `(url, key, ttl_secs)` | STRUCT(success, value) |
| `redis_hget` | `(url, key, field)` | STRUCT(success, value) |
| `redis_hset` | `(url, key, field, value)` | STRUCT(success, value) |
| `redis_get_secret` | `(secret_name, key)` | STRUCT(success, value) |
| `redis_set_secret` | `(secret_name, key, value)` | STRUCT(success, value) |

## Basic Operations

```sql
-- Set a value
SELECT (redis_set('redis://localhost:6379', 'greeting', 'Hello!')).success;

-- Set with TTL (expires in 300 seconds)
SELECT (redis_set('redis://localhost:6379', 'session:abc', 'data', 300)).success;

-- Get a value
SELECT (redis_get('redis://localhost:6379', 'greeting')).value;

-- Delete a key
SELECT (redis_del('redis://localhost:6379', 'greeting')).success;

-- Set expiration on an existing key
SELECT (redis_expire('redis://localhost:6379', 'session:abc', 600)).success;
```

## Key Listing

```sql
-- List keys matching a pattern
SELECT (redis_keys('redis://localhost:6379', 'session:*')).keys;

-- List all keys (use with caution on large databases)
SELECT (redis_keys('redis://localhost:6379', '*')).keys;
```

## Hash Operations

```sql
-- Set a hash field
SELECT (redis_hset('redis://localhost:6379', 'user:42', 'name', 'Alice')).success;

-- Get a hash field
SELECT (redis_hget('redis://localhost:6379', 'user:42', 'name')).value;
```

## Using Secrets

```sql
-- Store Redis credentials
SELECT duck_net_add_secret('cache', 'redis',
    '{"host": "redis.example.com", "port": "6380", "password": "secret"}');

-- Use the secret
SELECT (redis_get_secret('cache', 'my_key')).value;
SELECT (redis_set_secret('cache', 'my_key', 'my_value')).success;
```

## Security Considerations

- Redis response parsing enforces recursion depth limits to prevent stack overflow.
- Responses are capped at 16 MiB.
- Use `rediss://` (Redis over TLS) for encrypted connections. Plaintext triggers a [security warning](../security/warnings.md).
- Store passwords using the [secrets manager](../security/secrets.md) with the `redis` type.
- Redis hostnames are checked against [SSRF rules](../security/ssrf.md).
