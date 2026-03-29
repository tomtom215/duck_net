# Quick Start

## HTTP Requests

```sql
-- GET request
SELECT (http_get('https://api.github.com/repos/duckdb/duckdb')).body;

-- POST with JSON body
SELECT (http_post('https://httpbin.org/post', '{"key": "value"}')).body;

-- POST with custom headers
SELECT (http_post(
    'https://api.example.com/data',
    MAP {'Content-Type': 'application/json', 'Authorization': 'Bearer token'},
    '{"key": "value"}'
)).body;

-- Generic request with any method
SELECT (http_request('PATCH', 'https://api.example.com/item/1', MAP {}, '{"status": "done"}')).body;
```

## Authentication

```sql
-- Basic auth header
SELECT http_basic_auth('username', 'password');
-- Returns: "Basic dXNlcm5hbWU6cGFzc3dvcmQ="

-- Bearer token header
SELECT http_bearer_auth('my-token');
-- Returns: "Bearer my-token"

-- OAuth2 Client Credentials
SELECT http_oauth2_token('https://auth.example.com/token', 'client_id', 'client_secret');
-- Returns: "Bearer <access_token>"
```

## Secrets Management

Never hardcode credentials in SQL:

```sql
-- Store credentials securely in memory
SELECT duck_net_add_secret('my_api', 'http', '{"bearer_token": "sk-..."}');

-- Use stored credentials
SELECT (http_get_secret('my_api', 'https://api.example.com/data')).body;

-- View stored secrets (values are redacted)
FROM duck_net_secrets();

-- Clean up
SELECT duck_net_clear_secret('my_api');
```

## Configuration

```sql
-- Set global rate limit
SELECT duck_net_set_rate_limit(10);  -- 10 requests/second

-- Configure retries with exponential backoff
SELECT duck_net_set_retries(3, 1000);  -- 3 retries, 1s base backoff

-- Set request timeout
SELECT duck_net_set_timeout(60);  -- 60 seconds

-- Check current security configuration
SELECT duck_net_security_status();
```

## Security Warnings

duck_net proactively warns about insecure configurations:

```sql
-- View all security warnings from this session
FROM duck_net_security_warnings();

-- Suppress warnings (for CI/testing environments)
SELECT duck_net_set_security_warnings(false);

-- Re-enable warnings
SELECT duck_net_set_security_warnings(true);
```
