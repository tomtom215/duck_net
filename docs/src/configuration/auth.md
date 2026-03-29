# Authentication Helpers

duck_net provides scalar functions for generating authentication headers. These are convenience wrappers that return header values for use with HTTP functions.

## Functions

| Function | Parameters | Returns |
|----------|-----------|---------|
| `http_basic_auth` | `(username, password)` | VARCHAR (`"Basic <base64>"`) |
| `http_bearer_auth` | `(token)` | VARCHAR (`"Bearer <token>"`) |
| `http_oauth2_token` | `(token_url, client_id, client_secret)` | VARCHAR (`"Bearer <access_token>"`) |
| `http_oauth2_token` | `(token_url, client_id, client_secret, scope)` | VARCHAR (`"Bearer <access_token>"`) |

## Basic Authentication

Generate a `Basic` auth header from a username and password:

```sql
SELECT http_basic_auth('username', 'password');
-- Returns: "Basic dXNlcm5hbWU6cGFzc3dvcmQ="

-- Use with an HTTP request
SELECT (http_get(
    'https://api.example.com/data',
    MAP {'Authorization': http_basic_auth('user', 'pass')}
)).body;
```

## Bearer Token

Generate a `Bearer` auth header from a token:

```sql
SELECT http_bearer_auth('sk-my-api-key');
-- Returns: "Bearer sk-my-api-key"

-- Use with an HTTP request
SELECT (http_get(
    'https://api.example.com/data',
    MAP {'Authorization': http_bearer_auth('sk-my-api-key')}
)).body;
```

## OAuth2 Client Credentials

Perform an OAuth2 Client Credentials grant to obtain an access token:

```sql
-- Basic client credentials flow
SELECT http_oauth2_token(
    'https://auth.example.com/oauth/token',
    'my-client-id',
    'my-client-secret'
);
-- Returns: "Bearer <access_token>"

-- With scope
SELECT http_oauth2_token(
    'https://auth.example.com/oauth/token',
    'my-client-id',
    'my-client-secret',
    'read:data write:data'
);
```

Use the result directly in an HTTP request:

```sql
SELECT (http_get(
    'https://api.example.com/protected',
    MAP {'Authorization': http_oauth2_token(
        'https://auth.example.com/oauth/token',
        'my-client-id', 'my-client-secret'
    )}
)).body;
```

## Using Secrets Instead

For repeated use, store credentials in the [secrets manager](../security/secrets.md) rather than calling auth helpers with inline credentials:

```sql
-- Store credentials once
SELECT duck_net_add_secret('my_api', 'http', '{"bearer_token": "sk-my-api-key"}');

-- Use the secret-aware function
SELECT (http_get_secret('my_api', 'https://api.example.com/data')).body;
```

## Security Considerations

- **Never hardcode credentials in SQL scripts that are committed to version control.**
- Auth helpers evaluate inline, so credentials may appear in query logs. Prefer the [secrets manager](../security/secrets.md) for sensitive tokens.
- OAuth2 token requests go through [SSRF validation](../security/ssrf.md).
- Basic auth sends credentials base64-encoded (not encrypted). Always use HTTPS.
