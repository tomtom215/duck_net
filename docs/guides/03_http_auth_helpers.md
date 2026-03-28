# Implementation Guide: Authentication Helpers

## Goal

Provide convenience functions for common HTTP authentication patterns, reducing boilerplate for API access.

## SQL Interface

```sql
-- Basic Auth: returns base64-encoded Authorization header value
SELECT http_get(
    'https://api.example.com/data',
    MAP{'Authorization': http_basic_auth('username', 'password')}
);

-- Bearer token (convenience — just prepends "Bearer ")
SELECT http_get(
    'https://api.example.com/data',
    MAP{'Authorization': http_bearer_auth('my-token-123')}
);

-- OAuth2 Client Credentials: fetches an access token from a token endpoint
SELECT http_get(
    'https://api.example.com/data',
    MAP{'Authorization': http_oauth2_token(
        'https://auth.example.com/oauth/token',
        'client_id_here',
        'client_secret_here'
    )}
);
```

## Functions

### http_basic_auth(username VARCHAR, password VARCHAR) → VARCHAR

Returns `'Basic <base64(username:password)>'`.

Pure string transformation. No HTTP call. No external dependency — implement base64 encoding manually (it's ~30 lines for the encoding table) or use the `base64` crate (already a transitive dependency via ureq/rustls).

```rust
// base64 is already in our dependency tree via rustls
fn basic_auth(user: &str, pass: &str) -> String {
    use base64::Engine;
    let encoded = base64::engine::general_purpose::STANDARD.encode(format!("{user}:{pass}"));
    format!("Basic {encoded}")
}
```

**Registration**: Simple scalar function via quack-rs `ScalarFunctionBuilder` (no complex types needed).

```rust
ScalarFunctionBuilder::new("http_basic_auth")
    .param(TypeId::Varchar)
    .param(TypeId::Varchar)
    .returns(TypeId::Varchar)
    .function(basic_auth_callback)
```

### http_bearer_auth(token VARCHAR) → VARCHAR

Returns `'Bearer <token>'`.

Trivial string concatenation. Exists purely for readability in SQL.

### http_oauth2_token(token_url VARCHAR, client_id VARCHAR, client_secret VARCHAR) → VARCHAR

Performs an OAuth2 Client Credentials grant:
1. POSTs to `token_url` with `grant_type=client_credentials`, `client_id`, `client_secret`
2. Parses the JSON response to extract `access_token`
3. Returns `'Bearer <access_token>'`

```rust
fn oauth2_token(token_url: &str, client_id: &str, client_secret: &str) -> Result<String, String> {
    let form_body = format!(
        "grant_type=client_credentials&client_id={}&client_secret={}",
        urlencoded(client_id),
        urlencoded(client_secret),
    );

    let resp = http::execute(
        Method::Post,
        token_url,
        &[("Content-Type".into(), "application/x-www-form-urlencoded".into())],
        Some(&form_body),
    );

    if resp.status != 200 {
        return Err(format!("OAuth2 token request failed: {} {}", resp.status, resp.reason));
    }

    // Extract access_token from JSON response
    // Minimal JSON parsing: find "access_token":"<value>"
    extract_json_string(&resp.body, "access_token")
        .map(|token| format!("Bearer {token}"))
        .ok_or_else(|| "No access_token in OAuth2 response".to_string())
}
```

**JSON extraction**: Need minimal JSON string extraction. Same utility as pagination guide's `json_dot_path`. Implement once, share.

**URL encoding**: `percent_encoding` crate is already in the dependency tree (via ureq). Or implement minimal form-encoding for the 3 fields needed.

### Registration

All three are simple `VARCHAR → VARCHAR` scalar functions. Use quack-rs `ScalarFunctionBuilder` — no raw C API needed.

## Dependencies

None new. `base64` and `percent-encoding` are already transitive dependencies via ureq/rustls.

## Estimated Scope

- `http_basic_auth`: ~15 lines
- `http_bearer_auth`: ~10 lines
- `http_oauth2_token`: ~40 lines
- JSON string extractor utility: ~30 lines
- Registration: ~30 lines
- Total: ~125 lines

## Security Considerations

- `http_basic_auth` and `http_oauth2_token` handle credentials. Document that these values appear in query logs and DuckDB's profiling output.
- OAuth2 tokens should not be cached across queries (stale tokens). Each call fetches a fresh token. If this becomes a performance issue, add optional caching with TTL later.
- Do NOT store credentials in DuckDB settings. Always pass them as function parameters so they're scoped to the query.

## Future Extensions

- `http_oauth2_token` with custom scopes: `http_oauth2_token(url, id, secret, 'scope1 scope2')`
- OAuth2 Authorization Code flow (requires redirect handling — complex, probably out of scope)
- API key header helper: `http_api_key('X-API-Key', 'my-key')` → returns a MAP with one entry (requires MAP return type)
- Integration with DuckDB's secrets management (CREATE SECRET) if the C API supports reading secrets
