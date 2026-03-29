# Rate Limiting

duck_net includes a built-in rate limiter to prevent overwhelming target services. Both global and per-domain limits are supported.

## Functions

| Function | Parameters | Returns |
|----------|-----------|---------|
| `duck_net_set_rate_limit` | `(requests_per_second INTEGER)` | VARCHAR (confirmation) |
| `duck_net_set_domain_rate_limits` | `(config VARCHAR)` | VARCHAR (confirmation) |

## Global Rate Limit

Set a maximum number of requests per second across all domains:

```sql
-- Limit to 10 requests per second
SELECT duck_net_set_rate_limit(10);

-- Disable rate limiting
SELECT duck_net_set_rate_limit(0);
```

The rate limiter applies to all outbound network calls (HTTP, gRPC, SMTP, etc.). When the limit is reached, subsequent requests are delayed until a slot becomes available.

## Per-Domain Rate Limits

Apply different rate limits to different domains. The configuration is a comma-separated string of `domain=rps` pairs:

```sql
-- Set per-domain limits
SELECT duck_net_set_domain_rate_limits('api.github.com=5,api.stripe.com=2,*.internal.com=20');
```

Per-domain limits take precedence over the global limit for matching domains.

## Practical Examples

```sql
-- Respect GitHub's rate limits
SELECT duck_net_set_rate_limit(5);

-- Batch process API calls without overwhelming the server
SELECT duck_net_set_rate_limit(10);
SELECT (http_get('https://api.example.com/items/' || id::VARCHAR)).body
FROM generate_series(1, 100) AS t(id);
```

## Default Behavior

Rate limiting is **disabled by default** (0 requests/second = unlimited). It is recommended to enable rate limiting when making bulk API calls or interacting with rate-limited services.

## Security Considerations

- Rate limiting is enforced client-side and does not replace server-side rate limits.
- Setting an appropriate rate limit helps avoid being blocked by target services.
- See the [Retries & Timeouts](./retries.md) page for complementary configuration.
