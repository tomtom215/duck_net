# Retries & Timeouts

duck_net provides configurable retry logic with exponential backoff and request timeouts for all network operations.

## Functions

| Function | Parameters | Returns |
|----------|-----------|---------|
| `duck_net_set_retries` | `(max_retries INTEGER, backoff_ms INTEGER)` | VARCHAR (confirmation) |
| `duck_net_set_timeout` | `(seconds INTEGER)` | VARCHAR (confirmation) |
| `duck_net_set_retry_statuses` | `(statuses VARCHAR)` | VARCHAR (confirmation) |

## Retry Configuration

```sql
-- Enable retries: 3 attempts with 1-second base backoff
SELECT duck_net_set_retries(3, 1000);

-- Disable retries
SELECT duck_net_set_retries(0, 0);
```

Retries use **exponential backoff**: the delay doubles after each attempt. With a base backoff of 1000ms, the delays are approximately 1s, 2s, 4s.

## Retry Status Codes

By default, duck_net retries on status codes 429 (Too Many Requests), 500, 502, 503, and 504. You can customize which status codes trigger a retry:

```sql
-- Only retry on 429 and 503
SELECT duck_net_set_retry_statuses('429,503');

-- Retry on all 5xx errors
SELECT duck_net_set_retry_statuses('500,501,502,503,504');
```

## Timeout Configuration

Set the maximum time (in seconds) to wait for a response:

```sql
-- Set timeout to 60 seconds
SELECT duck_net_set_timeout(60);

-- Set a short timeout for health checks
SELECT duck_net_set_timeout(5);
```

The timeout applies to each individual request attempt, not the total time including retries. The minimum timeout is 1 second.

## Practical Examples

```sql
-- Configure for a flaky API
SELECT duck_net_set_retries(5, 2000);    -- 5 retries, 2s base backoff
SELECT duck_net_set_timeout(30);          -- 30s per attempt
SELECT duck_net_set_retry_statuses('429,500,502,503,504');

-- Then make requests normally
SELECT (http_get('https://api.example.com/data')).body;
```

## Default Values

| Setting | Default |
|---------|---------|
| Max retries | 0 (disabled) |
| Base backoff | 1000 ms |
| Timeout | 30 seconds |
| Retry statuses | 429, 500, 502, 503, 504 |

## Security Considerations

- Retries can amplify requests; combine with [rate limiting](./rate-limiting.md) to avoid overwhelming targets.
- Long timeouts on many concurrent requests can exhaust local resources.
- Exponential backoff helps reduce load on struggling servers.
