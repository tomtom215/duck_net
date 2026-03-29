# WebSocket

duck_net provides WebSocket support for request-response style interactions. Send a message, receive a response, and close the connection in a single function call.

## Functions

| Function | Parameters | Returns |
|----------|-----------|---------|
| `ws_request` | `(url, message)` | STRUCT(success BOOLEAN, response VARCHAR, message VARCHAR) |
| `ws_request` | `(url, message, timeout_secs)` | STRUCT(success BOOLEAN, response VARCHAR, message VARCHAR) |
| `ws_multi_request` | `(url, messages, timeout_secs)` | STRUCT(success BOOLEAN, responses VARCHAR, count INTEGER, message VARCHAR) |

## Single Request

```sql
-- Send a message and receive a response
SELECT (ws_request('wss://echo.websocket.org', 'Hello, WebSocket!')).response;

-- With a custom timeout (seconds)
SELECT (ws_request('wss://api.example.com/ws', '{"action": "ping"}', 10)).response;
```

## Multi-Message Request

Send multiple messages in a single connection. Messages are newline-separated:

```sql
SELECT (ws_multi_request(
    'wss://api.example.com/ws',
    '{"action": "subscribe", "channel": "trades"}
{"action": "ping"}',
    5
)).*;
```

The `responses` field contains all received messages joined by newlines, and `count` indicates how many were received.

## Accessing Results

```sql
SELECT
    r.success,
    r.response,
    r.message AS error_message
FROM (
    SELECT ws_request('wss://echo.websocket.org', 'test') AS r
);
```

## Security Considerations

- WebSocket URLs are validated against [SSRF rules](../security/ssrf.md).
- Responses are capped at 16 MiB to prevent memory exhaustion.
- Use `wss://` (TLS) endpoints in production; plaintext `ws://` triggers a [security warning](../security/warnings.md).
- Store tokens using the [secrets manager](../security/secrets.md) with the `websocket` secret type.
