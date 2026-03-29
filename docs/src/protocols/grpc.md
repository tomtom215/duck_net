# gRPC

duck_net supports gRPC unary calls and server reflection for service discovery. Protobuf messages are passed as JSON and automatically encoded/decoded.

## Functions

| Function | Parameters | Returns |
|----------|-----------|---------|
| `grpc_call` | `(url, service, method, json_payload)` | STRUCT(success BOOLEAN, status_code INTEGER, body VARCHAR, grpc_status INTEGER, grpc_message VARCHAR) |
| `grpc_list_services` | `(url)` | STRUCT(success BOOLEAN, services VARCHAR[], message VARCHAR) |

## Unary Calls

Pass the service name, method, and a JSON-encoded request body:

```sql
-- Call a gRPC method
SELECT (grpc_call(
    'https://grpc.example.com:443',
    'myapp.UserService',
    'GetUser',
    '{"user_id": 42}'
)).body;
```

The `body` field contains the JSON-decoded protobuf response. The `grpc_status` field contains the gRPC status code (0 = OK).

```sql
-- Check for errors
SELECT
    r.success,
    r.grpc_status,
    r.grpc_message,
    r.body
FROM (
    SELECT grpc_call(
        'https://grpc.example.com:443',
        'myapp.UserService',
        'GetUser',
        '{"user_id": 42}'
    ) AS r
);
```

## Service Reflection

Discover available services on a gRPC server that has reflection enabled:

```sql
SELECT (grpc_list_services('https://grpc.example.com:443')).services;
```

## Security Considerations

- gRPC endpoints are validated against [SSRF rules](../security/ssrf.md).
- Responses are capped at 16 MiB to prevent memory exhaustion.
- Protobuf deserialization enforces recursion depth limits to prevent stack overflow.
- Use the `grpc` [secret type](../security/secrets.md) for token-based authentication.
- Only TLS (`https://`) connections are supported in production; plaintext triggers a warning.
