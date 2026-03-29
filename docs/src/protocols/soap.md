# SOAP / XML-RPC / JSON-RPC

duck_net supports SOAP 1.1, SOAP 1.2, XML-RPC, and JSON-RPC protocols for interacting with legacy and modern RPC-style services.

## Functions

| Function | Parameters | Returns |
|----------|-----------|---------|
| `soap_request` | `(url, action, body_xml)` | VARCHAR (full SOAP response) |
| `soap_request` | `(url, action, body_xml, soap_version)` | VARCHAR |
| `soap_request` | `(url, action, body_xml, soap_version, extra_headers_json)` | VARCHAR |
| `soap_extract_body` | `(soap_response)` | VARCHAR (body content) |
| `soap_is_fault` | `(soap_response)` | VARCHAR (`'true'` or `'false'`) |
| `soap_fault_string` | `(soap_response)` | VARCHAR (fault message) |
| `xmlrpc_call` | `(url, method, params_xml)` | VARCHAR (XML-RPC response) |
| `jsonrpc_call` | `(url, method, params_json)` | VARCHAR (JSON-RPC response) |
| `jsonrpc_call` | `(url, method, params_json, headers_json)` | VARCHAR |

## SOAP Requests

```sql
-- SOAP 1.1 request (default)
SELECT soap_request(
    'https://service.example.com/ws',
    'GetUser',
    '<GetUserRequest><UserId>42</UserId></GetUserRequest>'
);

-- SOAP 1.2 with explicit version
SELECT soap_request(
    'https://service.example.com/ws',
    'GetUser',
    '<GetUserRequest><UserId>42</UserId></GetUserRequest>',
    '1.2'
);
```

## Parsing SOAP Responses

```sql
WITH resp AS (
    SELECT soap_request('https://service.example.com/ws', 'GetUser',
        '<GetUserRequest><UserId>42</UserId></GetUserRequest>') AS xml
)
SELECT
    soap_is_fault(xml) AS is_error,
    soap_extract_body(xml) AS body,
    soap_fault_string(xml) AS fault
FROM resp;
```

## XML-RPC

```sql
SELECT xmlrpc_call(
    'https://rpc.example.com/xmlrpc',
    'system.listMethods',
    '<params/>'
);
```

## JSON-RPC

```sql
-- JSON-RPC 2.0 call
SELECT jsonrpc_call(
    'https://rpc.example.com/jsonrpc',
    'eth_blockNumber',
    '[]'
);

-- With custom headers
SELECT jsonrpc_call(
    'https://rpc.example.com/jsonrpc',
    'getBalance',
    '["0xabc...", "latest"]',
    '{"X-API-Key": "my-key"}'
);
```

## Security Considerations

- SOAP action headers are validated for injection characters.
- All endpoints are checked against [SSRF rules](../security/ssrf.md).
- XML parsing is bounded to prevent entity expansion attacks.
- Use [secrets](../security/secrets.md) for service credentials.
