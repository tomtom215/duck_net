# HTTP / HTTPS

duck_net provides scalar functions for every standard HTTP method, plus multipart uploads and a pagination table function. All requests enforce [SSRF protection](../security/ssrf.md) and [response size limits](../security/architecture.md) (256 MiB).

## Functions

| Function | Parameters | Returns |
|----------|-----------|---------|
| `http_get` | `(url)` or `(url, headers MAP)` | Response STRUCT |
| `http_post` | `(url, body)` or `(url, headers MAP, body)` | Response STRUCT |
| `http_put` | `(url, body)` or `(url, headers MAP, body)` | Response STRUCT |
| `http_patch` | `(url, body)` or `(url, headers MAP, body)` | Response STRUCT |
| `http_delete` | `(url)` or `(url, headers MAP)` | Response STRUCT |
| `http_head` | `(url)` or `(url, headers MAP)` | Response STRUCT |
| `http_options` | `(url)` or `(url, headers MAP)` | Response STRUCT |
| `http_request` | `(method, url, headers MAP, body)` | Response STRUCT |
| `http_post_multipart` | `(url, form MAP, files MAP)` or `(url, headers MAP, form MAP, files MAP)` | Response STRUCT |
| `http_paginate` | `(url)` with named params | Table: page, status, headers, body |

## Response STRUCT

Every HTTP function returns `STRUCT(status INTEGER, reason VARCHAR, headers MAP(VARCHAR, VARCHAR), body VARCHAR)`. Use dotted access to extract fields:

```sql
SELECT (http_get('https://api.example.com/data')).status;
SELECT (http_get('https://api.example.com/data')).body;
```

## GET, DELETE, HEAD, OPTIONS

These methods accept a URL and an optional headers map:

```sql
-- Simple GET
SELECT (http_get('https://api.github.com/repos/duckdb/duckdb')).body;

-- GET with custom headers
SELECT (http_get(
    'https://api.example.com/data',
    MAP {'Authorization': 'Bearer sk-...', 'Accept': 'application/json'}
)).body;

-- HEAD request (returns headers only)
SELECT (http_head('https://example.com')).headers;

-- OPTIONS request (CORS preflight)
SELECT (http_options('https://api.example.com/')).headers;
```

## POST, PUT, PATCH

These methods require a body and accept an optional headers map:

```sql
-- POST with JSON body
SELECT (http_post('https://httpbin.org/post', '{"key": "value"}')).body;

-- PUT with headers
SELECT (http_put(
    'https://api.example.com/item/1',
    MAP {'Content-Type': 'application/json'},
    '{"name": "updated"}'
)).body;

-- PATCH
SELECT (http_patch(
    'https://api.example.com/item/1',
    MAP {'Content-Type': 'application/json'},
    '{"status": "done"}'
)).body;
```

## Generic Request

Use `http_request` for any HTTP method:

```sql
SELECT (http_request('PATCH', 'https://api.example.com/item/1', MAP {}, '{"done": true}')).body;
```

## Multipart Uploads

Upload files with form fields using `http_post_multipart`. The `files MAP` maps field names to file paths on disk:

```sql
SELECT (http_post_multipart(
    'https://api.example.com/upload',
    MAP {'description': 'My file'},   -- form fields
    MAP {'file': '/path/to/data.csv'}  -- file fields
)).body;
```

## Pagination Table Function

`http_paginate` iterates through paginated APIs and returns one row per page:

```sql
-- Page-number pagination
FROM http_paginate('https://api.example.com/items', page_param := 'page', max_pages := 5);

-- Cursor/next-URL pagination (follows JSON pointer or Link header)
FROM http_paginate('https://api.example.com/items', next_url_path := '$.next');
```

| Named Parameter | Type | Default | Description |
|----------------|------|---------|-------------|
| `page_param` | VARCHAR | `'page'` | Query parameter name for page number |
| `start_page` | BIGINT | `1` | First page number |
| `max_pages` | BIGINT | `100` | Maximum pages to fetch |
| `next_url_path` | VARCHAR | — | JSON path to next page URL (enables cursor mode) |

## Security Considerations

- All URLs are validated against [SSRF rules](../security/ssrf.md) before connection.
- Use [secrets](../security/secrets.md) instead of hardcoding credentials in SQL.
- Responses are capped at 256 MiB to prevent memory exhaustion.
- Pagination URLs are re-validated for scheme and SSRF on every page.
- TLS is enforced via rustls with no fallback to plaintext.

See [Authentication Helpers](../configuration/auth.md) for `http_basic_auth`, `http_bearer_auth`, and `http_oauth2_token`.
