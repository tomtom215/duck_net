# WebDAV

duck_net provides WebDAV functions for remote file and directory management over HTTP.

## Functions

| Function | Parameters | Returns |
|----------|-----------|---------|
| `webdav_list` | `(url)` | Table: href, name, content_type, size, last_modified, is_collection |
| `webdav_read` | `(url)` | VARCHAR (file content) |
| `webdav_write` | `(url, content)` | VARCHAR (status message) |
| `webdav_delete` | `(url)` | VARCHAR (status message) |
| `webdav_mkcol` | `(url)` | VARCHAR (status message) |

## Listing Files

The `webdav_list` table function returns directory contents:

```sql
-- List files in a WebDAV directory
FROM webdav_list('https://dav.example.com/files/');
```

Output columns:

| Column | Type | Description |
|--------|------|-------------|
| `href` | VARCHAR | Full resource URL |
| `name` | VARCHAR | File or directory name |
| `content_type` | VARCHAR | MIME type |
| `size` | BIGINT | File size in bytes |
| `last_modified` | VARCHAR | Last modification timestamp |
| `is_collection` | BOOLEAN | `true` for directories |

## Reading Files

```sql
-- Read a file's content
SELECT webdav_read('https://dav.example.com/files/report.txt');
```

## Writing Files

```sql
-- Upload or overwrite a file
SELECT webdav_write('https://dav.example.com/files/report.txt', 'Hello, WebDAV!');
```

## Creating Directories

```sql
-- Create a new collection (directory)
SELECT webdav_mkcol('https://dav.example.com/files/new-folder/');
```

## Deleting Resources

```sql
-- Delete a file or directory
SELECT webdav_delete('https://dav.example.com/files/old-report.txt');
```

## Authenticated Access

Most WebDAV servers require authentication. Use HTTP headers or [secrets](../security/secrets.md):

```sql
-- Using Basic auth with the HTTP secret type
SELECT duck_net_add_secret('dav', 'http', '{"username": "user", "password": "pass"}');
SELECT http_get_secret('dav', 'https://dav.example.com/files/');
```

## Security Considerations

- All WebDAV URLs pass through [SSRF validation](../security/ssrf.md).
- Path traversal sequences (`..`, null bytes) are blocked in resource paths.
- Use HTTPS endpoints to protect credentials and file content in transit.
