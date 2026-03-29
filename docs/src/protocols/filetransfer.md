# File Transfer (FTP / FTPS / SFTP / SCP)

duck_net provides functions for transferring files over FTP, FTPS, and SFTP, plus SCP for SSH-based file copy.

## Functions

### FTP / FTPS

| Function | Parameters | Returns |
|----------|-----------|---------|
| `ftp_read` | `(url)` | STRUCT(success, content, size, message) |
| `ftp_read_blob` | `(url)` | STRUCT(success, data BLOB, size, message) |
| `ftp_write` | `(url, content)` | STRUCT(success, bytes_written, message) |
| `ftp_delete` | `(url)` | STRUCT(success, message) |
| `ftp_list` | `(url)` | Table: name, size, is_dir |

### SFTP

| Function | Parameters | Returns |
|----------|-----------|---------|
| `sftp_read` | `(host, user, key_file, path)` or `(host, port, user, key_file, path)` | STRUCT(success, content, size, message) |
| `sftp_read_blob` | `(host, user, key_file, path)` or `(host, port, user, key_file, path)` | STRUCT(success, data BLOB, size, message) |
| `sftp_write` | `(host, user, key_file, path, content)` | STRUCT(success, bytes_written, message) |
| `sftp_delete` | `(host, user, key_file, path)` | STRUCT(success, message) |
| `sftp_list` | `(host, user, key_file, path)` with named params | Table: name, size, is_dir |

### SCP

| Function | Parameters | Returns |
|----------|-----------|---------|
| `scp_read` | `(host, user, key_file, remote_path)` or with port | STRUCT(success, data, size, message) |
| `scp_read_password` | `(host, user, password, remote_path)` | STRUCT(success, data, size, message) |
| `scp_write` | `(host, user, key_file, remote_path, data)` | STRUCT(success, bytes_written, message) |
| `scp_write_password` | `(host, user, password, remote_path, data)` | STRUCT(success, bytes_written, message) |

## FTP Examples

```sql
-- Read a text file via FTP
SELECT (ftp_read('ftp://ftp.example.com/pub/data.csv')).content;

-- Read binary data
SELECT (ftp_read_blob('ftp://ftp.example.com/pub/image.png')).data;

-- Upload a file
SELECT (ftp_write('ftp://user:pass@ftp.example.com/upload/data.csv', 'col1,col2\n1,2')).success;

-- List directory contents
FROM ftp_list('ftp://ftp.example.com/pub/');

-- Delete a file
SELECT (ftp_delete('ftp://user:pass@ftp.example.com/upload/old.csv')).success;
```

## SFTP Examples

```sql
-- Read a file over SFTP
SELECT (sftp_read('server.example.com', 'deploy', '/home/deploy/.ssh/id_ed25519', '/var/data/report.csv')).content;

-- Read with explicit port
SELECT (sftp_read('server.example.com', 2222, 'deploy', '/home/deploy/.ssh/id_ed25519', '/var/data/report.csv')).content;

-- Write a file
SELECT (sftp_write('server.example.com', 'deploy', '/home/deploy/.ssh/id_ed25519', '/tmp/output.txt', 'Hello!')).success;

-- List remote directory
FROM sftp_list('server.example.com', 'deploy', '/home/deploy/.ssh/id_ed25519', '/var/data/');
```

## SCP Examples

```sql
-- Read via SCP with key
SELECT (scp_read('server.example.com', 'deploy', '/home/deploy/.ssh/id_ed25519', '/etc/hostname')).data;

-- Write via SCP with password
SELECT (scp_write_password('server.example.com', 'admin', 'password', '/tmp/config.txt', 'key=value')).success;
```

## Security Considerations

- Path traversal (`..`, null bytes, excessively long paths) is blocked (CWE-22).
- FTP/SFTP responses are capped at 256 MiB.
- Use FTPS (`ftps://`) or SFTP instead of plaintext FTP where possible.
- SSH host key verification uses TOFU (Trust On First Use) via `known_hosts`.
- Store credentials using the [secrets manager](../security/secrets.md) with `ftp` or `sftp` types.
- All hostnames are validated against [SSRF rules](../security/ssrf.md).
