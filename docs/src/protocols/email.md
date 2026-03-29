# Email (SMTP / IMAP)

duck_net provides functions for sending email via SMTP and reading/managing email via IMAP.

## Functions

### SMTP (Sending)

| Function | Parameters | Returns |
|----------|-----------|---------|
| `smtp_send` | `(host, from, to, subject, body)` | STRUCT(success BOOLEAN, message VARCHAR) |
| `smtp_send` | `(host, port, username, password, from, to, subject)` | STRUCT(success BOOLEAN, message VARCHAR) |
| `smtp_send_secret` | `(secret_name, from, to, subject, body)` | STRUCT(success BOOLEAN, message VARCHAR) |

### IMAP (Reading)

| Function | Parameters | Returns |
|----------|-----------|---------|
| `imap_list` | `(host, username, password)` with named params | Table: uid, from_addr, to_addr, subject, date, size |
| `imap_fetch` | `(host, username, password, uid)` | STRUCT(success BOOLEAN, body VARCHAR, message VARCHAR) |
| `imap_move` | `(host, username, password, uid, dest_mailbox)` | STRUCT(success BOOLEAN, message VARCHAR) |
| `imap_delete` | `(host, username, password, uid)` | STRUCT(success BOOLEAN, message VARCHAR) |
| `imap_flag` | `(host, username, password, uid, flag)` | STRUCT(success BOOLEAN, message VARCHAR) |

## Sending Email

```sql
-- Simple send (STARTTLS on port 587)
SELECT (smtp_send(
    'smtp.gmail.com',
    'me@gmail.com',
    'recipient@example.com',
    'Hello from DuckDB',
    'This email was sent from a SQL query!'
)).success;

-- With explicit credentials and port
SELECT (smtp_send(
    'smtp.gmail.com', '587',
    'me@gmail.com', 'app-password',
    'me@gmail.com', 'team@example.com',
    'Daily Report'
)).message;

-- Using secrets (recommended)
SELECT duck_net_add_secret('mail', 'smtp',
    '{"host": "smtp.gmail.com", "username": "me@gmail.com", "password": "app-password"}');
SELECT (smtp_send_secret('mail',
    'me@gmail.com', 'team@example.com', 'Report', 'See attached.'
)).success;
```

## Reading Email

```sql
-- List recent messages from INBOX
FROM imap_list('imap.gmail.com', 'me@gmail.com', 'app-password');

-- List from a specific mailbox with search
FROM imap_list('imap.gmail.com', 'me@gmail.com', 'app-password',
    mailbox := 'INBOX', search := 'UNSEEN', limit := 10);

-- Fetch a specific message body by UID
SELECT (imap_fetch('imap.gmail.com', 'me@gmail.com', 'app-password', 12345)).body;
```

## Managing Email

```sql
-- Move a message to another folder
SELECT (imap_move('imap.gmail.com', 'me@gmail.com', 'pass', 12345, 'Archive')).success;

-- Delete a message
SELECT (imap_delete('imap.gmail.com', 'me@gmail.com', 'pass', 12345)).success;

-- Flag a message as seen
SELECT (imap_flag('imap.gmail.com', 'me@gmail.com', 'pass', 12345, '\\Seen')).success;
```

## Security Considerations

- SMTP uses STARTTLS by default; plaintext downgrade is blocked.
- IMAP connections use TLS (port 993). Plaintext IMAP triggers a [security warning](../security/warnings.md).
- CRLF injection in headers and bodies is sanitized (CWE-93).
- IMAP responses are capped at 10 MiB.
- **Never hardcode passwords in SQL.** Use the [secrets manager](../security/secrets.md) with `smtp` or `imap` secret types.
