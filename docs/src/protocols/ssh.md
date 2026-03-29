# SSH Remote Execution

duck_net provides SSH functions for executing commands on remote servers and transferring files via SCP.

## Functions

| Function | Parameters | Returns |
|----------|-----------|---------|
| `ssh_exec` | `(host, user, key_file, command)` | STRUCT(success BOOLEAN, exit_code INTEGER, stdout VARCHAR, stderr VARCHAR) |
| `ssh_exec` | `(host, port, user, key_file, command)` | STRUCT(success, exit_code, stdout, stderr) |
| `ssh_exec_password` | `(host, user, password, command)` | STRUCT(success, exit_code, stdout, stderr) |
| `ssh_exec_secret` | `(secret_name, hostname, command)` | STRUCT(success, exit_code, stdout, stderr) |

For SCP file transfer functions, see [File Transfer](./filetransfer.md).

## Key-Based Authentication

```sql
-- Execute a command with SSH key
SELECT (ssh_exec(
    'server.example.com',
    'deploy',
    '/home/user/.ssh/id_ed25519',
    'uptime'
)).stdout;

-- With explicit port
SELECT (ssh_exec(
    'server.example.com', 2222,
    'deploy',
    '/home/user/.ssh/id_ed25519',
    'df -h'
)).stdout;
```

## Password Authentication

```sql
SELECT (ssh_exec_password(
    'server.example.com',
    'admin',
    'password123',
    'whoami'
)).stdout;
```

## Using Secrets

```sql
-- Store SSH credentials
SELECT duck_net_add_secret('prod', 'ssh', '{"key_file": "/home/user/.ssh/id_ed25519", "username": "deploy"}');

-- Execute using stored credentials
SELECT (ssh_exec_secret('prod', 'server.example.com', 'uptime')).stdout;
```

## Working with Results

```sql
-- Check exit code and capture both stdout and stderr
SELECT
    r.success,
    r.exit_code,
    r.stdout,
    r.stderr
FROM (
    SELECT ssh_exec('server.example.com', 'deploy', '/path/to/key', 'ls /nonexistent') AS r
);
```

## Practical Examples

```sql
-- Run a deploy script
SELECT (ssh_exec_secret('prod', 'deploy.example.com', '/opt/deploy/run.sh')).exit_code;

-- Gather system info from multiple servers
SELECT
    host,
    (ssh_exec_secret('prod', host, 'uname -r')).stdout AS kernel
FROM (VALUES ('web1.example.com'), ('web2.example.com'), ('db1.example.com')) AS t(host);
```

## Security Considerations

- **Command injection protection**: Shell metacharacters are validated (CWE-78). Commands containing dangerous characters are rejected.
- SSH host keys are verified via `known_hosts` (Trust On First Use model).
- Command output is capped at 64 MiB.
- **Never embed passwords in SQL queries.** Use the [secrets manager](../security/secrets.md) with the `ssh` type or key-based authentication.
- All hostnames pass through [SSRF validation](../security/ssrf.md).
