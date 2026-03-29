# DuckDB Native Secrets Integration

duck_net integrates with DuckDB's built-in [Secrets Manager](https://duckdb.org/docs/stable/configuration/secrets_manager) for cloud storage and HTTP protocols.

## When to Use Which

| Use Case | Recommended Approach |
|----------|---------------------|
| S3, GCS, R2, Azure | DuckDB native `CREATE SECRET` |
| HTTP Bearer/Basic auth | DuckDB native `CREATE SECRET (TYPE http)` |
| SMTP, SSH, Redis, LDAP, etc. | duck_net `duck_net_add_secret()` |
| Credentials that must not persist | duck_net in-memory secrets |
| Credentials shared across sessions | DuckDB `CREATE PERSISTENT SECRET` |

## DuckDB Native Secrets

For S3/HTTP/GCS/R2 protocols, prefer DuckDB's native secrets which are managed by the httpfs extension:

```sql
-- S3 credentials
CREATE SECRET my_s3 (
    TYPE s3,
    KEY_ID 'AKIAIOSFODNN7EXAMPLE',
    SECRET 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
    REGION 'us-east-1'
);

-- HTTP authentication
CREATE SECRET my_api (
    TYPE http,
    BEARER_TOKEN 'sk-...'
);

-- Google Cloud Storage (requires HMAC keys)
CREATE SECRET my_gcs (
    TYPE gcs,
    KEY_ID 'GOOG...',
    SECRET 'hmac_secret'
);

-- Cloudflare R2
CREATE SECRET my_r2 (
    TYPE r2,
    KEY_ID 'access_key',
    SECRET 'secret_key',
    ACCOUNT_ID 'account_id'
);
```

## Scoped Secrets

DuckDB supports scoped secrets that apply to specific path prefixes:

```sql
-- Different credentials for different S3 buckets
CREATE SECRET prod_s3 (
    TYPE s3, KEY_ID '...', SECRET '...', SCOPE 's3://prod-bucket'
);
CREATE SECRET staging_s3 (
    TYPE s3, KEY_ID '...', SECRET '...', SCOPE 's3://staging-bucket'
);

-- DuckDB automatically picks the correct secret based on path
SELECT * FROM 's3://prod-bucket/data.parquet';     -- Uses prod_s3
SELECT * FROM 's3://staging-bucket/data.parquet';   -- Uses staging_s3

-- Check which secret applies to a path
FROM which_secret('s3://prod-bucket/file.parquet', 's3');
```

## Persistent Secrets

```sql
-- Persistent secrets survive DuckDB restarts
CREATE PERSISTENT SECRET my_prod_s3 (
    TYPE s3,
    KEY_ID '...',
    SECRET '...',
    REGION 'us-east-1'
);
```

> **Warning**: Persistent secrets are stored in **unencrypted** binary format at `~/.duckdb/stored_secrets/`. For sensitive credentials, prefer duck_net's in-memory secrets which are zeroized on removal and never written to disk.

## Listing and Managing Secrets

```sql
-- List all DuckDB secrets (values are redacted)
FROM duckdb_secrets();

-- Drop a secret
DROP SECRET my_s3;

-- Drop a persistent secret
DROP PERSISTENT SECRET my_prod_s3;
```

## duck_net + DuckDB Secrets

duck_net's S3 functions use the same key names as DuckDB's native S3 secrets (`KEY_ID`, `SECRET`, `REGION`, `ENDPOINT`) so credentials can be managed consistently:

```sql
-- Using duck_net's in-memory secret for S3
SELECT duck_net_add_secret('my_s3', 's3', '{"key_id":"AKIA...","secret":"...","region":"us-east-1"}');
SELECT s3_get_secret('my_s3', 'my-bucket', 'path/to/file.txt');
```
