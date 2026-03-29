# Installation

## From Source

```bash
# Clone the repository
git clone https://github.com/tomtom215/duck_net.git
cd duck_net

# Build the extension
make release

# The extension is built to:
# build/release/extension/duck_net/duck_net.duckdb_extension
```

### Requirements

- Rust 1.85+ (MSRV)
- DuckDB 1.5.1+
- A C compiler (for libduckdb-sys)

## Loading the Extension

```sql
-- Load the extension
LOAD '/path/to/duck_net.duckdb_extension';

-- Verify it loaded
SELECT duck_net_security_status();
```

## Verifying Installation

After loading, you can verify all protocols are available:

```sql
-- Test HTTP
SELECT (http_get('https://httpbin.org/get')).status;
-- Should return: 200

-- Test DNS
SELECT dns_lookup('example.com', 'A');

-- Check security configuration
SELECT duck_net_security_status();

-- List any security warnings
FROM duck_net_security_warnings();
```
