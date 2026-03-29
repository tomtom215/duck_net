# LDAP

duck_net provides LDAP functions for searching directories, binding (authentication), and write operations (add, modify, delete).

## Functions

| Function | Parameters | Returns |
|----------|-----------|---------|
| `ldap_search` | `(url, base_dn, filter, attributes)` | Table: dn, attribute, value |
| `ldap_bind` | `(url, bind_dn, password)` | STRUCT(success BOOLEAN, message VARCHAR) |
| `ldap_add` | `(url, bind_dn, password, entry_dn, attributes_json)` | STRUCT(success, message) |
| `ldap_modify` | `(url, bind_dn, password, entry_dn, modifications_json)` | STRUCT(success, message) |
| `ldap_delete` | `(url, bind_dn, password, entry_dn)` | STRUCT(success, message) |
| `ldap_search_secret` | `(secret_name, url, base_dn, filter, attributes)` | Table: dn, attribute, value |

## Searching

```sql
-- Search for all users
FROM ldap_search(
    'ldaps://ldap.example.com',
    'dc=example,dc=com',
    '(objectClass=person)',
    'cn,mail,uid'
);

-- Search with a specific filter
FROM ldap_search(
    'ldaps://ldap.example.com',
    'ou=Engineering,dc=example,dc=com',
    '(&(objectClass=person)(mail=*@example.com))',
    'cn,mail'
);
```

## Authentication (Bind)

Test whether credentials are valid:

```sql
SELECT (ldap_bind(
    'ldaps://ldap.example.com',
    'cn=admin,dc=example,dc=com',
    'admin-password'
)).success;
```

## Write Operations

```sql
-- Add a new entry
SELECT (ldap_add(
    'ldaps://ldap.example.com',
    'cn=admin,dc=example,dc=com', 'admin-pass',
    'cn=alice,ou=Users,dc=example,dc=com',
    '{"objectClass": ["person", "inetOrgPerson"], "cn": "alice", "sn": "Smith", "mail": "alice@example.com"}'
)).success;

-- Modify an existing entry
SELECT (ldap_modify(
    'ldaps://ldap.example.com',
    'cn=admin,dc=example,dc=com', 'admin-pass',
    'cn=alice,ou=Users,dc=example,dc=com',
    '{"replace": {"mail": "alice.smith@example.com"}}'
)).success;

-- Delete an entry
SELECT (ldap_delete(
    'ldaps://ldap.example.com',
    'cn=admin,dc=example,dc=com', 'admin-pass',
    'cn=alice,ou=Users,dc=example,dc=com'
)).success;
```

## Using Secrets

```sql
SELECT duck_net_add_secret('corp_ldap', 'ldap',
    '{"username": "cn=admin,dc=example,dc=com", "password": "admin-pass"}');

FROM ldap_search_secret('corp_ldap',
    'ldaps://ldap.example.com', 'dc=example,dc=com', '(cn=*)', 'cn,mail');
```

## Security Considerations

- LDAP filter injection is prevented via RFC 4515 escaping (CWE-90).
- Always use `ldaps://` (LDAP over TLS). Plaintext `ldap://` triggers a [security warning](../security/warnings.md).
- Store bind credentials using the [secrets manager](../security/secrets.md) with the `ldap` type.
- All LDAP hostnames are validated against [SSRF rules](../security/ssrf.md).
