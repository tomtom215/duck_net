# GraphQL

duck_net provides functions for executing GraphQL queries and mutations over HTTP, with helpers for error inspection.

## Functions

| Function | Parameters | Returns |
|----------|-----------|---------|
| `graphql_query` | `(url, query)` | VARCHAR (JSON response) |
| `graphql_query` | `(url, query, variables_json)` | VARCHAR (JSON response) |
| `graphql_query` | `(url, query, variables_json, headers_json)` | VARCHAR (JSON response) |
| `graphql_has_errors` | `(json_response)` | VARCHAR (`'true'` or `'false'`) |
| `graphql_extract_errors` | `(json_response)` | VARCHAR (error messages) |

## Basic Query

```sql
-- Simple query
SELECT graphql_query(
    'https://api.example.com/graphql',
    '{ users { id name email } }'
);

-- Query with variables
SELECT graphql_query(
    'https://api.example.com/graphql',
    'query($id: ID!) { user(id: $id) { name email } }',
    '{"id": "42"}'
);

-- Query with variables and custom headers
SELECT graphql_query(
    'https://api.example.com/graphql',
    '{ viewer { login } }',
    '{}',
    '{"Authorization": "Bearer ghp_..."}'
);
```

## Mutations

GraphQL mutations use the same `graphql_query` function:

```sql
SELECT graphql_query(
    'https://api.example.com/graphql',
    'mutation($input: CreateUserInput!) { createUser(input: $input) { id } }',
    '{"input": {"name": "Alice", "email": "alice@example.com"}}'
);
```

## Error Handling

Check for GraphQL-level errors in the response:

```sql
WITH resp AS (
    SELECT graphql_query('https://api.example.com/graphql', '{ invalid }') AS body
)
SELECT
    graphql_has_errors(body) AS has_errors,
    graphql_extract_errors(body) AS error_messages
FROM resp;
```

## Working with Results

Combine with DuckDB's JSON functions to extract data:

```sql
SELECT json_extract_string(
    graphql_query('https://api.example.com/graphql', '{ users { id name } }'),
    '$.data.users'
) AS users_json;
```

## Security Considerations

- All requests go through [SSRF protection](../security/ssrf.md).
- Use [secrets](../security/secrets.md) to store API tokens rather than embedding them in queries.
- GraphQL introspection queries are permitted but may expose schema details; use authorization headers to control access.
