# OData

duck_net supports OData v4 queries with automatic pagination through a scalar function and a table function.

## Functions

| Function | Parameters | Returns |
|----------|-----------|---------|
| `odata_query` | `(url)` | VARCHAR (JSON response) |
| `odata_paginate` | `(url)` with named params | Table: page, status, headers, body |

## Single Query

```sql
-- Basic OData query
SELECT odata_query('https://services.odata.org/V4/Northwind/Northwind.svc/Products');
```

## Paginated Queries

The `odata_paginate` table function follows OData `@odata.nextLink` automatically:

```sql
-- Paginate through all products
FROM odata_paginate('https://services.odata.org/V4/Northwind/Northwind.svc/Products');

-- With OData query options
FROM odata_paginate(
    'https://services.odata.org/V4/Northwind/Northwind.svc/Products',
    filter := 'Price gt 20',
    select := 'ProductName,Price',
    orderby := 'Price desc',
    top := 50,
    max_pages := 10
);

-- With $expand for related entities
FROM odata_paginate(
    'https://services.odata.org/V4/Northwind/Northwind.svc/Orders',
    expand := 'Customer',
    top := 25
);
```

| Named Parameter | Type | Default | Description |
|----------------|------|---------|-------------|
| `filter` | VARCHAR | — | OData `$filter` expression |
| `select` | VARCHAR | — | OData `$select` fields |
| `orderby` | VARCHAR | — | OData `$orderby` clause |
| `expand` | VARCHAR | — | OData `$expand` for related entities |
| `top` | BIGINT | — | OData `$top` page size |
| `max_pages` | BIGINT | `100` | Maximum number of pages to fetch |

## Working with Results

Each row contains one page of results. Use DuckDB JSON functions to extract entities:

```sql
SELECT json_extract(body, '$.value') AS entities
FROM odata_paginate(
    'https://api.example.com/odata/Users',
    select := 'Id,Name,Email',
    top := 100,
    max_pages := 5
);
```

## Security Considerations

- OData URLs are validated against [SSRF rules](../security/ssrf.md) on every page.
- Pagination follow URLs are re-checked for scheme and host safety.
- Use [authentication helpers](../configuration/auth.md) for secured OData endpoints.
