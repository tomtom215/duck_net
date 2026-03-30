# OData

duck_net supports OData queries with automatic pagination through a scalar function and a table function. Both OData v4 (`@odata.nextLink`) and OData v2 JSON (`__next`) pagination formats are supported.

## Functions

| Function | Parameters | Returns |
|----------|-----------|---------|
| `odata_query` | `(url, headers MAP)` | STRUCT (status, reason, headers, body) |
| `odata_paginate` | `(url)` with named params | Table: page, status, headers, body |
| `odata_extract_count` | `(body VARCHAR)` | BIGINT or NULL |
| `odata_metadata` | `(url, authorization :=)` | Table: entity_set, entity_type, property_name, property_type, nullable, is_key, is_navigation |

## Single Query

```sql
-- Basic OData query
SELECT odata_query('https://services.odata.org/V4/Northwind/Northwind.svc/Products');
```

## Paginated Queries

The `odata_paginate` table function follows pagination links automatically across both OData v4 (`@odata.nextLink`) and OData v2 (`__next`) response formats:

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

## Total Record Count

`odata_extract_count(body)` extracts the server-reported total count from a response body. It handles both OData v4 (`@odata.count`, an unquoted integer) and OData v2 JSON (`__count`, a quoted string).

**OData v4** — add `$count=true` to the query:

```sql
SELECT
    odata_extract_count((odata_query('https://api.example.com/odata/Products?$count=true')).body) AS total
;
-- Returns the @odata.count value, or NULL if $count=true was not requested.
```

**OData v2 JSON** — add `$inlinecount=allpages` to the query:

```sql
SELECT odata_extract_count(
    (odata_query('https://api.example.com/odata/Products?$inlinecount=allpages')).body
) AS total;
-- Returns the __count value parsed as BIGINT, or NULL if $inlinecount was not requested.
```

`odata_extract_count` returns `NULL` (not an error) when the count field is absent from the response — for example when `$count=true` / `$inlinecount=allpages` was not included in the request.

## Schema Introspection

`odata_metadata(url)` fetches and parses the `$metadata` CSDL document from an OData service into a flat, queryable table. It works with both OData v4 and v2/v3 CSDL formats.

```sql
-- Discover all entity sets, types, and properties
SELECT *
FROM odata_metadata('https://services.odata.org/V4/Northwind/Northwind.svc/$metadata');
```

| Column | Type | Description |
|--------|------|-------------|
| `entity_set` | VARCHAR | Entity set name from the service container (`NULL` for complex types with no direct set mapping) |
| `entity_type` | VARCHAR | Entity or complex type name |
| `property_name` | VARCHAR | Property name |
| `property_type` | VARCHAR | OData type string, e.g. `Edm.String`, `Edm.Int32`, or navigation target type |
| `nullable` | BOOLEAN | Whether the property accepts NULL (OData default: `true`) |
| `is_key` | BOOLEAN | Whether this property is part of the entity key |
| `is_navigation` | BOOLEAN | Whether this is a `NavigationProperty` rather than a scalar property |

**Common introspection queries:**

```sql
-- List all available entity sets and their key properties
SELECT entity_set, property_name, property_type
FROM odata_metadata('https://api.example.com/odata/$metadata')
WHERE is_key = true
ORDER BY entity_set;

-- Find all required (non-nullable, non-key) fields for a specific entity
SELECT property_name, property_type
FROM odata_metadata('https://api.example.com/odata/$metadata')
WHERE entity_set = 'Orders'
  AND nullable = false
  AND is_key = false;

-- Explore navigation properties (related entities)
SELECT entity_type, property_name, property_type
FROM odata_metadata('https://api.example.com/odata/$metadata')
WHERE is_navigation = true
ORDER BY entity_type;
```

**Authenticated endpoints** — pass a Bearer token via the `authorization` named parameter:

```sql
SELECT *
FROM odata_metadata(
    'https://api.example.com/odata/$metadata',
    authorization := http_bearer_auth('my-token')
);
```

The `authorization` value is sent as-is in the `Authorization` HTTP header. Use `http_basic_auth(user, pass)` or `http_bearer_auth(token)` to construct the correct format.

> `odata_metadata` fetches CSDL XML and parses `EntityType`, `ComplexType`, `Property`, `NavigationProperty`, and `EntitySet` declarations. It does not evaluate `$metadata` annotations or function/action imports.

## OData v2 JSON Services

OData v2 services that return JSON responses are supported. Pass `Accept: application/json` (or rely on the auto-injected header) and pagination via `__next` is followed automatically:

```sql
-- OData v2 JSON service — pagination via __next is handled transparently
FROM odata_paginate(
    'https://services.odata.org/V2/Northwind/Northwind.svc/Products',
    filter := 'UnitPrice gt 20',
    select := 'ProductName,UnitPrice',
    top := 50
);
```

> OData v2 services that return Atom/XML are not currently supported. Configure the endpoint to return JSON where possible.

## Working with Results

Each row contains one page of results. Use DuckDB JSON functions to extract entities:

```sql
-- Extract all entities from every page into individual rows
SELECT unnest(json_extract(body, '$.value')::JSON[]) AS entity
FROM odata_paginate(
    'https://api.example.com/odata/Users',
    select := 'Id,Name,Email',
    top := 100,
    max_pages := 5
)
WHERE status = 200;

-- Project specific fields
SELECT
    entity->>'$.Id'    AS id,
    entity->>'$.Name'  AS name,
    entity->>'$.Email' AS email
FROM (
    SELECT unnest(json_extract(body, '$.value')::JSON[]) AS entity
    FROM odata_paginate(
        'https://api.example.com/odata/Users',
        select := 'Id,Name,Email',
        top := 100
    )
    WHERE status = 200
);
```

## Authentication

Pass an authorization header using the auth helpers:

```sql
-- Bearer token
FROM odata_paginate(
    'https://api.example.com/odata/Orders',
    top := 200
) -- headers parameter: use odata_query for header support
;

-- With odata_query and a Bearer token
SELECT odata_query(
    'https://api.example.com/odata/Orders?$top=100',
    MAP {'Authorization': http_bearer_auth('my-token')}
);
```

## Security Considerations

- OData URLs are validated against [SSRF rules](../security/ssrf.md) on every page.
- Pagination follow URLs (`@odata.nextLink` and `__next`) are re-validated for scheme and host safety before each request.
- Use [authentication helpers](../configuration/auth.md) for secured OData endpoints.
