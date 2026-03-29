# Monitoring (Prometheus / Elasticsearch / InfluxDB)

duck_net provides functions for querying monitoring and observability platforms directly from SQL.

## Functions

### Prometheus

| Function | Parameters | Returns |
|----------|-----------|---------|
| `prometheus_query` | `(url, promql)` | STRUCT(success BOOLEAN, result_type VARCHAR, body VARCHAR, message VARCHAR) |
| `prometheus_query_range` | `(url, promql, start, end, step)` | STRUCT(success, result_type, body, message) |

### Elasticsearch

| Function | Parameters | Returns |
|----------|-----------|---------|
| `es_search` | `(url, index, query_json)` | STRUCT(success BOOLEAN, body VARCHAR, message VARCHAR) |
| `es_count` | `(url, index, query_json)` | STRUCT(success, body, message) |
| `es_cat` | `(url, endpoint)` | STRUCT(success, body, message) |

### InfluxDB

| Function | Parameters | Returns |
|----------|-----------|---------|
| `influx_query` | `(url, org, token, flux_query)` | STRUCT(success BOOLEAN, body VARCHAR, message VARCHAR) |
| `influx_write` | `(url, org, bucket, token, line_protocol)` | STRUCT(success, body, message) |
| `influx_health` | `(url)` | STRUCT(success, body, message) |

## Prometheus

```sql
-- Instant query
SELECT (prometheus_query(
    'http://prometheus:9090', 'up{job="api"}'
)).body;

-- Range query (last hour, 15s step)
SELECT (prometheus_query_range(
    'http://prometheus:9090',
    'rate(http_requests_total[5m])',
    '2026-03-29T00:00:00Z',
    '2026-03-29T01:00:00Z',
    '15s'
)).body;
```

## Elasticsearch

```sql
-- Search documents
SELECT (es_search(
    'https://es.example.com:9200', 'logs-*',
    '{"query": {"match": {"level": "error"}}, "size": 10}'
)).body;

-- Count matching documents
SELECT (es_count(
    'https://es.example.com:9200', 'logs-*',
    '{"query": {"range": {"@timestamp": {"gte": "now-1h"}}}}'
)).body;

-- Cluster health (cat API)
SELECT (es_cat('https://es.example.com:9200', 'health')).body;
SELECT (es_cat('https://es.example.com:9200', 'indices')).body;
```

## InfluxDB

```sql
-- Query with Flux
SELECT (influx_query(
    'http://influxdb:8086', 'my-org', 'my-token',
    'from(bucket: "metrics") |> range(start: -1h) |> filter(fn: (r) => r._measurement == "cpu")'
)).body;

-- Write line protocol data
SELECT (influx_write(
    'http://influxdb:8086', 'my-org', 'metrics', 'my-token',
    'cpu,host=server01 usage=0.64 1648684800000000000'
)).success;

-- Health check
SELECT (influx_health('http://influxdb:8086')).body;
```

## Using Secrets

```sql
-- Store Elasticsearch credentials
SELECT duck_net_add_secret('es', 'elasticsearch', '{"username": "elastic", "password": "secret"}');

-- Store InfluxDB token
SELECT duck_net_add_secret('influx', 'influxdb', '{"token": "my-token"}');
```

## Security Considerations

- All monitoring URLs are validated against [SSRF rules](../security/ssrf.md).
- Use HTTPS endpoints in production to protect tokens in transit.
- Store tokens using the [secrets manager](../security/secrets.md) with `elasticsearch` or `influxdb` types.
