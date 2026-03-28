# duck_net Roadmap

## Design Principle

Every feature must pass this filter: **Does it map naturally to DuckDB's synchronous, batch-oriented, pull-based execution model?**

- Scalar functions: stateless, row-in → row-out
- Table functions: produce a finite, pull-based result set
- No persistent connections, no push-based streaming, no background threads

Protocols that are request-response and stateless are excellent fits. Protocols that are streaming, session-oriented, or push-based are not.

## Priority 1: HTTP Enhancements

Make the existing HTTP client production-ready for real data pipelines.

### 1a. Retry with Configurable Backoff
### 1b. Paginated API Consumption (Table Function)
### 1c. Authentication Helpers (Bearer, Basic, OAuth2 Client Credentials)

## Priority 2: DNS Lookups

Scalar functions for DNS resolution. Perfect fit for log enrichment and network analysis.

### 2a. dns_lookup, dns_reverse, dns_txt, dns_mx

## Priority 3: SMTP Send

Fire-and-forget email sending from SQL. Useful for alerting on query results.

### 3a. smtp_send

## Rejected Protocols

| Protocol | Reason |
|----------|--------|
| WebSockets | Push-based streaming. No natural mapping to DuckDB functions. "Connect-send-receive-disconnect" is just worse HTTP. |
| MQTT Subscribe | Push-based streaming. Same fundamental mismatch as WebSockets. |
| MQTT Publish | Feasible but extremely niche. Who publishes MQTT from SQL? |
| XMPP | Deeply stateful, session-oriented, streaming. Zero SQL use case. |
| gRPC | Request-response fits, but protobuf handling is enormous complexity for marginal gain over HTTP+JSON. Revisit if demand materializes. |
| FTP/SFTP | Dying protocol. httpfs covers HTTP file access, S3 extensions cover cloud storage. |
