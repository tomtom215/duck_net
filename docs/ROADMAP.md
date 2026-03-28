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

## Priority 3: FTP/SFTP File Operations

Enterprise file exchange over FTP and SFTP. Complements httpfs (which covers HTTP/S3 but not FTP/SFTP). SFTP especially remains deeply entrenched in finance, healthcare, government, and supply chain for regulated file transfers.

### 3a. ftp_list, sftp_list (table functions)
### 3b. ftp_read, sftp_read (scalar functions)
### 3c. ftp_write, sftp_write (scalar functions)
### 3d. ftp_delete, sftp_delete (scalar functions)

## Priority 4: DNS Lookups

Scalar functions for DNS resolution. Perfect fit for log enrichment and network analysis.

### 4a. dns_lookup, dns_reverse, dns_txt, dns_mx

## Priority 5: SMTP Send

Fire-and-forget email sending from SQL. Useful for alerting on query results.

### 5a. smtp_send

## Rejected Protocols

| Protocol | Reason |
|----------|--------|
| WebSockets | Push-based streaming. No natural mapping to DuckDB functions. "Connect-send-receive-disconnect" is just worse HTTP. |
| MQTT Subscribe | Push-based streaming. Same fundamental mismatch as WebSockets. |
| MQTT Publish | Feasible but extremely niche. Who publishes MQTT from SQL? |
| XMPP | Deeply stateful, session-oriented, streaming. Zero SQL use case. |
| gRPC | Request-response fits, but protobuf handling is enormous complexity for marginal gain over HTTP+JSON. Revisit if demand materializes. |
