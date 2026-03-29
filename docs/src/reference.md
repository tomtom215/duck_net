# Function Reference

A complete list of all duck_net functions organized by protocol. Each function links to its detailed documentation page.

## HTTP / HTTPS

| Function | Description |
|----------|-------------|
| [`http_get`](./protocols/http.md) | HTTP GET request |
| [`http_post`](./protocols/http.md) | HTTP POST request |
| [`http_put`](./protocols/http.md) | HTTP PUT request |
| [`http_patch`](./protocols/http.md) | HTTP PATCH request |
| [`http_delete`](./protocols/http.md) | HTTP DELETE request |
| [`http_head`](./protocols/http.md) | HTTP HEAD request |
| [`http_options`](./protocols/http.md) | HTTP OPTIONS request |
| [`http_request`](./protocols/http.md) | Generic HTTP request with any method |
| [`http_post_multipart`](./protocols/http.md) | Multipart form upload |
| [`http_paginate`](./protocols/http.md) | Paginated HTTP table function |
| [`http_basic_auth`](./configuration/auth.md) | Generate Basic auth header |
| [`http_bearer_auth`](./configuration/auth.md) | Generate Bearer auth header |
| [`http_oauth2_token`](./configuration/auth.md) | OAuth2 Client Credentials grant |

## GraphQL / RPC

| Function | Description |
|----------|-------------|
| [`graphql_query`](./protocols/graphql.md) | Execute a GraphQL query or mutation |
| [`graphql_has_errors`](./protocols/graphql.md) | Check for GraphQL errors |
| [`graphql_extract_errors`](./protocols/graphql.md) | Extract GraphQL error messages |
| [`soap_request`](./protocols/soap.md) | SOAP 1.1/1.2 request |
| [`soap_extract_body`](./protocols/soap.md) | Extract SOAP response body |
| [`soap_is_fault`](./protocols/soap.md) | Check for SOAP fault |
| [`soap_fault_string`](./protocols/soap.md) | Extract SOAP fault message |
| [`xmlrpc_call`](./protocols/soap.md) | XML-RPC method call |
| [`jsonrpc_call`](./protocols/soap.md) | JSON-RPC 2.0 method call |
| [`grpc_call`](./protocols/grpc.md) | gRPC unary call |
| [`grpc_list_services`](./protocols/grpc.md) | gRPC server reflection |

## OData / WebDAV

| Function | Description |
|----------|-------------|
| [`odata_query`](./protocols/odata.md) | OData v4 query |
| [`odata_paginate`](./protocols/odata.md) | Paginated OData table function |
| [`webdav_list`](./protocols/webdav.md) | List WebDAV directory |
| [`webdav_read`](./protocols/webdav.md) | Read WebDAV file |
| [`webdav_write`](./protocols/webdav.md) | Write WebDAV file |
| [`webdav_delete`](./protocols/webdav.md) | Delete WebDAV resource |
| [`webdav_mkcol`](./protocols/webdav.md) | Create WebDAV collection |
| [`ws_request`](./protocols/websocket.md) | WebSocket request-response |
| [`ws_multi_request`](./protocols/websocket.md) | WebSocket multi-message |

## DNS / Network

| Function | Description |
|----------|-------------|
| [`dns_lookup`](./protocols/dns.md) | Resolve hostname to IP |
| [`dns_lookup_a`](./protocols/dns.md) | Resolve to IPv4 |
| [`dns_lookup_aaaa`](./protocols/dns.md) | Resolve to IPv6 |
| [`dns_reverse`](./protocols/dns.md) | Reverse DNS lookup |
| [`dns_txt`](./protocols/dns.md) | DNS TXT records |
| [`dns_mx`](./protocols/dns.md) | DNS MX records |
| [`doh_lookup`](./protocols/dns.md) | DNS-over-HTTPS query |
| [`mdns_discover`](./protocols/dns.md) | mDNS service discovery |
| [`ping`](./protocols/network-utils.md) | ICMP ping |
| [`traceroute`](./protocols/network-utils.md) | Network traceroute |
| [`whois_lookup`](./protocols/network-utils.md) | WHOIS domain query |
| [`whois_query`](./protocols/network-utils.md) | Raw WHOIS query |
| [`stun_lookup`](./protocols/network-utils.md) | STUN NAT discovery |
| [`bgp_route`](./protocols/network-utils.md) | BGP route lookup |
| [`bgp_prefix_overview`](./protocols/network-utils.md) | BGP prefix info |
| [`bgp_asn_info`](./protocols/network-utils.md) | BGP ASN details |
| [`ntp_query`](./protocols/time.md) | NTP time query |
| [`sntp_query`](./protocols/time.md) | SNTP time query |
| [`ptp_probe`](./protocols/time.md) | PTP clock probe |

## Email / File Transfer / SSH

| Function | Description |
|----------|-------------|
| [`smtp_send`](./protocols/email.md) | Send email via SMTP |
| [`imap_list`](./protocols/email.md) | List IMAP messages |
| [`imap_fetch`](./protocols/email.md) | Fetch IMAP message body |
| [`imap_move`](./protocols/email.md) | Move IMAP message |
| [`imap_delete`](./protocols/email.md) | Delete IMAP message |
| [`imap_flag`](./protocols/email.md) | Set IMAP message flag |
| [`ftp_read`](./protocols/filetransfer.md) | Read file via FTP |
| [`ftp_read_blob`](./protocols/filetransfer.md) | Read binary via FTP |
| [`ftp_write`](./protocols/filetransfer.md) | Write file via FTP |
| [`ftp_delete`](./protocols/filetransfer.md) | Delete file via FTP |
| [`ftp_list`](./protocols/filetransfer.md) | List FTP directory |
| [`sftp_read`](./protocols/filetransfer.md) | Read file via SFTP |
| [`sftp_read_blob`](./protocols/filetransfer.md) | Read binary via SFTP |
| [`sftp_write`](./protocols/filetransfer.md) | Write file via SFTP |
| [`sftp_delete`](./protocols/filetransfer.md) | Delete file via SFTP |
| [`sftp_list`](./protocols/filetransfer.md) | List SFTP directory |
| [`scp_read`](./protocols/filetransfer.md) | Read file via SCP |
| [`scp_read_password`](./protocols/filetransfer.md) | Read via SCP (password) |
| [`scp_write`](./protocols/filetransfer.md) | Write file via SCP |
| [`scp_write_password`](./protocols/filetransfer.md) | Write via SCP (password) |
| [`ssh_exec`](./protocols/ssh.md) | Execute SSH command |
| [`ssh_exec_password`](./protocols/ssh.md) | SSH with password auth |

## Data Stores

| Function | Description |
|----------|-------------|
| [`ldap_search`](./protocols/ldap.md) | LDAP directory search |
| [`ldap_bind`](./protocols/ldap.md) | LDAP authentication |
| [`ldap_add`](./protocols/ldap.md) | LDAP add entry |
| [`ldap_modify`](./protocols/ldap.md) | LDAP modify entry |
| [`ldap_delete`](./protocols/ldap.md) | LDAP delete entry |
| [`redis_get`](./protocols/redis.md) | Redis GET |
| [`redis_set`](./protocols/redis.md) | Redis SET |
| [`redis_del`](./protocols/redis.md) | Redis DEL |
| [`redis_keys`](./protocols/redis.md) | Redis KEYS |
| [`redis_expire`](./protocols/redis.md) | Redis EXPIRE |
| [`redis_hget`](./protocols/redis.md) | Redis HGET |
| [`redis_hset`](./protocols/redis.md) | Redis HSET |
| [`s3_get`](./protocols/s3.md) | S3 GetObject |
| [`s3_put`](./protocols/s3.md) | S3 PutObject |
| [`s3_list`](./protocols/s3.md) | S3 ListObjects |

## Messaging

| Function | Description |
|----------|-------------|
| [`mqtt_publish`](./protocols/messaging.md) | MQTT publish |
| [`amqp_publish`](./protocols/messaging.md) | AMQP publish |
| [`kafka_produce`](./protocols/messaging.md) | Kafka produce |
| [`nats_publish`](./protocols/messaging.md) | NATS publish |
| [`nats_request`](./protocols/messaging.md) | NATS request-reply |
| [`zmq_request`](./protocols/messaging.md) | ZeroMQ REQ-REP |

## Monitoring / Service Discovery

| Function | Description |
|----------|-------------|
| [`prometheus_query`](./protocols/monitoring.md) | Prometheus instant query |
| [`prometheus_query_range`](./protocols/monitoring.md) | Prometheus range query |
| [`es_search`](./protocols/monitoring.md) | Elasticsearch search |
| [`es_count`](./protocols/monitoring.md) | Elasticsearch count |
| [`es_cat`](./protocols/monitoring.md) | Elasticsearch cat API |
| [`influx_query`](./protocols/monitoring.md) | InfluxDB Flux query |
| [`influx_write`](./protocols/monitoring.md) | InfluxDB line protocol write |
| [`influx_health`](./protocols/monitoring.md) | InfluxDB health check |
| [`consul_get`](./protocols/service-discovery.md) | Consul KV get |
| [`consul_set`](./protocols/service-discovery.md) | Consul KV set |
| [`consul_delete`](./protocols/service-discovery.md) | Consul KV delete |
| [`etcd_get`](./protocols/service-discovery.md) | etcd KV get |
| [`etcd_put`](./protocols/service-discovery.md) | etcd KV put |
| [`vault_read`](./protocols/service-discovery.md) | Vault read secret |
| [`vault_write`](./protocols/service-discovery.md) | Vault write secret |
| [`vault_list`](./protocols/service-discovery.md) | Vault list secrets |
| [`vault_health`](./protocols/service-discovery.md) | Vault health check |

## Infrastructure

| Function | Description |
|----------|-------------|
| [`snmp_get`](./protocols/infrastructure.md) | SNMP GET |
| [`snmp_walk`](./protocols/infrastructure.md) | SNMP WALK |
| [`syslog_send`](./protocols/infrastructure.md) | Send syslog message |
| [`ipmi_device_id`](./protocols/infrastructure.md) | IPMI device info |
| [`ipmi_chassis_status`](./protocols/infrastructure.md) | IPMI chassis status |
| [`ipmi_chassis_control`](./protocols/infrastructure.md) | IPMI power control |
| [`radius_auth`](./protocols/infrastructure.md) | RADIUS authentication |
| [`tls_inspect`](./protocols/certificates.md) | TLS certificate inspection |
| [`ocsp_check`](./protocols/certificates.md) | OCSP revocation check |
| [`caldav_events`](./protocols/certificates.md) | CalDAV calendar events |
| [`carddav_contacts`](./protocols/certificates.md) | CardDAV contacts |

## Configuration

| Function | Description |
|----------|-------------|
| [`duck_net_set_rate_limit`](./configuration/rate-limiting.md) | Set global rate limit |
| [`duck_net_set_domain_rate_limits`](./configuration/rate-limiting.md) | Set per-domain rate limits |
| [`duck_net_set_retries`](./configuration/retries.md) | Configure retry behavior |
| [`duck_net_set_timeout`](./configuration/retries.md) | Set request timeout |
| [`duck_net_set_retry_statuses`](./configuration/retries.md) | Configure retryable status codes |
| [`duck_net_set_security_warnings`](../security/warnings.md) | Enable/disable warnings |
| [`duck_net_security_status`](../security/architecture.md) | View security config |

## Secrets Management

| Function | Description |
|----------|-------------|
| [`duck_net_add_secret`](../security/secrets.md) | Store a secret |
| [`duck_net_secret`](../security/secrets.md) | Get a secret value |
| [`duck_net_secret_redacted`](../security/secrets.md) | Get redacted secret |
| [`duck_net_clear_secret`](../security/secrets.md) | Remove a secret |
| [`duck_net_clear_all_secrets`](../security/secrets.md) | Remove all secrets |
| [`duck_net_secrets`](../security/secrets.md) | List all secrets (table) |
