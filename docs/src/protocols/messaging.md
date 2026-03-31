# Messaging (MQTT / AMQP / Kafka / NATS / ZeroMQ)

duck_net provides publish/produce functions for five messaging protocols. These are fire-and-forget or request-reply operations suited for sending messages from SQL queries.

## Functions

| Function | Parameters | Returns |
|----------|-----------|---------|
| `mqtt_publish` | `(broker, topic, payload)` | STRUCT(success BOOLEAN, message VARCHAR) |
| `mqtt_publish` | `(broker, topic, payload, retain BOOLEAN)` | STRUCT(success, message) |
| `amqp_publish` | `(url, exchange, routing_key, message)` | STRUCT(success, message) |
| `amqp_publish` | `(url, exchange, routing_key, message, content_type)` | STRUCT(success, message) |
| `kafka_produce` | `(brokers, topic, key, value)` | STRUCT(success BOOLEAN, partition INTEGER, offset BIGINT, message VARCHAR) |
| `kafka_produce` | `(brokers, topic, value)` | STRUCT(success, partition, offset, message) |
| `nats_publish` | `(url, subject, payload)` | STRUCT(success, message) |
| `nats_request` | `(url, subject, payload)` | STRUCT(success BOOLEAN, response VARCHAR, message VARCHAR) |
| `nats_request` | `(url, subject, payload, timeout_ms)` | STRUCT(success, response, message) |
| `zmq_request` | `(endpoint, message)` | STRUCT(success BOOLEAN, response VARCHAR, message VARCHAR) |

## MQTT

```sql
-- Publish a message to an MQTT broker
SELECT (mqtt_publish('tcp://broker.example.com:1883', 'sensors/temp', '22.5')).success;

-- Publish with retain flag
SELECT (mqtt_publish('tcp://broker.example.com:1883', 'config/version', '1.2.0', true)).success;
```

## AMQP (RabbitMQ)

```sql
-- Publish to an exchange
SELECT (amqp_publish(
    'amqp://guest:guest@localhost:5672',
    'events', 'user.created',
    '{"user_id": 42, "name": "Alice"}'
)).success;

-- With explicit content type
SELECT (amqp_publish(
    'amqp://localhost:5672',
    'logs', 'app.info',
    'Application started',
    'text/plain'
)).success;
```

## Kafka

```sql
-- Produce a message with a key
SELECT (kafka_produce(
    'localhost:9092',
    'events', 'user-42',
    '{"action": "login"}'
)).*;

-- Produce without a key (round-robin partition)
SELECT (kafka_produce(
    'localhost:9092',
    'events',
    '{"action": "heartbeat"}'
)).offset;
```

## NATS

```sql
-- Publish (fire-and-forget)
SELECT (nats_publish('nats://localhost:4222', 'events.user', '{"id": 42}')).success;

-- Request-reply pattern
SELECT (nats_request('nats://localhost:4222', 'api.greet', '{"name": "Alice"}')).response;

-- Request with custom timeout (milliseconds)
SELECT (nats_request('nats://localhost:4222', 'api.compute', '{"n": 100}', 5000)).response;
```

## ZeroMQ

> [!WARNING]
> ZeroMQ plaintext connections (NULL security, ZMTP/3.0) are **blocked by default**. CURVE encryption is not yet implemented in duck_net. To use ZeroMQ you must explicitly opt in, acknowledging that all messages will be sent in cleartext.

```sql
-- Required before any zmq_request call:
SELECT duck_net_allow_zeromq_plaintext(true);

-- REQ-REP pattern
SELECT (zmq_request('tcp://localhost:5555', 'Hello')).response;

-- Disable again when done (or simply don't call it for production sessions):
SELECT duck_net_allow_zeromq_plaintext(false);
```

Only use ZeroMQ on trusted, isolated networks. Do not use it over untrusted network paths. This opt-in is intentional — it forces an explicit acknowledgement that the connection has no transport security.

## Security Considerations

- All broker hostnames are validated against [SSRF rules](../security/ssrf.md).
- MQTT topic names are validated for injection characters.
- Use TLS-enabled broker URLs where available (`mqtts://`, `amqps://`, `nats+tls://`).
- Responses from NATS and ZeroMQ are capped at 16 MiB.
- Store broker credentials using the [secrets manager](../security/secrets.md) with `mqtt`, `kafka`, or `nats` types.
