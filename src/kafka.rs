// SPDX-License-Identifier: MIT
// Copyright 2026 Tom F. <tomf@tomtomtech.net> (https://github.com/tomtom215)

use crate::runtime;

/// Maximum key size: 1 MiB (CWE-400).
const MAX_KEY_SIZE: usize = 1024 * 1024;

/// Maximum messages to consume in a single call (CWE-400).
const MAX_CONSUME_MESSAGES: i64 = 10_000;

pub struct KafkaConsumeMessage {
    pub key: String,
    pub value: String,
    pub partition: i32,
    pub offset: i64,
    pub timestamp_ms: i64,
}

pub struct KafkaConsumeResult {
    pub success: bool,
    pub messages: Vec<KafkaConsumeMessage>,
    pub message: String,
}

/// Consume messages from a Kafka topic starting at `start_offset`.
///
/// `start_offset` of -2 means "earliest", -1 means "latest".
/// Returns up to `max_messages` records.
pub fn consume(
    brokers: &str,
    topic: &str,
    partition: i32,
    start_offset: i64,
    max_messages: i64,
) -> KafkaConsumeResult {
    crate::security_warnings::warn_plaintext(
        "Kafka",
        "PLAINTEXT_KAFKA",
        "Kafka with SASL/TLS via a dedicated Kafka extension",
    );

    let max_messages = max_messages.clamp(1, MAX_CONSUME_MESSAGES);

    runtime::block_on(async {
        consume_async(brokers, topic, partition, start_offset, max_messages).await
    })
}

async fn consume_async(
    brokers: &str,
    topic: &str,
    partition: i32,
    start_offset: i64,
    max_messages: i64,
) -> KafkaConsumeResult {
    use rskafka::client::{
        partition::{OffsetAt, UnknownTopicHandling},
        ClientBuilder,
    };

    let broker_list: Vec<String> = brokers
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();

    if broker_list.is_empty() {
        return KafkaConsumeResult {
            success: false,
            messages: vec![],
            message: "No brokers specified".to_string(),
        };
    }

    for broker in &broker_list {
        let host = broker.split(':').next().unwrap_or(broker);
        if let Err(e) = crate::security::validate_no_ssrf_host(host) {
            return KafkaConsumeResult {
                success: false,
                messages: vec![],
                message: e,
            };
        }
    }

    if topic.is_empty() || topic.len() > 249 || topic.contains('\0') {
        return KafkaConsumeResult {
            success: false,
            messages: vec![],
            message: "Invalid topic name".to_string(),
        };
    }

    let client = match ClientBuilder::new(broker_list).build().await {
        Ok(c) => c,
        Err(e) => {
            return KafkaConsumeResult {
                success: false,
                messages: vec![],
                message: format!("Kafka connection failed: {e}"),
            }
        }
    };

    let partition_client = match client
        .partition_client(topic, partition, UnknownTopicHandling::Error)
        .await
    {
        Ok(pc) => pc,
        Err(e) => {
            return KafkaConsumeResult {
                success: false,
                messages: vec![],
                message: format!("Failed to get partition client: {e}"),
            }
        }
    };

    // Resolve the start offset
    let resolved_offset = match start_offset {
        -2 => match partition_client.get_offset(OffsetAt::Earliest).await {
            Ok(o) => o,
            Err(e) => {
                return KafkaConsumeResult {
                    success: false,
                    messages: vec![],
                    message: format!("Failed to get earliest offset: {e}"),
                }
            }
        },
        -1 => match partition_client.get_offset(OffsetAt::Latest).await {
            Ok(o) => o,
            Err(e) => {
                return KafkaConsumeResult {
                    success: false,
                    messages: vec![],
                    message: format!("Failed to get latest offset: {e}"),
                }
            }
        },
        o => o,
    };

    // Fetch records: rskafka returns batches; collect up to max_messages
    let max_bytes = 10 * 1024 * 1024i32; // 10 MiB fetch limit
    let records = match partition_client
        .fetch_records(resolved_offset, 0..max_bytes, 5_000)
        .await
    {
        Ok((records, _watermark)) => records,
        Err(e) => {
            return KafkaConsumeResult {
                success: false,
                messages: vec![],
                message: format!("Fetch failed: {e}"),
            }
        }
    };

    let messages: Vec<KafkaConsumeMessage> = records
        .into_iter()
        .take(max_messages as usize)
        .enumerate()
        .map(|(i, record)| {
            let offset = resolved_offset + i as i64;
            let key = record
                .record
                .key
                .map(|k| String::from_utf8_lossy(&k).to_string())
                .unwrap_or_default();
            let value = record
                .record
                .value
                .map(|v| String::from_utf8_lossy(&v).to_string())
                .unwrap_or_default();
            let timestamp_ms = record.record.timestamp.timestamp_millis();
            KafkaConsumeMessage {
                key,
                value,
                partition,
                offset,
                timestamp_ms,
            }
        })
        .collect();

    let count = messages.len();
    KafkaConsumeResult {
        success: true,
        messages,
        message: format!("Consumed {count} message(s) from {topic}:{partition}"),
    }
}
/// Maximum value size: 16 MiB (CWE-400).
const MAX_VALUE_SIZE: usize = 16 * 1024 * 1024;

pub struct KafkaProduceResult {
    pub success: bool,
    pub partition: i32,
    pub offset: i64,
    pub message: String,
}

/// Produce a message to a Kafka topic.
///
/// `brokers` is a comma-separated list of broker addresses (e.g., "localhost:9092").
pub fn produce(brokers: &str, topic: &str, key: Option<&str>, value: &str) -> KafkaProduceResult {
    // Warn about plaintext Kafka connections (CWE-319)
    crate::security_warnings::warn_plaintext(
        "Kafka",
        "PLAINTEXT_KAFKA",
        "Kafka with SASL/TLS via a dedicated Kafka extension",
    );

    runtime::block_on(async { produce_async(brokers, topic, key, value).await })
}

async fn produce_async(
    brokers: &str,
    topic: &str,
    key: Option<&str>,
    value: &str,
) -> KafkaProduceResult {
    use rskafka::client::{partition::UnknownTopicHandling, ClientBuilder};
    use rskafka::record::Record;
    use std::collections::BTreeMap;

    let broker_list: Vec<String> = brokers
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();

    if broker_list.is_empty() {
        return KafkaProduceResult {
            success: false,
            partition: -1,
            offset: -1,
            message: "No brokers specified".to_string(),
        };
    }

    // SSRF protection: validate all broker hosts (CWE-918)
    for broker in &broker_list {
        let host = broker.split(':').next().unwrap_or(broker);
        if let Err(e) = crate::security::validate_no_ssrf_host(host) {
            return KafkaProduceResult {
                success: false,
                partition: -1,
                offset: -1,
                message: e,
            };
        }
    }

    // Validate topic name
    if topic.is_empty() || topic.len() > 249 {
        return KafkaProduceResult {
            success: false,
            partition: -1,
            offset: -1,
            message: "Topic name must be 1-249 characters".to_string(),
        };
    }
    if topic.contains('\0') {
        return KafkaProduceResult {
            success: false,
            partition: -1,
            offset: -1,
            message: "Topic name must not contain null bytes".to_string(),
        };
    }

    // Validate key/value sizes (CWE-400)
    if let Some(k) = key {
        if k.len() > MAX_KEY_SIZE {
            return KafkaProduceResult {
                success: false,
                partition: -1,
                offset: -1,
                message: format!("Key too large: {} bytes (max {MAX_KEY_SIZE})", k.len()),
            };
        }
    }
    if value.len() > MAX_VALUE_SIZE {
        return KafkaProduceResult {
            success: false,
            partition: -1,
            offset: -1,
            message: format!(
                "Value too large: {} bytes (max {MAX_VALUE_SIZE})",
                value.len()
            ),
        };
    }

    let client = match ClientBuilder::new(broker_list).build().await {
        Ok(c) => c,
        Err(e) => {
            return KafkaProduceResult {
                success: false,
                partition: -1,
                offset: -1,
                message: format!("Kafka connection failed: {e}"),
            }
        }
    };

    // Get a partition client for partition 0
    let partition_client = match client
        .partition_client(topic, 0, UnknownTopicHandling::Error)
        .await
    {
        Ok(pc) => pc,
        Err(e) => {
            return KafkaProduceResult {
                success: false,
                partition: -1,
                offset: -1,
                message: format!("Failed to get partition client: {e}"),
            }
        }
    };

    let record = Record {
        key: key.map(|k| k.as_bytes().to_vec()),
        value: Some(value.as_bytes().to_vec()),
        headers: BTreeMap::new(),
        timestamp: chrono::Utc::now(),
    };

    match partition_client
        .produce(
            vec![record],
            rskafka::client::partition::Compression::NoCompression,
        )
        .await
    {
        Ok(offsets) => {
            let offset = offsets.first().copied().unwrap_or(-1);
            KafkaProduceResult {
                success: true,
                partition: 0,
                offset,
                message: format!(
                    "Produced {} bytes to topic='{}' partition=0 offset={}",
                    value.len(),
                    topic,
                    offset
                ),
            }
        }
        Err(e) => KafkaProduceResult {
            success: false,
            partition: -1,
            offset: -1,
            message: format!("Kafka produce failed: {e}"),
        },
    }
}
