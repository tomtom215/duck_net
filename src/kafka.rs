// SPDX-License-Identifier: MIT
// Copyright 2026 Tom F. <tomf@tomtomtech.net> (https://github.com/tomtom215)

use crate::runtime;

/// Maximum key size: 1 MiB (CWE-400).
const MAX_KEY_SIZE: usize = 1024 * 1024;
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
