use crate::runtime;

pub struct KafkaProduceResult {
    pub success: bool,
    pub partition: i32,
    pub offset: i64,
    pub message: String,
}

/// Produce a message to a Kafka topic.
///
/// `brokers` is a comma-separated list of broker addresses (e.g., "localhost:9092").
pub fn produce(
    brokers: &str,
    topic: &str,
    key: Option<&str>,
    value: &str,
) -> KafkaProduceResult {
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
        .produce(vec![record], rskafka::client::partition::Compression::NoCompression)
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
