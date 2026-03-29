// SPDX-License-Identifier: MIT
// Copyright 2026 Tom F. <tomf@tomtomtech.net> (https://github.com/tomtom215)

use crate::runtime;

/// Maximum message size: 16 MiB (CWE-400).
const MAX_MESSAGE_SIZE: usize = 16 * 1024 * 1024;

/// Maximum exchange/routing_key name length.
const MAX_NAME_LENGTH: usize = 255;

pub struct AmqpPublishResult {
    pub success: bool,
    pub message: String,
}

/// Publish a message to an AMQP exchange (RabbitMQ).
///
/// URL format: amqp://user:pass@host:port/vhost
pub fn publish(
    url: &str,
    exchange: &str,
    routing_key: &str,
    message: &str,
    content_type: Option<&str>,
) -> AmqpPublishResult {
    runtime::block_on(async {
        publish_async(url, exchange, routing_key, message, content_type).await
    })
}

async fn publish_async(
    url: &str,
    exchange: &str,
    routing_key: &str,
    message: &str,
    content_type: Option<&str>,
) -> AmqpPublishResult {
    use lapin::{options::*, BasicProperties, Connection, ConnectionProperties};

    // SSRF protection: block connections to private/reserved IPs (CWE-918)
    if let Err(e) = crate::security::validate_no_ssrf(url) {
        return AmqpPublishResult {
            success: false,
            message: e,
        };
    }

    // Validate URL length (CWE-400)
    if let Err(e) = crate::security::validate_url_length(url) {
        return AmqpPublishResult {
            success: false,
            message: e,
        };
    }

    // Validate exchange and routing_key names (CWE-20)
    if exchange.len() > MAX_NAME_LENGTH {
        return AmqpPublishResult {
            success: false,
            message: format!(
                "Exchange name too long: {} chars (max {MAX_NAME_LENGTH})",
                exchange.len()
            ),
        };
    }
    if routing_key.len() > MAX_NAME_LENGTH {
        return AmqpPublishResult {
            success: false,
            message: format!(
                "Routing key too long: {} chars (max {MAX_NAME_LENGTH})",
                routing_key.len()
            ),
        };
    }

    // Validate message size (CWE-400)
    if message.len() > MAX_MESSAGE_SIZE {
        return AmqpPublishResult {
            success: false,
            message: format!(
                "Message too large: {} bytes (max {MAX_MESSAGE_SIZE})",
                message.len()
            ),
        };
    }

    let conn = match Connection::connect(url, ConnectionProperties::default()).await {
        Ok(c) => c,
        Err(e) => {
            return AmqpPublishResult {
                success: false,
                message: format!("AMQP connection failed: {e}"),
            }
        }
    };

    let channel = match conn.create_channel().await {
        Ok(ch) => ch,
        Err(e) => {
            return AmqpPublishResult {
                success: false,
                message: format!("Failed to create AMQP channel: {e}"),
            }
        }
    };

    let properties = match content_type {
        Some(ct) => BasicProperties::default().with_content_type(ct.into()),
        None => BasicProperties::default().with_content_type("text/plain".into()),
    };

    match channel
        .basic_publish(
            exchange,
            routing_key,
            BasicPublishOptions::default(),
            message.as_bytes(),
            properties,
        )
        .await
    {
        Ok(confirm) => match confirm.await {
            Ok(_) => AmqpPublishResult {
                success: true,
                message: format!(
                    "Published {} bytes to exchange='{}' routing_key='{}'",
                    message.len(),
                    exchange,
                    routing_key
                ),
            },
            Err(e) => AmqpPublishResult {
                success: false,
                message: format!("AMQP publish confirmation failed: {e}"),
            },
        },
        Err(e) => AmqpPublishResult {
            success: false,
            message: format!("AMQP publish failed: {e}"),
        },
    }
}
