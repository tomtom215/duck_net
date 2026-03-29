// SPDX-License-Identifier: MIT
// Copyright 2026 Tom F. <tomf@tomtomtech.net> (https://github.com/tomtom215)

use std::net::UdpSocket;
use std::time::Duration;

const NTP_PORT: u16 = 123;
const NTP_PACKET_SIZE: usize = 48;
const TIMEOUT_SECS: u64 = 5;

/// Seconds between 1900-01-01 and 1970-01-01 (NTP epoch offset).
const NTP_EPOCH_OFFSET: u64 = 2_208_988_800;

pub struct NtpResult {
    pub offset_ms: f64,
    pub delay_ms: f64,
    pub stratum: u8,
    #[allow(dead_code)]
    pub precision: i8,
    pub reference_id: String,
    pub server_time_unix: f64,
}

/// Query an NTP server for the current time.
pub fn query(server: &str) -> Result<NtpResult, String> {
    // Input validation
    crate::security::validate_host(server)?;
    // SSRF protection: block connections to private/reserved IPs (CWE-918)
    crate::security::validate_no_ssrf_host(server)?;

    let addr = format!("{server}:{NTP_PORT}");

    let socket =
        UdpSocket::bind("0.0.0.0:0").map_err(|e| format!("Failed to bind UDP socket: {e}"))?;
    socket
        .set_read_timeout(Some(Duration::from_secs(TIMEOUT_SECS)))
        .map_err(|e| format!("Failed to set timeout: {e}"))?;

    // Build NTP request packet
    let mut packet = [0u8; NTP_PACKET_SIZE];
    // LI=0, VN=4, Mode=3 (client)
    packet[0] = 0b00_100_011; // version 4, mode 3

    let t1 = now_unix_secs();

    // Set transmit timestamp (bytes 40-47)
    let t1_ntp = t1 + NTP_EPOCH_OFFSET as f64;
    let secs = t1_ntp as u32;
    let frac = ((t1_ntp - secs as f64) * (u32::MAX as f64)) as u32;
    packet[40..44].copy_from_slice(&secs.to_be_bytes());
    packet[44..48].copy_from_slice(&frac.to_be_bytes());

    socket
        .send_to(&packet, &addr)
        .map_err(|e| format!("Failed to send NTP request: {e}"))?;

    let mut response = [0u8; NTP_PACKET_SIZE];
    let (size, _) = socket
        .recv_from(&mut response)
        .map_err(|e| format!("Failed to receive NTP response: {e}"))?;

    let t4 = now_unix_secs();

    if size < NTP_PACKET_SIZE {
        return Err(format!(
            "NTP response too short: {size} bytes (expected {NTP_PACKET_SIZE})"
        ));
    }

    // Parse response
    let stratum = response[1];
    let precision = response[3] as i8;

    // Reference ID (bytes 12-15)
    let reference_id = if stratum <= 1 {
        // For stratum 0-1, it's an ASCII string
        let id_bytes = &response[12..16];
        String::from_utf8_lossy(id_bytes)
            .trim_end_matches('\0')
            .to_string()
    } else {
        // For stratum 2+, it's an IP address
        format!(
            "{}.{}.{}.{}",
            response[12], response[13], response[14], response[15]
        )
    };

    // Receive timestamp (server time when it sent the response) - bytes 40-47
    let tx_secs = u32::from_be_bytes([response[40], response[41], response[42], response[43]]);
    let tx_frac = u32::from_be_bytes([response[44], response[45], response[46], response[47]]);
    let t3 = (tx_secs as f64 - NTP_EPOCH_OFFSET as f64) + (tx_frac as f64 / u32::MAX as f64);

    // Receive timestamp at server (when server got our request) - bytes 32-39
    let rx_secs = u32::from_be_bytes([response[32], response[33], response[34], response[35]]);
    let rx_frac = u32::from_be_bytes([response[36], response[37], response[38], response[39]]);
    let t2 = (rx_secs as f64 - NTP_EPOCH_OFFSET as f64) + (rx_frac as f64 / u32::MAX as f64);

    // Calculate offset and delay
    // offset = ((t2 - t1) + (t3 - t4)) / 2
    // delay = (t4 - t1) - (t3 - t2)
    let offset = ((t2 - t1) + (t3 - t4)) / 2.0;
    let delay = (t4 - t1) - (t3 - t2);

    Ok(NtpResult {
        offset_ms: offset * 1000.0,
        delay_ms: delay * 1000.0,
        stratum,
        precision,
        reference_id,
        server_time_unix: t3,
    })
}

fn now_unix_secs() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64()
}
