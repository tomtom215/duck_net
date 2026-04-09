// SPDX-License-Identifier: MIT
// Copyright 2026 Tom F. <tomf@tomtomtech.net> (https://github.com/tomtom215)

use std::net::UdpSocket;
use std::time::Duration;

const NTP_PORT: u16 = 123;
const NTP_PACKET_SIZE: usize = 48;
const TIMEOUT_SECS: u64 = 5;

/// Seconds between 1900-01-01 and 1970-01-01 (NTP epoch offset).
const NTP_EPOCH_OFFSET: u64 = 2_208_988_800;

/// Result of an SNTP v4 query with nanosecond precision and all header fields.
pub struct SntpResult {
    /// Clock offset in nanoseconds.
    pub offset_ns: f64,
    /// Round-trip delay in nanoseconds.
    pub delay_ns: f64,
    /// Stratum level of the server.
    pub stratum: u8,
    /// Leap indicator (0 = no warning, 1 = last minute 61s, 2 = last minute 59s, 3 = alarm).
    pub leap_indicator: u8,
    /// NTP version number.
    pub version: u8,
    /// Poll interval (log2 seconds).
    pub poll_interval: i8,
    /// Precision of the server clock (log2 seconds).
    pub precision: i8,
    /// Root delay in microseconds (fixed-point 16.16).
    pub root_delay_us: f64,
    /// Root dispersion in microseconds (fixed-point 16.16).
    pub root_dispersion_us: f64,
    /// Reference identifier (ASCII for stratum <= 1, IP for stratum >= 2).
    pub reference_id: String,
    /// Reference timestamp as Unix seconds (with fractional nanoseconds).
    pub reference_time_unix: f64,
    /// Origin timestamp as Unix seconds (T1 copied back by server).
    #[allow(dead_code)]
    pub origin_time_unix: f64,
    /// Receive timestamp as Unix seconds (T2 at server).
    pub receive_time_unix: f64,
    /// Transmit timestamp as Unix seconds (T3 at server).
    pub transmit_time_unix: f64,
    /// Best estimate of server time as Unix seconds.
    pub server_time_unix: f64,
}

/// Result of multiple SNTP probes with statistical analysis.
pub struct PtpProbeResult {
    /// Offset from the probe with the lowest delay (nanoseconds).
    pub best_offset_ns: f64,
    /// Delay from the best probe (nanoseconds).
    pub best_delay_ns: f64,
    /// Average offset across all probes (nanoseconds).
    pub avg_offset_ns: f64,
    /// Minimum round-trip delay observed (nanoseconds).
    pub min_delay_ns: f64,
    /// Maximum round-trip delay observed (nanoseconds).
    pub max_delay_ns: f64,
    /// Standard deviation of offsets (nanoseconds).
    pub stddev_ns: f64,
    /// Number of successful samples collected.
    pub samples: u8,
    /// Stratum from the best measurement.
    pub stratum: u8,
    /// Reference ID from the best measurement.
    pub reference_id: String,
    /// Server time from the best measurement.
    pub server_time_unix: f64,
}

/// Convert an NTP timestamp (seconds + fraction since 1900) to Unix nanoseconds.
fn ntp_to_unix_ns(secs: u32, frac: u32) -> f64 {
    let unix_secs = secs as f64 - NTP_EPOCH_OFFSET as f64;
    let nanos = (frac as f64 / u32::MAX as f64) * 1_000_000_000.0;
    unix_secs * 1_000_000_000.0 + nanos
}

/// Convert an NTP timestamp to Unix seconds (with sub-second precision).
fn ntp_to_unix_secs(secs: u32, frac: u32) -> f64 {
    (secs as f64 - NTP_EPOCH_OFFSET as f64) + (frac as f64 / u32::MAX as f64)
}

/// Parse a 32-bit fixed-point 16.16 value from 4 bytes (big-endian) into microseconds.
fn fixed16_16_to_us(bytes: &[u8]) -> f64 {
    let raw = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    let integer = (raw >> 16) as f64;
    let fraction = (raw & 0xFFFF) as f64 / 65536.0;
    (integer + fraction) * 1_000_000.0
}

/// Validate that a server hostname is well-formed.
fn validate_server(server: &str) -> Result<(), String> {
    if server.is_empty() {
        return Err("Server hostname must not be empty".to_string());
    }
    if server.len() > 253 {
        return Err(format!(
            "Server hostname too long: {} chars (max 253)",
            server.len()
        ));
    }
    if !server
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
    {
        return Err(format!(
            "Invalid server hostname '{}': only alphanumeric, dots, and hyphens allowed",
            server
        ));
    }
    Ok(())
}

/// Get the current time as Unix seconds with sub-second precision.
fn now_unix_secs() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64()
}

/// Query an NTP server using SNTP v4 (RFC 4330) with nanosecond precision.
///
/// Extracts all NTP header fields and computes clock offset and round-trip
/// delay with nanosecond granularity.
pub fn sntp_query(server: &str) -> Result<SntpResult, String> {
    let result = sntp_query_inner(server);
    match &result {
        Ok(_) => crate::audit_log::record("ptp", "sntp_query", server, true, 0, ""),
        Err(e) => crate::audit_log::record("ptp", "sntp_query", server, false, 0, e),
    }
    result
}

fn sntp_query_inner(server: &str) -> Result<SntpResult, String> {
    validate_server(server)?;
    // Atomic resolve-and-validate (closes UDP DNS-rebinding TOCTOU, CWE-918).
    let addr = crate::security::resolve_and_validate_udp(server, NTP_PORT)?;

    let bind_addr = if addr.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let socket =
        UdpSocket::bind(bind_addr).map_err(|e| format!("Failed to bind UDP socket: {e}"))?;
    socket
        .set_read_timeout(Some(Duration::from_secs(TIMEOUT_SECS)))
        .map_err(|e| format!("Failed to set timeout: {e}"))?;

    // Build SNTP v4 request packet (LI=0, VN=4, Mode=3 client)
    let mut packet = [0u8; NTP_PACKET_SIZE];
    packet[0] = 0b00_100_011; // LI=0, version=4, mode=3

    let t1 = now_unix_secs();

    // Set transmit timestamp (bytes 40-47) so the server can echo it back
    let t1_ntp = t1 + NTP_EPOCH_OFFSET as f64;
    let secs = t1_ntp as u32;
    let frac = ((t1_ntp - secs as f64) * (u32::MAX as f64)) as u32;
    packet[40..44].copy_from_slice(&secs.to_be_bytes());
    packet[44..48].copy_from_slice(&frac.to_be_bytes());

    socket
        .send_to(&packet, addr)
        .map_err(|e| format!("Failed to send SNTP request: {e}"))?;

    let mut response = [0u8; NTP_PACKET_SIZE];
    let (size, _) = socket
        .recv_from(&mut response)
        .map_err(|e| format!("Failed to receive SNTP response: {e}"))?;

    let t4 = now_unix_secs();

    if size < NTP_PACKET_SIZE {
        return Err(format!(
            "SNTP response too short: {size} bytes (expected {NTP_PACKET_SIZE})"
        ));
    }

    // --- Parse header fields ---

    // Byte 0: LI (bits 6-7), VN (bits 3-5), Mode (bits 0-2)
    let leap_indicator = (response[0] >> 6) & 0x03;
    let version = (response[0] >> 3) & 0x07;
    let stratum = response[1];
    let poll_interval = response[2] as i8;
    let precision = response[3] as i8;

    // Root delay (bytes 4-7): fixed-point 16.16
    let root_delay_us = fixed16_16_to_us(&response[4..8]);

    // Root dispersion (bytes 8-11): fixed-point 16.16
    let root_dispersion_us = fixed16_16_to_us(&response[8..12]);

    // Reference ID (bytes 12-15)
    let reference_id = if stratum <= 1 {
        let id_bytes = &response[12..16];
        String::from_utf8_lossy(id_bytes)
            .trim_end_matches('\0')
            .to_string()
    } else {
        format!(
            "{}.{}.{}.{}",
            response[12], response[13], response[14], response[15]
        )
    };

    // --- Parse all four timestamps ---

    // Reference timestamp (bytes 16-23)
    let ref_secs = u32::from_be_bytes([response[16], response[17], response[18], response[19]]);
    let ref_frac = u32::from_be_bytes([response[20], response[21], response[22], response[23]]);

    // Origin timestamp (bytes 24-31) — our T1 echoed back
    let orig_secs = u32::from_be_bytes([response[24], response[25], response[26], response[27]]);
    let orig_frac = u32::from_be_bytes([response[28], response[29], response[30], response[31]]);

    // Receive timestamp (bytes 32-39) — server's T2
    let rx_secs = u32::from_be_bytes([response[32], response[33], response[34], response[35]]);
    let rx_frac = u32::from_be_bytes([response[36], response[37], response[38], response[39]]);

    // Transmit timestamp (bytes 40-47) — server's T3
    let tx_secs = u32::from_be_bytes([response[40], response[41], response[42], response[43]]);
    let tx_frac = u32::from_be_bytes([response[44], response[45], response[46], response[47]]);

    // Convert to nanoseconds for high-precision offset/delay calculation
    let t1_ns = t1 * 1_000_000_000.0;
    let t2_ns = ntp_to_unix_ns(rx_secs, rx_frac);
    let t3_ns = ntp_to_unix_ns(tx_secs, tx_frac);
    let t4_ns = t4 * 1_000_000_000.0;

    // offset = ((T2 - T1) + (T3 - T4)) / 2
    let offset_ns = ((t2_ns - t1_ns) + (t3_ns - t4_ns)) / 2.0;
    // delay = (T4 - T1) - (T3 - T2)
    let delay_ns = (t4_ns - t1_ns) - (t3_ns - t2_ns);

    // Convert timestamps to Unix seconds for the result struct
    let reference_time_unix = ntp_to_unix_secs(ref_secs, ref_frac);
    let origin_time_unix = ntp_to_unix_secs(orig_secs, orig_frac);
    let receive_time_unix = ntp_to_unix_secs(rx_secs, rx_frac);
    let transmit_time_unix = ntp_to_unix_secs(tx_secs, tx_frac);

    Ok(SntpResult {
        offset_ns,
        delay_ns,
        stratum,
        leap_indicator,
        version,
        poll_interval,
        precision,
        root_delay_us,
        root_dispersion_us,
        reference_id,
        reference_time_unix,
        origin_time_unix,
        receive_time_unix,
        transmit_time_unix,
        server_time_unix: transmit_time_unix,
    })
}

/// Send multiple SNTP probes and return statistical analysis with the best
/// (minimum-delay) measurement, similar to PTP delay measurement strategies.
///
/// `count` is clamped to the range 1..=10.
pub fn ptp_probe(server: &str, count: u8) -> Result<PtpProbeResult, String> {
    validate_server(server)?;

    let count = count.clamp(1, 10);
    let mut offsets: Vec<f64> = Vec::with_capacity(count as usize);
    let mut delays: Vec<f64> = Vec::with_capacity(count as usize);
    let mut best_index: usize = 0;
    let mut best_result: Option<SntpResult> = None;
    let mut min_delay = f64::MAX;

    for i in 0..count {
        match sntp_query(server) {
            Ok(result) => {
                let idx = offsets.len();
                offsets.push(result.offset_ns);
                delays.push(result.delay_ns);

                if result.delay_ns < min_delay {
                    min_delay = result.delay_ns;
                    best_index = idx;
                    best_result = Some(result);
                }

                // Brief pause between probes to avoid flooding
                if i + 1 < count {
                    std::thread::sleep(Duration::from_millis(150));
                }
            }
            Err(e) => {
                // Skip failed probes; we only need at least one success
                if i + 1 < count {
                    std::thread::sleep(Duration::from_millis(150));
                }
                if i == count - 1 && offsets.is_empty() {
                    return Err(format!("All {count} SNTP probes failed. Last error: {e}"));
                }
            }
        }
    }

    if offsets.is_empty() {
        return Err("No successful SNTP probes".to_string());
    }

    let samples = offsets.len() as u8;

    // Compute statistics
    let avg_offset_ns = offsets.iter().sum::<f64>() / offsets.len() as f64;
    let min_delay_ns = delays.iter().copied().fold(f64::MAX, f64::min);
    let max_delay_ns = delays.iter().copied().fold(f64::MIN, f64::max);

    // Standard deviation of offsets
    let variance = if offsets.len() > 1 {
        offsets
            .iter()
            .map(|o| {
                let diff = o - avg_offset_ns;
                diff * diff
            })
            .sum::<f64>()
            / (offsets.len() - 1) as f64
    } else {
        0.0
    };
    let stddev_ns = variance.sqrt();

    let best = best_result.ok_or("No successful SNTP probes (internal error)")?;

    Ok(PtpProbeResult {
        best_offset_ns: offsets[best_index],
        best_delay_ns: delays[best_index],
        avg_offset_ns,
        min_delay_ns,
        max_delay_ns,
        stddev_ns,
        samples,
        stratum: best.stratum,
        reference_id: best.reference_id,
        server_time_unix: best.server_time_unix,
    })
}
