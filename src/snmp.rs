// SPDX-License-Identifier: MIT
// Copyright 2026 Tom F. <tomf@tomtomtech.net> (https://github.com/tomtom215)

use std::net::UdpSocket;
use std::time::Duration;

const SNMP_PORT: u16 = 161;
const TIMEOUT_SECS: u64 = 10;
const MAX_RESPONSE_BYTES: usize = 65535;

pub struct SnmpResult {
    pub oid: String,
    pub value: String,
    pub value_type: String,
}

/// Perform an SNMP GET request (SNMPv2c).
pub fn get(host: &str, oid: &str, community: &str) -> Result<SnmpResult, String> {
    // Warn about SNMPv2c limitations (CWE-327)
    crate::security_warnings::warn_weak_auth(
        "SNMP",
        "SNMPV2C_WEAK_AUTH",
        "SNMPv2c with plaintext community strings. \
         Consider SNMPv3 for authentication and encryption",
    );
    validate_community(community)?;
    let request = build_get_request(oid, community)?;
    let response = send_udp(host, SNMP_PORT, &request)?;
    parse_response(&response).and_then(|results| {
        results
            .into_iter()
            .next()
            .ok_or_else(|| "No values in SNMP response".to_string())
    })
}

/// Validate SNMP community string length and content.
fn validate_community(community: &str) -> Result<(), String> {
    if community.is_empty() {
        return Err("Community string must not be empty".to_string());
    }
    if community.len() > 255 {
        return Err("Community string too long (max 255 characters)".to_string());
    }
    if community.contains('\0') {
        return Err("Community string must not contain null bytes".to_string());
    }
    Ok(())
}

/// Maximum walk entries to prevent unbounded iteration (CWE-400).
const MAX_WALK_ENTRIES: usize = 10_000;

/// Perform an SNMP WALK (repeated GET-NEXT) starting from an OID.
pub fn walk(
    host: &str,
    oid: &str,
    community: &str,
    max_entries: usize,
) -> Result<Vec<SnmpResult>, String> {
    validate_community(community)?;
    // Clamp max_entries to prevent unbounded iteration
    let max_entries = max_entries.min(MAX_WALK_ENTRIES);
    let base_oid = oid;
    let mut current_oid = oid.to_string();
    let mut results = Vec::new();

    for _ in 0..max_entries {
        let request = build_getnext_request(&current_oid, community)?;
        let response = send_udp(host, SNMP_PORT, &request)?;
        let parsed = parse_response(&response)?;

        if let Some(result) = parsed.into_iter().next() {
            // Check if we've walked past the base OID subtree
            if !result.oid.starts_with(base_oid) {
                break;
            }
            current_oid = result.oid.clone();
            results.push(result);
        } else {
            break;
        }
    }

    Ok(results)
}

/// Validate SNMP host: alphanumeric, dots, hyphens, colons (IPv6), brackets.
fn is_valid_host(host: &str) -> bool {
    if host.is_empty() || host.len() > 253 {
        return false;
    }
    host.chars()
        .all(|c| c.is_alphanumeric() || matches!(c, '.' | '-' | ':' | '[' | ']'))
}

fn send_udp(host: &str, port: u16, data: &[u8]) -> Result<Vec<u8>, String> {
    // Validate host input
    if !is_valid_host(host) {
        return Err(format!("Invalid SNMP host: {host}"));
    }
    // SSRF protection: block connections to private/reserved IPs (CWE-918)
    crate::security::validate_no_ssrf_host(host)?;

    let socket =
        UdpSocket::bind("0.0.0.0:0").map_err(|e| format!("Failed to bind UDP socket: {e}"))?;
    socket
        .set_read_timeout(Some(Duration::from_secs(TIMEOUT_SECS)))
        .map_err(|e| format!("Failed to set timeout: {e}"))?;

    let addr = format!("{host}:{port}");
    socket
        .send_to(data, &addr)
        .map_err(|e| format!("Failed to send SNMP request to {addr}: {e}"))?;

    let mut buf = vec![0u8; MAX_RESPONSE_BYTES];
    let (size, _) = socket
        .recv_from(&mut buf)
        .map_err(|e| format!("Failed to receive SNMP response: {e}"))?;
    buf.truncate(size);
    Ok(buf)
}

// ===== BER/ASN.1 Encoding for SNMPv2c =====

/// Build an SNMPv2c GET request packet.
fn build_get_request(oid: &str, community: &str) -> Result<Vec<u8>, String> {
    build_request(oid, community, 0xA0) // GET-REQUEST PDU type
}

/// Build an SNMPv2c GET-NEXT request packet.
fn build_getnext_request(oid: &str, community: &str) -> Result<Vec<u8>, String> {
    build_request(oid, community, 0xA1) // GET-NEXT-REQUEST PDU type
}

fn build_request(oid: &str, community: &str, pdu_type: u8) -> Result<Vec<u8>, String> {
    let oid_bytes = encode_oid(oid)?;

    // Variable binding: SEQUENCE { OID, NULL }
    let mut varbind = Vec::new();
    varbind.extend_from_slice(&oid_bytes);
    varbind.push(0x05); // NULL type
    varbind.push(0x00); // NULL length

    let varbind_seq = wrap_sequence(&varbind);

    // Variable binding list: SEQUENCE { varbind }
    let varbind_list = wrap_sequence(&varbind_seq);

    // PDU: pdu_type { request-id, error-status, error-index, varbind-list }
    let request_id = encode_integer(1);
    let error_status = encode_integer(0);
    let error_index = encode_integer(0);

    let mut pdu_content = Vec::new();
    pdu_content.extend_from_slice(&request_id);
    pdu_content.extend_from_slice(&error_status);
    pdu_content.extend_from_slice(&error_index);
    pdu_content.extend_from_slice(&varbind_list);

    let pdu = wrap_tlv(pdu_type, &pdu_content);

    // SNMP message: SEQUENCE { version, community, pdu }
    let version = encode_integer(1); // SNMPv2c = version 1
    let community_bytes = encode_octet_string(community.as_bytes());

    let mut message = Vec::new();
    message.extend_from_slice(&version);
    message.extend_from_slice(&community_bytes);
    message.extend_from_slice(&pdu);

    Ok(wrap_sequence(&message))
}

fn encode_integer(value: i64) -> Vec<u8> {
    let mut bytes = Vec::new();
    let mut v = value;

    if v == 0 {
        bytes.push(0);
    } else if v > 0 {
        while v > 0 {
            bytes.push((v & 0xFF) as u8);
            v >>= 8;
        }
        // Add leading zero if high bit set
        if bytes.last().is_some_and(|b| b & 0x80 != 0) {
            bytes.push(0);
        }
        bytes.reverse();
    } else {
        while v < -1 {
            bytes.push((v & 0xFF) as u8);
            v >>= 8;
        }
        bytes.push((v & 0xFF) as u8);
        bytes.reverse();
    }

    let mut result = vec![0x02]; // INTEGER type
    result.extend_from_slice(&encode_length(bytes.len()));
    result.extend_from_slice(&bytes);
    result
}

fn encode_octet_string(data: &[u8]) -> Vec<u8> {
    let mut result = vec![0x04]; // OCTET STRING type
    result.extend_from_slice(&encode_length(data.len()));
    result.extend_from_slice(data);
    result
}

fn encode_oid(oid: &str) -> Result<Vec<u8>, String> {
    let parts: Vec<u32> = oid
        .split('.')
        .filter(|s| !s.is_empty())
        .map(|s| {
            s.parse::<u32>()
                .map_err(|e| format!("Invalid OID component '{s}': {e}"))
        })
        .collect::<Result<Vec<_>, _>>()?;

    if parts.len() < 2 {
        return Err("OID must have at least 2 components".to_string());
    }

    let mut encoded = Vec::new();
    // First two components are encoded as 40*X + Y
    encoded.push((parts[0] * 40 + parts[1]) as u8);

    for &part in &parts[2..] {
        if part < 128 {
            encoded.push(part as u8);
        } else {
            // Multi-byte encoding
            let mut temp = Vec::new();
            let mut v = part;
            temp.push((v & 0x7F) as u8);
            v >>= 7;
            while v > 0 {
                temp.push((v & 0x7F) as u8 | 0x80);
                v >>= 7;
            }
            temp.reverse();
            encoded.extend_from_slice(&temp);
        }
    }

    let mut result = vec![0x06]; // OBJECT IDENTIFIER type
    result.extend_from_slice(&encode_length(encoded.len()));
    result.extend_from_slice(&encoded);
    Ok(result)
}

fn encode_length(len: usize) -> Vec<u8> {
    if len < 128 {
        vec![len as u8]
    } else if len < 256 {
        vec![0x81, len as u8]
    } else {
        vec![0x82, (len >> 8) as u8, (len & 0xFF) as u8]
    }
}

fn wrap_sequence(data: &[u8]) -> Vec<u8> {
    wrap_tlv(0x30, data)
}

fn wrap_tlv(tag: u8, data: &[u8]) -> Vec<u8> {
    let mut result = vec![tag];
    result.extend_from_slice(&encode_length(data.len()));
    result.extend_from_slice(data);
    result
}

// ===== BER/ASN.1 Decoding =====

fn parse_response(data: &[u8]) -> Result<Vec<SnmpResult>, String> {
    let (_, content) = parse_tlv(data)?;

    // Skip version and community
    let mut pos = 0;

    // version (INTEGER)
    let (len, _) = parse_tlv(&content[pos..])?;
    pos += len;

    // community (OCTET STRING)
    let (len, _) = parse_tlv(&content[pos..])?;
    pos += len;

    // PDU (RESPONSE = 0xA2)
    let (_, pdu_content) = parse_tlv(&content[pos..])?;

    // request-id, error-status, error-index
    let mut pdu_pos = 0;
    let (len, _) = parse_tlv(&pdu_content[pdu_pos..])?; // request-id
    pdu_pos += len;
    let (len, error_status_bytes) = parse_tlv(&pdu_content[pdu_pos..])?; // error-status
    let error_status = decode_integer(&error_status_bytes);
    pdu_pos += len;
    let (len, _) = parse_tlv(&pdu_content[pdu_pos..])?; // error-index
    pdu_pos += len;

    if error_status != 0 {
        return Err(format!("SNMP error status: {error_status}"));
    }

    // Variable binding list
    let (_, varbind_list) = parse_tlv(&pdu_content[pdu_pos..])?;

    let mut results = Vec::new();
    let mut vb_pos = 0;
    while vb_pos < varbind_list.len() {
        let (vb_total, vb_content) = parse_tlv(&varbind_list[vb_pos..])?;
        vb_pos += vb_total;

        // Each varbind: SEQUENCE { OID, value }
        let mut inner_pos = 0;
        let (oid_total, oid_content) = parse_tlv(&vb_content[inner_pos..])?;
        let oid_tag = vb_content[inner_pos];
        inner_pos += oid_total;

        let oid_str = if oid_tag == 0x06 {
            decode_oid(&oid_content)
        } else {
            "unknown".to_string()
        };

        if inner_pos < vb_content.len() {
            let value_tag = vb_content[inner_pos];
            let (_, value_content) = parse_tlv(&vb_content[inner_pos..])?;

            let (value, value_type) = decode_value(value_tag, &value_content);
            results.push(SnmpResult {
                oid: oid_str,
                value,
                value_type,
            });
        }
    }

    Ok(results)
}

fn parse_tlv(data: &[u8]) -> Result<(usize, Vec<u8>), String> {
    if data.is_empty() {
        return Err("Empty TLV data".to_string());
    }

    let _tag = data[0];
    let (length, header_len) = if data.len() < 2 {
        return Err("TLV too short".to_string());
    } else if data[1] & 0x80 == 0 {
        (data[1] as usize, 2)
    } else {
        let num_bytes = (data[1] & 0x7F) as usize;
        if data.len() < 2 + num_bytes {
            return Err("TLV length encoding truncated".to_string());
        }
        let mut len = 0usize;
        for i in 0..num_bytes {
            len = (len << 8) | data[2 + i] as usize;
        }
        (len, 2 + num_bytes)
    };

    let total = header_len + length;
    if data.len() < total {
        return Err("TLV data truncated".to_string());
    }

    Ok((total, data[header_len..total].to_vec()))
}

fn decode_integer(data: &[u8]) -> i64 {
    if data.is_empty() {
        return 0;
    }
    let mut value = if data[0] & 0x80 != 0 { -1i64 } else { 0i64 };
    for &b in data {
        value = (value << 8) | b as i64;
    }
    value
}

fn decode_oid(data: &[u8]) -> String {
    if data.is_empty() {
        return String::new();
    }
    let mut parts = Vec::new();
    parts.push((data[0] / 40) as u32);
    parts.push((data[0] % 40) as u32);

    let mut i = 1;
    while i < data.len() {
        let mut value = 0u32;
        loop {
            if i >= data.len() {
                break;
            }
            let b = data[i];
            value = (value << 7) | (b & 0x7F) as u32;
            i += 1;
            if b & 0x80 == 0 {
                break;
            }
        }
        parts.push(value);
    }

    parts
        .iter()
        .map(|p| p.to_string())
        .collect::<Vec<_>>()
        .join(".")
}

fn decode_value(tag: u8, data: &[u8]) -> (String, String) {
    match tag {
        0x02 => (decode_integer(data).to_string(), "INTEGER".to_string()),
        0x04 => (
            String::from_utf8_lossy(data).to_string(),
            "OCTET STRING".to_string(),
        ),
        0x05 => ("".to_string(), "NULL".to_string()),
        0x06 => (decode_oid(data), "OID".to_string()),
        0x40 => {
            // IpAddress
            if data.len() == 4 {
                (
                    format!("{}.{}.{}.{}", data[0], data[1], data[2], data[3]),
                    "IpAddress".to_string(),
                )
            } else {
                (hex_string(data), "IpAddress".to_string())
            }
        }
        0x41 => (decode_integer(data).to_string(), "Counter32".to_string()),
        0x42 => (decode_integer(data).to_string(), "Gauge32".to_string()),
        0x43 => (decode_integer(data).to_string(), "TimeTicks".to_string()),
        0x44 => (hex_string(data), "Opaque".to_string()),
        0x46 => (decode_integer(data).to_string(), "Counter64".to_string()),
        0x80 => ("noSuchObject".to_string(), "noSuchObject".to_string()),
        0x81 => ("noSuchInstance".to_string(), "noSuchInstance".to_string()),
        0x82 => ("endOfMibView".to_string(), "endOfMibView".to_string()),
        _ => (hex_string(data), format!("UNKNOWN(0x{tag:02X})")),
    }
}

fn hex_string(data: &[u8]) -> String {
    data.iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join(" ")
}
