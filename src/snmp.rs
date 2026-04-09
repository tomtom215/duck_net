// SPDX-License-Identifier: MIT
// Copyright 2026 Tom F. <tomf@tomtomtech.net> (https://github.com/tomtom215)

use std::net::UdpSocket;
use std::time::Duration;

// ===== SNMPv3 =====

use hmac::{Hmac, Mac};
use md5_digest::Md5;
use sha1::Sha1;

/// SNMPv3 authentication protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SnmpV3AuthProtocol {
    Md5,
    Sha1,
    None,
}

impl SnmpV3AuthProtocol {
    pub fn from_str(s: &str) -> Result<Self, String> {
        match s.to_ascii_uppercase().as_str() {
            "MD5" => Ok(Self::Md5),
            "SHA" | "SHA1" | "SHA-1" => Ok(Self::Sha1),
            "NONE" | "" => Ok(Self::None),
            _ => Err(format!(
                "Unknown auth protocol: {s}. Use MD5, SHA1, or NONE"
            )),
        }
    }

    fn digest_len(&self) -> usize {
        match self {
            Self::Md5 => 16,
            Self::Sha1 => 20,
            Self::None => 0,
        }
    }
}

/// Convert a passphrase to a localised SNMP authentication key.
///
/// Implements the RFC 3414 §2.6 password-to-key algorithm.
fn password_to_key(password: &[u8], engine_id: &[u8], protocol: SnmpV3AuthProtocol) -> Vec<u8> {
    // Step 1: Expand password to 1 MiB
    let target_len = 1_048_576usize;
    let mut expanded = Vec::with_capacity(target_len);
    let pw_len = password.len();
    if pw_len == 0 {
        return vec![0u8; protocol.digest_len()];
    }
    let mut index = 0usize;
    while expanded.len() < target_len {
        expanded.push(password[index % pw_len]);
        index += 1;
    }

    // Step 2: Hash the expanded password
    let key = match protocol {
        SnmpV3AuthProtocol::Md5 => {
            use md5_digest::Digest;
            let mut h = Md5::new();
            h.update(&expanded);
            h.finalize().to_vec()
        }
        SnmpV3AuthProtocol::Sha1 => {
            use sha1::Digest;
            let mut h = Sha1::new();
            h.update(&expanded);
            h.finalize().to_vec()
        }
        SnmpV3AuthProtocol::None => return vec![],
    };

    // Step 3: Localise the key using the engine ID (RFC 3414 §2.6)
    match protocol {
        SnmpV3AuthProtocol::Md5 => {
            use md5_digest::Digest;
            let mut h = Md5::new();
            h.update(&key);
            h.update(engine_id);
            h.update(&key);
            h.finalize().to_vec()
        }
        SnmpV3AuthProtocol::Sha1 => {
            use sha1::Digest;
            let mut h = Sha1::new();
            h.update(&key);
            h.update(engine_id);
            h.update(&key);
            h.finalize().to_vec()
        }
        SnmpV3AuthProtocol::None => vec![],
    }
}

/// Compute HMAC-MD5 or HMAC-SHA1 over `data` using `auth_key`, then truncate
/// to the first 12 bytes (the SNMP authentication parameter, RFC 3414 §7.3.1).
fn compute_auth_param(auth_key: &[u8], data: &[u8], protocol: SnmpV3AuthProtocol) -> [u8; 12] {
    let full_mac = match protocol {
        SnmpV3AuthProtocol::Md5 => {
            let mut mac = <Hmac<Md5>>::new_from_slice(auth_key).expect("HMAC accepts any key size");
            mac.update(data);
            mac.finalize().into_bytes().to_vec()
        }
        SnmpV3AuthProtocol::Sha1 => {
            let mut mac =
                <Hmac<Sha1>>::new_from_slice(auth_key).expect("HMAC accepts any key size");
            mac.update(data);
            mac.finalize().into_bytes().to_vec()
        }
        SnmpV3AuthProtocol::None => return [0u8; 12],
    };
    let mut result = [0u8; 12];
    let copy_len = full_mac.len().min(12);
    result[..copy_len].copy_from_slice(&full_mac[..copy_len]);
    result
}

/// Build a minimal SNMPv3 message:
///   - authNoPriv (authentication, no encryption)
///   - or noAuthNoPriv (no security)
///
/// `request_id` is a 32-bit unique identifier for this exchange.
/// Returns (packet_bytes, auth_param_offset) where the auth_param_offset is
/// the byte position of the 12-byte authentication parameter so it can be
/// patched in after the MAC is computed over the whole message.
fn build_v3_request(
    oid: &str,
    username: &str,
    engine_id: &[u8],
    auth_key: &[u8],
    auth_protocol: SnmpV3AuthProtocol,
    pdu_type: u8, // 0xA0 = GET, 0xA1 = GET-NEXT
    request_id: i64,
) -> Result<(Vec<u8>, Option<usize>), String> {
    let oid_bytes = encode_oid(oid)?;
    let request_id_bytes = encode_integer(request_id);

    // Variable binding: SEQUENCE { OID, NULL }
    let mut varbind = Vec::new();
    varbind.extend_from_slice(&oid_bytes);
    varbind.push(0x05);
    varbind.push(0x00);
    let varbind_seq = wrap_sequence(&varbind);
    let varbind_list = wrap_sequence(&varbind_seq);

    // PDU
    let mut pdu_content = Vec::new();
    pdu_content.extend_from_slice(&request_id_bytes);
    pdu_content.extend_from_slice(&encode_integer(0)); // error-status
    pdu_content.extend_from_slice(&encode_integer(0)); // error-index
    pdu_content.extend_from_slice(&varbind_list);
    let pdu = wrap_tlv(pdu_type, &pdu_content);

    // scopedPDU: SEQUENCE { contextEngineID, contextName, pdu }
    let context_engine = encode_octet_string(engine_id);
    let context_name = encode_octet_string(b"");
    let mut scoped = Vec::new();
    scoped.extend_from_slice(&context_engine);
    scoped.extend_from_slice(&context_name);
    scoped.extend_from_slice(&pdu);
    let scoped_pdu = wrap_sequence(&scoped);

    // USM security parameters: SEQUENCE { engineID, engineBoots, engineTime,
    //                                     userName, authParam(12 zeros), privParam }
    let usm_engine_id = encode_octet_string(engine_id);
    let usm_boots = encode_integer(0);
    let usm_time = encode_integer(0);
    let usm_username = encode_octet_string(username.as_bytes());
    // 12-byte zero auth parameter placeholder
    let usm_auth_placeholder = encode_octet_string(&[0u8; 12]);
    let usm_priv = encode_octet_string(b"");

    let mut usm_content = Vec::new();
    usm_content.extend_from_slice(&usm_engine_id);
    usm_content.extend_from_slice(&usm_boots);
    usm_content.extend_from_slice(&usm_time);
    usm_content.extend_from_slice(&usm_username);
    usm_content.extend_from_slice(&usm_auth_placeholder);
    usm_content.extend_from_slice(&usm_priv);
    let usm_seq = wrap_sequence(&usm_content);
    let security_params = encode_octet_string(&usm_seq);

    // msgGlobalData: SEQUENCE { msgID, msgMaxSize, msgFlags, msgSecurityModel }
    let msg_id = encode_integer(request_id & 0x7FFFFFFF); // msgID fits in i32
    let msg_max_size = encode_integer(65507);
    // msgFlags: bit 0 = auth, bit 1 = priv, bit 2 = reportable
    let auth_flag: u8 = if auth_protocol == SnmpV3AuthProtocol::None {
        0x04
    } else {
        0x05
    };
    let msg_flags = encode_octet_string(&[auth_flag]);
    let msg_security_model = encode_integer(3); // USM = 3

    let mut global_data_content = Vec::new();
    global_data_content.extend_from_slice(&msg_id);
    global_data_content.extend_from_slice(&msg_max_size);
    global_data_content.extend_from_slice(&msg_flags);
    global_data_content.extend_from_slice(&msg_security_model);
    let global_data = wrap_sequence(&global_data_content);

    // SNMPv3 message: SEQUENCE { version(3), globalData, securityParams, scopedPDU }
    let version = encode_integer(3);
    let mut message_content = Vec::new();
    message_content.extend_from_slice(&version);
    message_content.extend_from_slice(&global_data);
    message_content.extend_from_slice(&security_params);
    message_content.extend_from_slice(&scoped_pdu);
    let message = wrap_sequence(&message_content);

    if auth_protocol == SnmpV3AuthProtocol::None || auth_key.is_empty() {
        return Ok((message, None));
    }

    // Find the auth parameter placeholder offset in the full message so we can
    // patch the real MAC into it. Search for the 14-byte signature:
    // 04 0C [12 zero bytes] = OCTET STRING length=12 followed by 12 zero bytes.
    let signature = {
        let mut s = vec![0x04u8, 0x0C];
        s.extend_from_slice(&[0u8; 12]);
        s
    };
    let auth_offset = message
        .windows(14)
        .position(|w| w == signature.as_slice())
        .map(|pos| pos + 2); // skip the 04 0C tag+len bytes

    Ok((message, auth_offset))
}

/// Perform an SNMPv3 GET request (authNoPriv).
pub fn v3_get(
    host: &str,
    oid: &str,
    username: &str,
    auth_protocol: SnmpV3AuthProtocol,
    auth_password: &str,
    engine_id: &[u8],
) -> Result<SnmpResult, String> {
    let auth_key = if auth_protocol != SnmpV3AuthProtocol::None {
        password_to_key(auth_password.as_bytes(), engine_id, auth_protocol)
    } else {
        vec![]
    };

    let (mut packet, auth_offset) =
        build_v3_request(oid, username, engine_id, &auth_key, auth_protocol, 0xA0, 1)?;

    if let (Some(offset), false) = (auth_offset, auth_key.is_empty()) {
        let mac = compute_auth_param(&auth_key, &packet, auth_protocol);
        packet[offset..offset + 12].copy_from_slice(&mac);
    }

    let response = send_udp(host, SNMP_PORT, &packet)?;
    parse_response(&response).and_then(|results| {
        results
            .into_iter()
            .next()
            .ok_or_else(|| "No values in SNMPv3 response".to_string())
    })
}

/// Perform an SNMPv3 WALK starting from `oid` (authNoPriv).
pub fn v3_walk(
    host: &str,
    oid: &str,
    username: &str,
    auth_protocol: SnmpV3AuthProtocol,
    auth_password: &str,
    engine_id: &[u8],
    max_entries: usize,
) -> Result<Vec<SnmpResult>, String> {
    let auth_key = if auth_protocol != SnmpV3AuthProtocol::None {
        password_to_key(auth_password.as_bytes(), engine_id, auth_protocol)
    } else {
        vec![]
    };

    let max_entries = max_entries.min(MAX_WALK_ENTRIES);
    let base_oid = oid;
    let mut current_oid = oid.to_string();
    let mut results = Vec::new();
    let mut request_id = 2i64;

    for _ in 0..max_entries {
        let (mut packet, auth_offset) = build_v3_request(
            &current_oid,
            username,
            engine_id,
            &auth_key,
            auth_protocol,
            0xA1, // GET-NEXT
            request_id,
        )?;

        if let (Some(offset), false) = (auth_offset, auth_key.is_empty()) {
            let mac = compute_auth_param(&auth_key, &packet, auth_protocol);
            packet[offset..offset + 12].copy_from_slice(&mac);
        }

        let response = send_udp(host, SNMP_PORT, &packet)?;
        let parsed = parse_response(&response)?;

        if let Some(result) = parsed.into_iter().next() {
            if !result.oid.starts_with(base_oid) {
                break;
            }
            current_oid = result.oid.clone();
            results.push(result);
        } else {
            break;
        }
        request_id += 1;
    }

    Ok(results)
}

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
    // Warn about SNMPv2c limitations (CWE-327)
    crate::security_warnings::warn_weak_auth(
        "SNMP",
        "SNMPV2C_WEAK_AUTH",
        "SNMPv2c with plaintext community strings. \
         Consider SNMPv3 for authentication and encryption",
    );
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
    // Atomic resolve-and-validate: closes the DNS-rebinding window that used
    // to exist between validate_no_ssrf_host() and send_to("host:port") which
    // re-resolved via the OS resolver (CWE-918).
    let addr = crate::security::resolve_and_validate_udp(host, port)?;

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

    socket
        .send_to(data, addr)
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
