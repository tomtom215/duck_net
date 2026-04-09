// SPDX-License-Identifier: MIT
// Copyright 2026 Tom F. <tomf@tomtomtech.net> (https://github.com/tomtom215)

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddrV4, UdpSocket};
use std::time::{Duration, Instant};

/// mDNS multicast address and port.
const MDNS_ADDR: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251);
const MDNS_PORT: u16 = 5353;

/// Maximum mDNS response size.
const MAX_RESPONSE_SIZE: usize = 9000; // mDNS allows larger than 512

/// DNS record types.
const TYPE_A: u16 = 1;
const TYPE_PTR: u16 = 12;
const TYPE_TXT: u16 = 16;
const TYPE_AAAA: u16 = 28;
const TYPE_SRV: u16 = 33;

pub struct MdnsService {
    pub instance_name: String,
    pub hostname: String,
    pub port: u16,
    pub ips: Vec<String>,
    pub txt: Vec<String>,
}

/// Validate mDNS service type (e.g., "_http._tcp.local").
fn is_valid_service_type(service: &str) -> bool {
    if service.is_empty() || service.len() > 255 {
        return false;
    }
    // Must contain at least one underscore-prefixed label
    service.contains('_')
        && service
            .chars()
            .all(|c| c.is_alphanumeric() || matches!(c, '.' | '-' | '_'))
}

/// Discover services on the local network using mDNS (RFC 6762).
///
/// Sends a PTR query for the given service type to the mDNS multicast
/// address and collects responses for `timeout_secs` seconds.
///
/// Security: only queries local multicast, validates service type format,
/// enforces response size limits, and uses timeouts.
pub fn discover(service_type: &str, timeout_secs: u32) -> Result<Vec<MdnsService>, String> {
    if !is_valid_service_type(service_type) {
        return Err("Invalid service type: must contain underscore-prefixed labels (e.g., _http._tcp.local)".to_string());
    }

    let timeout = Duration::from_secs(timeout_secs.clamp(1, 30) as u64);

    let socket =
        UdpSocket::bind("0.0.0.0:0").map_err(|e| format!("Failed to bind UDP socket: {e}"))?;

    // Join multicast group
    socket
        .join_multicast_v4(&MDNS_ADDR, &Ipv4Addr::UNSPECIFIED)
        .map_err(|e| format!("Failed to join mDNS multicast: {e}"))?;

    socket
        .set_read_timeout(Some(Duration::from_millis(500)))
        .map_err(|e| format!("Failed to set timeout: {e}"))?;

    // Build PTR query
    let query = build_mdns_query(service_type, TYPE_PTR);

    // Send query to mDNS multicast address
    let dest = SocketAddrV4::new(MDNS_ADDR, MDNS_PORT);
    socket
        .send_to(&query, dest)
        .map_err(|e| format!("mDNS send failed: {e}"))?;

    // Collect responses
    let mut services: HashMap<String, MdnsService> = HashMap::new();
    let start = Instant::now();

    while start.elapsed() < timeout {
        let mut buf = [0u8; MAX_RESPONSE_SIZE];
        match socket.recv_from(&mut buf) {
            Ok((size, _addr)) => {
                if size > 12 {
                    parse_mdns_response(&buf[..size], &mut services);
                }
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
            Err(ref e) if e.kind() == std::io::ErrorKind::TimedOut => continue,
            Err(_) => continue,
        }
    }

    // Leave multicast group
    let _ = socket.leave_multicast_v4(&MDNS_ADDR, &Ipv4Addr::UNSPECIFIED);

    let out: Vec<MdnsService> = services.into_values().collect();
    crate::audit_log::record("mdns", "discover", service_type, true, out.len() as i32, "");
    Ok(out)
}

/// Build a DNS query packet for mDNS.
fn build_mdns_query(name: &str, qtype: u16) -> Vec<u8> {
    let mut packet = Vec::new();

    // Header
    packet.extend_from_slice(&[0x00, 0x00]); // Transaction ID
    packet.extend_from_slice(&[0x00, 0x00]); // Flags (standard query)
    packet.extend_from_slice(&[0x00, 0x01]); // Questions: 1
    packet.extend_from_slice(&[0x00, 0x00]); // Answer RRs: 0
    packet.extend_from_slice(&[0x00, 0x00]); // Authority RRs: 0
    packet.extend_from_slice(&[0x00, 0x00]); // Additional RRs: 0

    // Question: encoded domain name
    encode_dns_name(&mut packet, name);
    packet.extend_from_slice(&qtype.to_be_bytes()); // QTYPE
    packet.extend_from_slice(&[0x00, 0x01]); // QCLASS: IN

    packet
}

/// Encode a DNS name (e.g., "_http._tcp.local" -> \x05_http\x04_tcp\x05local\x00).
fn encode_dns_name(packet: &mut Vec<u8>, name: &str) {
    for label in name.split('.') {
        if label.is_empty() {
            continue;
        }
        let len = label.len().min(63);
        packet.push(len as u8);
        packet.extend_from_slice(&label.as_bytes()[..len]);
    }
    packet.push(0x00); // Root label
}

/// Parse an mDNS response and extract service information.
fn parse_mdns_response(data: &[u8], services: &mut HashMap<String, MdnsService>) {
    if data.len() < 12 {
        return;
    }

    let _flags = u16::from_be_bytes([data[2], data[3]]);
    let qdcount = u16::from_be_bytes([data[4], data[5]]) as usize;
    let ancount = u16::from_be_bytes([data[6], data[7]]) as usize;
    let nscount = u16::from_be_bytes([data[8], data[9]]) as usize;
    let arcount = u16::from_be_bytes([data[10], data[11]]) as usize;

    let mut offset = 12;

    // Skip questions
    for _ in 0..qdcount {
        offset = skip_dns_name(data, offset);
        offset += 4; // QTYPE + QCLASS
        if offset >= data.len() {
            return;
        }
    }

    // Parse all resource records (answers + authority + additional)
    let total_rr = ancount + nscount + arcount;
    for _ in 0..total_rr {
        if offset >= data.len() {
            break;
        }

        let (name, new_offset) = read_dns_name(data, offset);
        offset = new_offset;

        if offset + 10 > data.len() {
            break;
        }

        let rtype = u16::from_be_bytes([data[offset], data[offset + 1]]);
        let _rclass = u16::from_be_bytes([data[offset + 2], data[offset + 3]]);
        let _ttl = u32::from_be_bytes([
            data[offset + 4],
            data[offset + 5],
            data[offset + 6],
            data[offset + 7],
        ]);
        let rdlength = u16::from_be_bytes([data[offset + 8], data[offset + 9]]) as usize;
        offset += 10;

        if offset + rdlength > data.len() {
            break;
        }

        let rdata = &data[offset..offset + rdlength];

        match rtype {
            TYPE_PTR => {
                let (instance, _) = read_dns_name(data, offset);
                services
                    .entry(instance.clone())
                    .or_insert_with(|| MdnsService {
                        instance_name: instance,
                        hostname: String::new(),
                        port: 0,
                        ips: Vec::new(),
                        txt: Vec::new(),
                    });
            }
            TYPE_SRV => {
                if rdlength >= 6 {
                    let _priority = u16::from_be_bytes([rdata[0], rdata[1]]);
                    let _weight = u16::from_be_bytes([rdata[2], rdata[3]]);
                    let port = u16::from_be_bytes([rdata[4], rdata[5]]);
                    let (hostname, _) = read_dns_name(data, offset + 6);

                    if let Some(svc) = services.get_mut(&name) {
                        svc.hostname = hostname;
                        svc.port = port;
                    }
                }
            }
            TYPE_A => {
                if rdlength == 4 {
                    let ip = format!("{}.{}.{}.{}", rdata[0], rdata[1], rdata[2], rdata[3]);
                    // Try to find a service that references this name
                    for svc in services.values_mut() {
                        if (svc.hostname == name || name.ends_with(&svc.hostname))
                            && !svc.ips.contains(&ip)
                        {
                            svc.ips.push(ip.clone());
                        }
                    }
                }
            }
            TYPE_AAAA => {
                if rdlength == 16 {
                    let ip = format!(
                        "{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}",
                        u16::from_be_bytes([rdata[0], rdata[1]]),
                        u16::from_be_bytes([rdata[2], rdata[3]]),
                        u16::from_be_bytes([rdata[4], rdata[5]]),
                        u16::from_be_bytes([rdata[6], rdata[7]]),
                        u16::from_be_bytes([rdata[8], rdata[9]]),
                        u16::from_be_bytes([rdata[10], rdata[11]]),
                        u16::from_be_bytes([rdata[12], rdata[13]]),
                        u16::from_be_bytes([rdata[14], rdata[15]]),
                    );
                    for svc in services.values_mut() {
                        if (svc.hostname == name || name.ends_with(&svc.hostname))
                            && !svc.ips.contains(&ip)
                        {
                            svc.ips.push(ip.clone());
                        }
                    }
                }
            }
            TYPE_TXT => {
                // TXT records: one or more <length><text> pairs
                let mut pos = 0;
                let mut txt_entries = Vec::new();
                while pos < rdlength {
                    let txt_len = rdata[pos] as usize;
                    pos += 1;
                    if pos + txt_len <= rdlength {
                        let txt = String::from_utf8_lossy(&rdata[pos..pos + txt_len]).to_string();
                        txt_entries.push(txt);
                    }
                    pos += txt_len;
                }
                if let Some(svc) = services.get_mut(&name) {
                    svc.txt = txt_entries;
                }
            }
            _ => {}
        }

        offset += rdlength;
    }
}

/// Read a DNS name from a packet, handling compression pointers.
fn read_dns_name(data: &[u8], mut offset: usize) -> (String, usize) {
    let mut labels = Vec::new();
    let mut jumped = false;
    let mut return_offset = 0;
    let mut iterations = 0;

    loop {
        iterations += 1;
        if iterations > 128 || offset >= data.len() {
            break;
        }

        let len = data[offset];

        if len == 0 {
            offset += 1;
            break;
        }

        if (len & 0xC0) == 0xC0 {
            // Compression pointer
            if offset + 1 >= data.len() {
                break;
            }
            let pointer = ((len as usize & 0x3F) << 8) | data[offset + 1] as usize;
            if !jumped {
                return_offset = offset + 2;
                jumped = true;
            }
            offset = pointer;
        } else {
            let label_len = len as usize;
            offset += 1;
            if offset + label_len > data.len() {
                break;
            }
            let label = String::from_utf8_lossy(&data[offset..offset + label_len]).to_string();
            labels.push(label);
            offset += label_len;
        }
    }

    let name = labels.join(".");
    let final_offset = if jumped { return_offset } else { offset };
    (name, final_offset)
}

/// Skip a DNS name in a packet (for advancing past questions).
fn skip_dns_name(data: &[u8], mut offset: usize) -> usize {
    let mut iterations = 0;
    loop {
        iterations += 1;
        if iterations > 128 || offset >= data.len() {
            return offset;
        }

        let len = data[offset];

        if len == 0 {
            return offset + 1;
        }

        if (len & 0xC0) == 0xC0 {
            return offset + 2; // Pointer is 2 bytes
        }

        offset += 1 + len as usize;
    }
}
