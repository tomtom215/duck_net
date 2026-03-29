// SPDX-License-Identifier: MIT
// Copyright 2026 Tom F. <tomf@tomtomtech.net> (https://github.com/tomtom215)

use std::net::UdpSocket;
use std::time::Duration;

const IPMI_PORT: u16 = 623;
const TIMEOUT_SECS: u64 = 5;
const MAX_RESPONSE_SIZE: usize = 1024;

pub struct IpmiResult {
    pub success: bool,
    pub data: String,
    pub completion_code: u8,
    pub message: String,
}

pub struct IpmiChassisStatus {
    pub success: bool,
    pub power_on: bool,
    pub power_overload: bool,
    pub interlock: bool,
    pub power_fault: bool,
    pub power_control_fault: bool,
    pub power_restore_policy: String,
    pub last_power_event: String,
    pub message: String,
}

pub struct IpmiSensorResult {
    pub success: bool,
    pub device_id: u8,
    pub device_revision: u8,
    pub firmware_major: u8,
    pub firmware_minor: u8,
    pub ipmi_version: String,
    pub manufacturer_id: u32,
    pub product_id: u16,
    pub message: String,
}

fn is_valid_host(host: &str) -> bool {
    if host.is_empty() || host.len() > 253 {
        return false;
    }
    // Only allow alphanumeric, dots, hyphens, colons (for IPv6), and brackets
    host.chars().all(|c| {
        c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == ':' || c == '[' || c == ']'
    })
}

/// Compute the IPMI two's-complement checksum over a byte slice.
/// The checksum is the value that, when added to the sum of all bytes, yields 0 (mod 256).
fn ipmi_checksum(data: &[u8]) -> u8 {
    let sum: u8 = data.iter().fold(0u8, |acc, &b| acc.wrapping_add(b));
    (!sum).wrapping_add(1)
}

/// Build a complete RMCP + IPMI v1.5 (unauthenticated) request packet.
fn build_ipmi_request(netfn: u8, cmd: u8, data: &[u8]) -> Vec<u8> {
    let mut packet = vec![
        0x06, // RMCP Version
        0x00, // Reserved
        0xFF, // Sequence number
        0x07, // Class: IPMI
    ];

    // --- IPMI Session Header (unauthenticated, v1.5) ---
    packet.push(0x00); // Auth Type: None
    packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // Session Sequence: 0
    packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // Session ID: 0

    // Message length: target_addr(1) + netfn_lun(1) + hdr_checksum(1) +
    //                 source_addr(1) + src_lun_seq(1) + cmd(1) + data(N) + data_checksum(1)
    let msg_len: u8 = (7 + data.len()) as u8;
    packet.push(msg_len);

    // --- IPMI Message ---
    let target_addr: u8 = 0x20; // BMC slave address
    let netfn_lun: u8 = netfn << 2; // LUN = 0

    packet.push(target_addr);
    packet.push(netfn_lun);

    // Header checksum (over target_addr and netfn_lun)
    let hdr_cksum = ipmi_checksum(&[target_addr, netfn_lun]);
    packet.push(hdr_cksum);

    let source_addr: u8 = 0x81; // Remote console
    let src_lun_seq: u8 = 0x00; // Seq=0, LUN=0

    packet.push(source_addr);
    packet.push(src_lun_seq);
    packet.push(cmd);

    // Command-specific data
    packet.extend_from_slice(data);

    // Data checksum (over source_addr, src_lun_seq, cmd, and data)
    let mut cksum_data = vec![source_addr, src_lun_seq, cmd];
    cksum_data.extend_from_slice(data);
    let data_cksum = ipmi_checksum(&cksum_data);
    packet.push(data_cksum);

    packet
}

/// Parse an RMCP + IPMI response packet.
/// Returns the completion code and the response data bytes on success.
fn parse_ipmi_response(buf: &[u8]) -> Result<(u8, Vec<u8>), String> {
    // Minimum response: RMCP(4) + Session(10) + IPMI header(7, including checksums) = 21
    if buf.len() < 21 {
        return Err(format!(
            "Response too short: {} bytes (minimum 21)",
            buf.len()
        ));
    }

    // Validate RMCP header
    if buf[0] != 0x06 {
        return Err(format!("Invalid RMCP version: 0x{:02X}", buf[0]));
    }
    if buf[3] != 0x07 {
        return Err(format!(
            "Invalid RMCP class: 0x{:02X} (expected 0x07)",
            buf[3]
        ));
    }

    // IPMI session header starts at offset 4
    // Auth type at offset 4 (should be 0x00 for none)
    // Session seq at offsets 5..9
    // Session ID at offsets 9..13
    // Message length at offset 13
    let msg_len = buf[13] as usize;

    // IPMI message starts at offset 14
    let msg_start = 14;
    if buf.len() < msg_start + msg_len {
        return Err(format!(
            "Response truncated: have {} bytes, need {}",
            buf.len(),
            msg_start + msg_len
        ));
    }

    let msg = &buf[msg_start..msg_start + msg_len];

    // msg[0] = responder address
    // msg[1] = netfn/lun
    // msg[2] = header checksum
    // msg[3] = requester address
    // msg[4] = seq/lun
    // msg[5] = command
    // msg[6] = completion code
    // msg[7..msg_len-1] = response data
    // msg[msg_len-1] = data checksum

    if msg.len() < 8 {
        return Err(format!(
            "IPMI message too short: {} bytes (minimum 8)",
            msg.len()
        ));
    }

    let completion_code = msg[6];

    // Response data is everything between completion code and data checksum
    let resp_data = if msg.len() > 8 {
        msg[7..msg.len() - 1].to_vec()
    } else {
        Vec::new()
    };

    Ok((completion_code, resp_data))
}

/// Send an IPMI command over RMCP/UDP and return the parsed response.
fn send_ipmi(host: &str, netfn: u8, cmd: u8, data: &[u8]) -> Result<(u8, Vec<u8>), String> {
    if !is_valid_host(host) {
        return Err(format!("Invalid host: {host}"));
    }
    // SSRF protection: block connections to private/reserved IPs (CWE-918)
    crate::security::validate_no_ssrf_host(host)?;

    let addr = format!("{host}:{IPMI_PORT}");

    let socket =
        UdpSocket::bind("0.0.0.0:0").map_err(|e| format!("Failed to bind UDP socket: {e}"))?;
    socket
        .set_read_timeout(Some(Duration::from_secs(TIMEOUT_SECS)))
        .map_err(|e| format!("Failed to set timeout: {e}"))?;

    let packet = build_ipmi_request(netfn, cmd, data);

    socket
        .send_to(&packet, &addr)
        .map_err(|e| format!("Failed to send IPMI request: {e}"))?;

    let mut response = [0u8; MAX_RESPONSE_SIZE];
    let (size, _) = socket
        .recv_from(&mut response)
        .map_err(|e| format!("Failed to receive IPMI response: {e}"))?;

    parse_ipmi_response(&response[..size])
}

/// Send a Get Device ID command (NetFn=App 0x06, Cmd=0x01) and parse the response.
pub fn get_device_id(host: &str) -> IpmiSensorResult {
    let fail = |msg: String| IpmiSensorResult {
        success: false,
        device_id: 0,
        device_revision: 0,
        firmware_major: 0,
        firmware_minor: 0,
        ipmi_version: String::new(),
        manufacturer_id: 0,
        product_id: 0,
        message: msg,
    };

    let (cc, data) = match send_ipmi(host, 0x06, 0x01, &[]) {
        Ok(v) => v,
        Err(e) => return fail(e),
    };

    if cc != 0x00 {
        return fail(format!("Command failed with completion code: 0x{cc:02X}"));
    }

    // Get Device ID response data:
    //   [0] Device ID
    //   [1] Device Revision (bits 3:0), provides SDRs (bit 7)
    //   [2] Firmware Revision 1 (major, bits 6:0), device available (bit 7)
    //   [3] Firmware Revision 2 (minor, BCD)
    //   [4] IPMI Version (BCD, e.g. 0x20 = 2.0)
    //   [5] Additional Device Support
    //   [6..8] Manufacturer ID (3 bytes, LS first)
    //   [9..10] Product ID (2 bytes, LS first)
    if data.len() < 11 {
        return fail(format!(
            "Get Device ID response too short: {} bytes (expected at least 11)",
            data.len()
        ));
    }

    let device_id = data[0];
    let device_revision = data[1] & 0x0F;
    let firmware_major = data[2] & 0x7F;
    let firmware_minor = data[3];
    let ipmi_ver_major = (data[4] >> 4) & 0x0F;
    let ipmi_ver_minor = data[4] & 0x0F;
    let ipmi_version = format!("{ipmi_ver_major}.{ipmi_ver_minor}");
    let manufacturer_id = (data[6] as u32) | ((data[7] as u32) << 8) | ((data[8] as u32) << 16);
    let product_id = (data[9] as u16) | ((data[10] as u16) << 8);

    IpmiSensorResult {
        success: true,
        device_id,
        device_revision,
        firmware_major,
        firmware_minor,
        ipmi_version,
        manufacturer_id,
        product_id,
        message: format!(
            "Device ID: 0x{device_id:02X}, FW: {firmware_major}.{firmware_minor:02X}, \
             IPMI {ipmi_ver_major}.{ipmi_ver_minor}, Manufacturer: 0x{manufacturer_id:06X}, \
             Product: 0x{product_id:04X}"
        ),
    }
}

/// Send a Get Chassis Status command (NetFn=Chassis 0x00, Cmd=0x01) and parse the response.
pub fn get_chassis_status(host: &str) -> IpmiChassisStatus {
    let fail = |msg: String| IpmiChassisStatus {
        success: false,
        power_on: false,
        power_overload: false,
        interlock: false,
        power_fault: false,
        power_control_fault: false,
        power_restore_policy: String::new(),
        last_power_event: String::new(),
        message: msg,
    };

    let (cc, data) = match send_ipmi(host, 0x00, 0x01, &[]) {
        Ok(v) => v,
        Err(e) => return fail(e),
    };

    if cc != 0x00 {
        return fail(format!("Command failed with completion code: 0x{cc:02X}"));
    }

    // Get Chassis Status response data:
    //   [0] Current Power State
    //       bit 0: power is on
    //       bit 1: power overload
    //       bit 2: interlock
    //       bit 3: power fault
    //       bit 4: power control fault
    //       bits 6:5: power restore policy (00=off, 01=restore, 10=always on, 11=unknown)
    //   [1] Last Power Event
    //   [2] Misc Chassis State
    if data.len() < 3 {
        return fail(format!(
            "Get Chassis Status response too short: {} bytes (expected at least 3)",
            data.len()
        ));
    }

    let current_power = data[0];
    let power_on = (current_power & 0x01) != 0;
    let power_overload = (current_power & 0x02) != 0;
    let interlock = (current_power & 0x04) != 0;
    let power_fault = (current_power & 0x08) != 0;
    let power_control_fault = (current_power & 0x10) != 0;

    let policy_bits = (current_power >> 5) & 0x03;
    let power_restore_policy = match policy_bits {
        0x00 => "always off".to_string(),
        0x01 => "restore previous state".to_string(),
        0x02 => "always on".to_string(),
        _ => "unknown".to_string(),
    };

    let last_event = data[1];
    let mut events = Vec::new();
    if last_event & 0x01 != 0 {
        events.push("AC failed");
    }
    if last_event & 0x02 != 0 {
        events.push("power overload");
    }
    if last_event & 0x04 != 0 {
        events.push("power interlock");
    }
    if last_event & 0x08 != 0 {
        events.push("power fault");
    }
    if last_event & 0x10 != 0 {
        events.push("IPMI command");
    }
    let last_power_event = if events.is_empty() {
        "none".to_string()
    } else {
        events.join(", ")
    };

    let power_state_str = if power_on { "on" } else { "off" };
    let message = format!(
        "Chassis power is {power_state_str}, restore policy: {power_restore_policy}, \
         last event: {last_power_event}"
    );

    IpmiChassisStatus {
        success: true,
        power_on,
        power_overload,
        interlock,
        power_fault,
        power_control_fault,
        power_restore_policy,
        last_power_event,
        message,
    }
}

/// Send a Chassis Control command (NetFn=Chassis 0x00, Cmd=0x02).
///
/// Valid actions: "power_off", "power_on", "power_cycle", "hard_reset",
/// "pulse_diag", "soft_shutdown".
pub fn chassis_control(host: &str, action: &str) -> IpmiResult {
    let fail = |msg: String| IpmiResult {
        success: false,
        data: String::new(),
        completion_code: 0xFF,
        message: msg,
    };

    let control_byte: u8 = match action {
        "power_off" => 0x00,
        "power_on" => 0x01,
        "power_cycle" => 0x02,
        "hard_reset" => 0x03,
        "pulse_diag" => 0x04,
        "soft_shutdown" => 0x05,
        _ => {
            return fail(format!(
                "Invalid chassis control action: '{action}'. \
                 Valid actions: power_off, power_on, power_cycle, hard_reset, \
                 pulse_diag, soft_shutdown"
            ));
        }
    };

    let (cc, _data) = match send_ipmi(host, 0x00, 0x02, &[control_byte]) {
        Ok(v) => v,
        Err(e) => return fail(e),
    };

    if cc != 0x00 {
        return fail(format!("Command failed with completion code: 0x{cc:02X}"));
    }

    IpmiResult {
        success: true,
        data: format!("Chassis control '{action}' sent successfully"),
        completion_code: cc,
        message: format!("Chassis control command '{action}' completed (code: 0x{cc:02X})"),
    }
}
