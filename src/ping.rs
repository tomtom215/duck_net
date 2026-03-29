use std::process::Command;

pub struct PingResult {
    pub alive: bool,
    pub latency_ms: f64,
    pub ttl: i32,
    pub message: String,
}

/// Ping a host using the system `ping` command.
///
/// Uses `ping -c 1` on Linux/macOS. Falls back gracefully if ping is not available.
pub fn ping(host: &str, timeout_secs: u32) -> PingResult {
    // Validate host to prevent command injection
    if !is_valid_host(host) {
        return PingResult {
            alive: false,
            latency_ms: -1.0,
            ttl: 0,
            message: format!("Invalid host: {host}"),
        };
    }

    let timeout = timeout_secs.max(1).min(30);

    let output = Command::new("ping")
        .args(["-c", "1", "-W", &timeout.to_string(), host])
        .output();

    match output {
        Ok(out) => {
            let stdout = String::from_utf8_lossy(&out.stdout).to_string();
            let stderr = String::from_utf8_lossy(&out.stderr).to_string();
            let alive = out.status.success();

            let latency_ms = parse_latency(&stdout);
            let ttl = parse_ttl(&stdout);

            PingResult {
                alive,
                latency_ms,
                ttl,
                message: if alive {
                    format!("Reply from {host}: time={latency_ms:.1}ms ttl={ttl}")
                } else {
                    format!(
                        "Host unreachable: {}",
                        if stderr.is_empty() { &stdout } else { &stderr }
                    )
                    .trim()
                    .to_string()
                },
            }
        }
        Err(e) => PingResult {
            alive: false,
            latency_ms: -1.0,
            ttl: 0,
            message: format!("Failed to execute ping: {e}"),
        },
    }
}

/// Traceroute to a host.
pub struct TracerouteHop {
    pub hop: i32,
    pub ip: String,
    pub hostname: String,
    pub latency_ms: f64,
}

pub fn traceroute(host: &str, max_hops: u32) -> Result<Vec<TracerouteHop>, String> {
    if !is_valid_host(host) {
        return Err(format!("Invalid host: {host}"));
    }

    let max_hops = max_hops.max(1).min(64);

    let output = Command::new("traceroute")
        .args(["-m", &max_hops.to_string(), "-w", "3", "-n", host])
        .output()
        .map_err(|e| format!("Failed to execute traceroute: {e}"))?;

    let stdout = String::from_utf8_lossy(&output.stdout);

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("traceroute failed: {stderr}"));
    }

    let mut hops = Vec::new();

    for line in stdout.lines().skip(1) {
        // Skip header
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 2 {
            continue;
        }

        let hop_num = match parts[0].parse::<i32>() {
            Ok(n) => n,
            Err(_) => continue,
        };

        if parts[1] == "*" {
            hops.push(TracerouteHop {
                hop: hop_num,
                ip: "*".to_string(),
                hostname: "*".to_string(),
                latency_ms: -1.0,
            });
            continue;
        }

        let ip = parts[1].to_string();
        let latency = parts
            .iter()
            .find_map(|p| {
                if p.ends_with("ms") || p.parse::<f64>().is_ok() {
                    p.trim_end_matches("ms").parse::<f64>().ok()
                } else {
                    None
                }
            })
            .unwrap_or(-1.0);

        hops.push(TracerouteHop {
            hop: hop_num,
            ip: ip.clone(),
            hostname: ip,
            latency_ms: latency,
        });
    }

    Ok(hops)
}

/// Validate a hostname/IP to prevent command injection.
fn is_valid_host(host: &str) -> bool {
    if host.is_empty() || host.len() > 253 {
        return false;
    }
    // Only allow alphanumeric, dots, hyphens, colons (for IPv6), and brackets
    host.chars().all(|c| {
        c.is_ascii_alphanumeric()
            || c == '.'
            || c == '-'
            || c == ':'
            || c == '['
            || c == ']'
    })
}

/// Parse latency from ping output (e.g., "time=12.3 ms" or "time=12.3ms").
fn parse_latency(output: &str) -> f64 {
    if let Some(pos) = output.find("time=") {
        let rest = &output[pos + 5..];
        let num_str: String = rest
            .chars()
            .take_while(|c| c.is_ascii_digit() || *c == '.')
            .collect();
        num_str.parse::<f64>().unwrap_or(-1.0)
    } else {
        -1.0
    }
}

/// Parse TTL from ping output (e.g., "ttl=64" or "TTL=64").
fn parse_ttl(output: &str) -> i32 {
    let lower = output.to_ascii_lowercase();
    if let Some(pos) = lower.find("ttl=") {
        let rest = &output[pos + 4..];
        let num_str: String = rest
            .chars()
            .take_while(|c| c.is_ascii_digit())
            .collect();
        num_str.parse::<i32>().unwrap_or(0)
    } else {
        0
    }
}
