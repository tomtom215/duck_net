// SPDX-License-Identifier: MIT
// Copyright 2026 Tom F. <tomf@tomtomtech.net> (https://github.com/tomtom215)

//! Protocol feature gating.
//!
//! duck_net registers only its **core web** protocol set by default.
//! Every other protocol must be explicitly opted in via a plain-text
//! config file before the extension is loaded.
//!
//! # Config file locations (first found wins)
//!
//! 1. `$DUCK_NET_CONFIG` — environment variable pointing to any path
//! 2. `~/.config/duck_net/protocols` — XDG-style location
//! 3. `~/.duck_net_protocols` — simple dotfile fallback
//!
//! # File format
//!
//! One protocol name per line.  Lines beginning with `#` and blank lines
//! are ignored.  Protocol names are case-insensitive.
//!
//! ```text
//! # Enable SSH remote execution and email
//! ssh
//! smtp
//! imap
//! ```
//!
//! Run `SELECT duck_net_generate_config();` from DuckDB to print a fully
//! commented template you can drop straight into the config file.

use std::collections::HashSet;
use std::sync::OnceLock;

// ---------------------------------------------------------------------------
// Protocol catalogue
// ---------------------------------------------------------------------------

/// Protocols that are **always** registered, regardless of configuration.
///
/// Confined to HTTP and its direct supporting cast: TLS, DNS, OAuth2, and
/// the security / secrets infrastructure that applies universally.
pub const CORE_PROTOCOLS: &[(&str, &str)] = &[
    (
        "scalars",
        "HTTP GET / POST / PUT / DELETE / HEAD / PATCH / OPTIONS",
    ),
    ("table", "HTTP pagination helpers"),
    ("soap", "SOAP / HTTP web services"),
    ("graphql", "GraphQL over HTTP"),
    ("oauth2", "OAuth2 client-credentials token acquisition"),
    ("tls_inspect", "TLS certificate inspection"),
    ("ocsp", "OCSP certificate revocation (used by tls_inspect)"),
    ("dns", "DNS lookups (A, AAAA, MX, TXT, PTR)"),
    ("doh", "DNS-over-HTTPS"),
    ("whois", "WHOIS domain lookups"),
    (
        "scalars_config",
        "Runtime configuration: timeouts, retries, rate limits",
    ),
    ("secrets", "In-process credentials store"),
    (
        "secrets_protocols",
        "HTTP / DNS authenticated helpers (http_get_secret, …)",
    ),
    (
        "secrets_protocols_ext",
        "Extended authenticated helpers (s3_get_secret, …)",
    ),
    ("security_warnings", "Security warning subsystem"),
    ("audit_log", "Audit logging subsystem"),
    ("duckdb_secrets_bridge", "DuckDB secrets-manager bridge"),
];

/// Every opt-in protocol: `(config_name, description)`.
///
/// `config_name` is the token users write in the config file.
pub const OPT_IN_PROTOCOLS: &[(&str, &str)] = &[
    ("smtp", "Send email via SMTP"),
    ("imap", "Read / manage email via IMAP"),
    ("ftp", "File Transfer Protocol (FTP / FTPS)"),
    ("sftp", "SSH File Transfer Protocol (SFTP)"),
    ("ssh", "SSH remote command execution and SCP"),
    ("websocket", "WebSocket connections"),
    ("grpc", "gRPC remote procedure calls"),
    ("redis", "Redis key-value store"),
    ("memcached", "Memcached in-memory cache"),
    ("elasticsearch", "Elasticsearch full-text search"),
    ("influxdb", "InfluxDB time-series database"),
    ("s3", "S3-compatible object storage"),
    ("kafka", "Apache Kafka message streaming"),
    ("amqp", "AMQP message queues (RabbitMQ, etc.)"),
    ("mqtt", "MQTT IoT messaging"),
    ("nats", "NATS cloud-native messaging"),
    ("zeromq", "ZeroMQ messaging"),
    ("ldap", "LDAP / Active Directory queries"),
    ("snmp", "SNMP network device monitoring"),
    ("consul", "HashiCorp Consul service discovery"),
    ("vault", "HashiCorp Vault secrets management"),
    ("ping", "ICMP ping and traceroute"),
    ("ipmi", "IPMI bare-metal hardware management"),
    ("radius", "RADIUS authentication"),
    ("bgp", "BGP routing data (read-only)"),
    ("mdns", "mDNS / Bonjour local service discovery"),
    ("stun", "STUN NAT traversal probing"),
    ("ptp", "IEEE 1588 Precision Time Protocol"),
    ("sip", "SIP VoIP signalling"),
    ("caldav", "CalDAV / CardDAV calendars and contacts"),
    ("syslog", "Syslog log forwarding"),
    ("odata", "OData REST API queries"),
    ("jsonrpc", "JSON-RPC calls"),
    ("webdav", "WebDAV file access"),
    ("aws_sigv4", "AWS Signature Version 4 request signing"),
    ("prometheus", "Prometheus metrics queries"),
    ("ntp", "Network Time Protocol"),
];

// ---------------------------------------------------------------------------
// Internal state
// ---------------------------------------------------------------------------

struct FeatureState {
    /// The opt-in protocols explicitly requested in the config file.
    enabled: HashSet<String>,
    /// Human-readable description of where the config came from.
    config_path: String,
}

static STATE: OnceLock<FeatureState> = OnceLock::new();

// ---------------------------------------------------------------------------
// Config file helpers
// ---------------------------------------------------------------------------

fn resolve_config_path() -> Option<std::path::PathBuf> {
    // 1. Explicit environment variable override.
    if let Ok(v) = std::env::var("DUCK_NET_CONFIG") {
        if !v.is_empty() {
            return Some(std::path::PathBuf::from(v));
        }
    }

    let home = std::env::var_os("HOME")?;
    let home = std::path::Path::new(&home);

    // 2. XDG-style: ~/.config/duck_net/protocols
    let xdg = home.join(".config/duck_net/protocols");
    if xdg.exists() {
        return Some(xdg);
    }

    // 3. Simple dotfile fallback: ~/.duck_net_protocols
    let dot = home.join(".duck_net_protocols");
    if dot.exists() {
        return Some(dot);
    }

    None
}

fn parse_protocol_list(text: &str) -> HashSet<String> {
    let all_known: HashSet<&str> = OPT_IN_PROTOCOLS
        .iter()
        .map(|(n, _)| *n)
        .chain(CORE_PROTOCOLS.iter().map(|(n, _)| *n))
        .collect();

    let mut parsed: HashSet<String> = HashSet::new();
    let mut unknown: Vec<String> = Vec::new();
    for raw in text.lines() {
        let trimmed = raw.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let name = trimmed.to_lowercase();
        if all_known.contains(name.as_str()) {
            parsed.insert(name);
        } else {
            unknown.push(name);
        }
    }

    if !unknown.is_empty() {
        eprintln!(
            "[duck_net] WARNING: unknown protocol name(s) in config file: {} — \
             typos or legacy names are silently ignored. Run \
             SELECT duck_net_generate_config(); to see valid names.",
            unknown.join(", ")
        );
    }

    parsed
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Initialise the feature gate.  Must be called once from `ffi::register_all`
/// before any `is_enabled` query.
pub fn init() {
    STATE.get_or_init(|| match resolve_config_path() {
        Some(path) => {
            let config_path = path.display().to_string();
            let enabled = std::fs::read_to_string(&path)
                .map(|t| parse_protocol_list(&t))
                .unwrap_or_default();
            FeatureState {
                enabled,
                config_path,
            }
        }
        None => FeatureState {
            enabled: HashSet::new(),
            config_path: "none — place a protocol list at \
                          ~/.config/duck_net/protocols or ~/.duck_net_protocols"
                .to_string(),
        },
    });
}

/// Returns `true` if `protocol` should be registered.
///
/// Core protocols always return `true`.  All others require an explicit
/// entry in the config file (case-insensitive).
pub fn is_enabled(protocol: &str) -> bool {
    // Core is unconditional.
    if CORE_PROTOCOLS.iter().any(|(name, _)| *name == protocol) {
        return true;
    }
    STATE
        .get()
        .map(|s| s.enabled.contains(protocol))
        .unwrap_or(false)
}

/// Path (or advisory message) for the config file that was consulted.
pub fn config_path() -> &'static str {
    STATE
        .get()
        .map(|s| s.config_path.as_str())
        .unwrap_or("not initialized — call features::init() first")
}

/// Snapshot of every opt-in protocol and whether it is currently enabled.
pub fn status_snapshot() -> Vec<(&'static str, &'static str, bool)> {
    OPT_IN_PROTOCOLS
        .iter()
        .map(|(name, desc)| (*name, *desc, is_enabled(name)))
        .collect()
}

/// Generate a fully-commented sample config file listing every opt-in protocol.
pub fn generate_sample_config() -> String {
    let mut out = String::from(
        "# duck_net protocol configuration\n\
         # ─────────────────────────────────────────────────────────────────\n\
         # Place this file at:  ~/.config/duck_net/protocols\n\
         #                  or: ~/.duck_net_protocols\n\
         # Override the path:   export DUCK_NET_CONFIG=/path/to/file\n\
         #\n\
         # One protocol name per uncommented line enables that protocol.\n\
         # Reload DuckDB (or re-LOAD the extension) for changes to take effect.\n\
         #\n\
         # Core web protocols are always enabled and must not be listed here:\n\
         #   HTTP, HTTPS/TLS, DNS, DoH, SOAP, GraphQL, OAuth2, WHOIS,\n\
         #   secrets manager, security warnings, audit log.\n\
         # ─────────────────────────────────────────────────────────────────\n\n",
    );

    let categories: &[(&str, &[&str])] = &[
        ("Email", &["smtp", "imap"]),
        ("File transfer", &["ftp", "sftp"]),
        ("Remote execution", &["ssh"]),
        (
            "Web / RPC",
            &[
                "websocket",
                "grpc",
                "jsonrpc",
                "odata",
                "webdav",
                "aws_sigv4",
            ],
        ),
        (
            "Databases & stores",
            &["redis", "memcached", "elasticsearch", "influxdb", "s3"],
        ),
        (
            "Message queues",
            &["kafka", "amqp", "mqtt", "nats", "zeromq"],
        ),
        ("Directory & auth", &["ldap", "snmp", "radius"]),
        ("Service mesh", &["consul", "vault", "prometheus"]),
        (
            "Network tools",
            &["ping", "bgp", "mdns", "stun", "ntp", "ptp"],
        ),
        ("Hardware", &["ipmi"]),
        ("Comms / IoT", &["sip", "caldav", "syslog"]),
    ];

    for (category, names) in categories {
        out.push_str(&format!("# ── {category}\n"));
        for name in *names {
            if let Some((_, desc)) = OPT_IN_PROTOCOLS.iter().find(|(n, _)| n == name) {
                out.push_str(&format!("# {name:<16}  {desc}\n# {name}\n"));
            }
        }
        out.push('\n');
    }

    out
}
