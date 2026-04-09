// SPDX-License-Identifier: MIT
// Copyright 2026 Tom F. <tomf@tomtomtech.net> (https://github.com/tomtom215)

mod amqp;
mod audit_log;
mod aws_sigv4;
mod bgp;
mod caldav;
mod consul;
pub(crate) mod dns;
mod doh;
mod duckdb_secrets_bridge;
mod elasticsearch;
mod features;
mod ftp;
mod graphql;
mod grpc;
mod imap;
mod influxdb;
mod ipmi;
mod jsonrpc;
mod kafka;
mod ldap;
mod mdns;
mod memcached;
mod mqtt;
mod nats;
mod ntp;
mod oauth2;
mod ocsp;
mod odata;
mod ping;
mod prometheus;
mod ptp;
mod radius;
mod redis_client;
mod s3;
pub(crate) mod scalars;
mod scalars_config;
mod secrets;
mod secrets_protocols;
mod secrets_protocols_ext;
mod security_warnings;
mod sftp;
mod sip;
mod smtp;
mod snmp;
mod soap;
mod ssh;
mod stun;
mod syslog;
mod table;
mod tls_inspect;
mod vault;
mod webdav;
mod websocket;
mod whois;
mod zeromq;

use quack_rs::prelude::*;

/// Inspect `~/.duckdb/stored_secrets/` at extension load time and emit a
/// security warning if it is present, non-empty, or world-readable. The
/// directory is created by DuckDB's secrets manager for persistent secrets
/// (CREATE PERSISTENT SECRET …) which are stored in unencrypted binary
/// form (CWE-312).
fn warn_if_persistent_secrets_present() {
    let Some(home) = std::env::var_os("HOME") else {
        return;
    };
    let path = std::path::Path::new(&home).join(".duckdb/stored_secrets");
    let Ok(meta) = std::fs::metadata(&path) else {
        return;
    };
    if !meta.is_dir() {
        return;
    }

    // Count entries (cheap; directory usually has 0..few files).
    let entry_count = std::fs::read_dir(&path).map(|d| d.count()).unwrap_or(0);

    #[cfg(unix)]
    let mode = {
        use std::os::unix::fs::PermissionsExt;
        meta.permissions().mode() & 0o777
    };
    #[cfg(not(unix))]
    let mode: u32 = 0o700;

    if entry_count > 0 || (mode & 0o077) != 0 {
        let extra = if (mode & 0o077) != 0 {
            format!(" (permissions {mode:04o} allow access beyond the owner)")
        } else {
            String::new()
        };
        eprintln!(
            "[duck_net] WARNING: DuckDB persistent-secrets directory {} contains {} entry(ies){}. \
             Persistent secrets are stored in UNENCRYPTED binary form. Prefer duck_net_add_secret() \
             for in-memory, zeroized credentials. CWE-312.",
            path.display(),
            entry_count,
            extra
        );
        crate::security_warnings::warn_persistent_secret_unencrypted();
    }
}

/// Convenience macro: only call `$module::register_all(con)?` when the named
/// opt-in protocol is present in the user's config file.
macro_rules! register_if_enabled {
    ($feature:literal, $module:ident, $con:expr) => {
        if crate::features::is_enabled($feature) {
            $module::register_all($con)?;
        }
    };
}

pub fn register_all(con: &Connection) -> Result<(), ExtensionError> {
    // 1. Initialise the feature gate first so every subsequent is_enabled
    //    query reflects the user's config file.
    crate::features::init();

    // 2. Initialise the async runtime and DNS resolver.  Failures surface as
    //    a DuckDB load error rather than a panic later.
    crate::runtime::init().map_err(ExtensionError::new)?;
    crate::dns::init().map_err(ExtensionError::new)?;

    // 3. Initialise audit log and security warning subsystems.
    crate::audit_log::init();
    crate::security_warnings::init();

    // 4. Check whether DuckDB's persistent secrets directory exists and warn
    //    if it is present, non-empty, or has lax permissions. Persistent
    //    secrets created via `CREATE PERSISTENT SECRET` are stored in
    //    unencrypted binary form on disk (CWE-312). This lets duck_net alert
    //    operators before their first query, independent of whether they call
    //    duck_net_secret().
    warn_if_persistent_secrets_present();

    unsafe {
        // ── Core web (always on) ──────────────────────────────────────────
        // HTTP, TLS, DNS, OAuth2, secrets, and all security infrastructure.
        // These are registered unconditionally; they are the whole reason
        // this extension exists.
        scalars::register_all(con)?;
        soap::register_all(con)?;
        table::register_all(con)?;
        graphql::register_all(con)?;
        oauth2::register_all(con)?;
        tls_inspect::register_all(con)?;
        ocsp::register_all(con)?;
        dns::register_all(con)?;
        doh::register_all(con)?;
        whois::register_all(con)?;
        scalars_config::register_all(con)?;
        secrets::register_all(con)?;
        secrets_protocols::register_all(con)?;
        secrets_protocols_ext::register_all(con)?;
        security_warnings::register_all(con)?;
        audit_log::register_all(con)?;
        duckdb_secrets_bridge::register_all(con)?;

        // Feature introspection (always on — users need this to discover
        // what is available and how to enable it).
        features::register_all(con)?;

        // ── Opt-in protocols ──────────────────────────────────────────────
        // Each protocol is registered only when the user has listed its name
        // in their duck_net config file.  See `SELECT duck_net_generate_config()`
        // for a ready-to-use template.

        // Email
        register_if_enabled!("smtp", smtp, con);
        register_if_enabled!("imap", imap, con);

        // File transfer
        register_if_enabled!("ftp", ftp, con);
        register_if_enabled!("sftp", sftp, con);

        // Remote execution
        register_if_enabled!("ssh", ssh, con);

        // Web / RPC
        register_if_enabled!("websocket", websocket, con);
        register_if_enabled!("grpc", grpc, con);
        register_if_enabled!("jsonrpc", jsonrpc, con);
        register_if_enabled!("odata", odata, con);
        register_if_enabled!("webdav", webdav, con);
        register_if_enabled!("aws_sigv4", aws_sigv4, con);

        // Databases & stores
        register_if_enabled!("redis", redis_client, con);
        register_if_enabled!("memcached", memcached, con);
        register_if_enabled!("elasticsearch", elasticsearch, con);
        register_if_enabled!("influxdb", influxdb, con);
        register_if_enabled!("s3", s3, con);

        // Message queues
        register_if_enabled!("kafka", kafka, con);
        register_if_enabled!("amqp", amqp, con);
        register_if_enabled!("mqtt", mqtt, con);
        register_if_enabled!("nats", nats, con);
        register_if_enabled!("zeromq", zeromq, con);

        // Directory & auth
        register_if_enabled!("ldap", ldap, con);
        register_if_enabled!("snmp", snmp, con);
        register_if_enabled!("radius", radius, con);

        // Service mesh
        register_if_enabled!("consul", consul, con);
        register_if_enabled!("vault", vault, con);
        register_if_enabled!("prometheus", prometheus, con);

        // Network tools
        register_if_enabled!("ping", ping, con);
        register_if_enabled!("bgp", bgp, con);
        register_if_enabled!("mdns", mdns, con);
        register_if_enabled!("stun", stun, con);
        register_if_enabled!("ntp", ntp, con);
        register_if_enabled!("ptp", ptp, con);

        // Hardware
        register_if_enabled!("ipmi", ipmi, con);

        // Comms / IoT / misc
        register_if_enabled!("sip", sip, con);
        register_if_enabled!("caldav", caldav, con);
        register_if_enabled!("syslog", syslog, con);
    }

    Ok(())
}
