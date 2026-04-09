// SPDX-License-Identifier: MIT
// Copyright 2026 Tom F. <tomf@tomtomtech.net> (https://github.com/tomtom215)

//! FFI bindings for the duck_net secrets manager and security configuration.

use quack_rs::prelude::*;

use crate::secrets;
use crate::security;

// ---------------------------------------------------------------------------
// Secrets Manager Callbacks
// ---------------------------------------------------------------------------

// duck_net_add_secret(name, type, config_json) -> VARCHAR
quack_rs::scalar_callback!(cb_add_secret, |_info, input, output| {
    let chunk = unsafe { DataChunk::from_raw(input) };
    let row_count = chunk.size();
    let name_reader = unsafe { chunk.reader(0) };
    let type_reader = unsafe { chunk.reader(1) };
    let config_reader = unsafe { chunk.reader(2) };
    let mut writer = unsafe { VectorWriter::from_vector(output) };

    for row in 0..row_count {
        let name = unsafe { name_reader.read_str(row) };
        let secret_type = unsafe { type_reader.read_str(row) };
        let config_json = unsafe { config_reader.read_str(row) };

        let msg = match secrets::add_secret(name, secret_type, config_json) {
            Ok(m) => m,
            Err(e) => format!("Error: {}", e),
        };
        unsafe { writer.write_varchar(row, &msg) };
    }
});

// duck_net_clear_secret(name) -> VARCHAR
quack_rs::scalar_callback!(cb_clear_secret, |_info, input, output| {
    let chunk = unsafe { DataChunk::from_raw(input) };
    let row_count = chunk.size();
    let name_reader = unsafe { chunk.reader(0) };
    let mut writer = unsafe { VectorWriter::from_vector(output) };

    for row in 0..row_count {
        let name = unsafe { name_reader.read_str(row) };
        let msg = match secrets::clear_secret(name) {
            Ok(m) => m,
            Err(e) => format!("Error: {}", e),
        };
        unsafe { writer.write_varchar(row, &msg) };
    }
});

// duck_net_clear_all_secrets() -> VARCHAR
quack_rs::scalar_callback!(cb_clear_all_secrets, |_info, _input, output| {
    let msg = secrets::clear_all_secrets();
    let mut writer = unsafe { VectorWriter::from_vector(output) };
    unsafe { writer.write_varchar(0, &msg) };
});

// duck_net_secret_type(name) -> VARCHAR
// Returns the type of a named secret, or NULL if not found.
quack_rs::scalar_callback!(cb_get_secret_type, |_info, input, output| {
    let chunk = unsafe { DataChunk::from_raw(input) };
    let row_count = chunk.size();
    let name_reader = unsafe { chunk.reader(0) };
    let mut writer = unsafe { VectorWriter::from_vector(output) };

    for row in 0..row_count {
        let name = unsafe { name_reader.read_str(row) };
        match secrets::get_type(name) {
            Some(stype) => unsafe { writer.write_varchar(row, &stype) },
            None => unsafe { writer.set_null(row) },
        }
    }
});

// duck_net_secret_redacted(name) -> VARCHAR
// Returns a JSON representation of a secret with sensitive values redacted.
quack_rs::scalar_callback!(cb_get_secret_redacted, |_info, input, output| {
    let chunk = unsafe { DataChunk::from_raw(input) };
    let row_count = chunk.size();
    let name_reader = unsafe { chunk.reader(0) };
    let mut writer = unsafe { VectorWriter::from_vector(output) };

    for row in 0..row_count {
        let name = unsafe { name_reader.read_str(row) };
        let msg = match secrets::get_redacted(name) {
            Some(redacted) => {
                let mut pairs: Vec<String> = redacted
                    .iter()
                    .map(|(k, v)| format!("\"{}\":\"{}\"", k, v.replace('"', "\\\"")))
                    .collect();
                pairs.sort(); // deterministic output
                format!("{{{}}}", pairs.join(","))
            }
            None => format!("Secret '{}' not found", name),
        };
        unsafe { writer.write_varchar(row, &msg) };
    }
});

// duck_net_rotate_secret(name, new_config_json) -> VARCHAR
// Atomically rotates a secret's configuration: zeroizes old values, replaces
// with new ones.  Secret type is preserved.  The existing secret is unchanged
// if parsing the new config fails.
quack_rs::scalar_callback!(cb_rotate_secret, |_info, input, output| {
    let chunk = unsafe { DataChunk::from_raw(input) };
    let row_count = chunk.size();
    let name_reader = unsafe { chunk.reader(0) };
    let config_reader = unsafe { chunk.reader(1) };
    let mut writer = unsafe { VectorWriter::from_vector(output) };

    for row in 0..row_count {
        let name = unsafe { name_reader.read_str(row) };
        let new_config_json = unsafe { config_reader.read_str(row) };

        let msg = match secrets::rotate_secret(name, new_config_json) {
            Ok(m) => m,
            Err(e) => format!("Error: {}", e),
        };
        unsafe { writer.write_varchar(row, &msg) };
    }
});

// duck_net_scrub_url(url) -> VARCHAR
// Scrub credentials from a URL for safe logging.
quack_rs::scalar_callback!(cb_scrub_url, |_info, input, output| {
    let chunk = unsafe { DataChunk::from_raw(input) };
    let row_count = chunk.size();
    let url_reader = unsafe { chunk.reader(0) };
    let mut writer = unsafe { VectorWriter::from_vector(output) };

    for row in 0..row_count {
        let url = unsafe { url_reader.read_str(row) };
        let scrubbed = security::scrub_url(url);
        unsafe { writer.write_varchar(row, &scrubbed) };
    }
});

// duck_net_scrub_error(msg) -> VARCHAR
// Scrub known credential patterns from an error message.
quack_rs::scalar_callback!(cb_scrub_error, |_info, input, output| {
    let chunk = unsafe { DataChunk::from_raw(input) };
    let row_count = chunk.size();
    let msg_reader = unsafe { chunk.reader(0) };
    let mut writer = unsafe { VectorWriter::from_vector(output) };

    for row in 0..row_count {
        let msg = unsafe { msg_reader.read_str(row) };
        let scrubbed = security::scrub_error(msg);
        unsafe { writer.write_varchar(row, &scrubbed) };
    }
});

// duck_net_secret(name, key) -> VARCHAR
// Returns a specific value from a named secret, or NULL if not found.
// NOTE: This function returns raw credential values as SQL results which may
// appear in query logs or exports. A security warning is emitted on first call.
quack_rs::scalar_callback!(cb_get_secret_value, |_info, input, output| {
    let chunk = unsafe { DataChunk::from_raw(input) };
    let row_count = chunk.size();
    let name_reader = unsafe { chunk.reader(0) };
    let key_reader = unsafe { chunk.reader(1) };
    let mut writer = unsafe { VectorWriter::from_vector(output) };

    for row in 0..row_count {
        let name = unsafe { name_reader.read_str(row) };
        let key = unsafe { key_reader.read_str(row) };

        // Emit warning: raw credential exposure in SQL results (CWE-312/CWE-532)
        crate::security_warnings::warn_secret_value_exposed(name);

        match secrets::get_value(name, key) {
            Some(value) => unsafe { writer.write_varchar(row, &value) },
            None => unsafe { writer.set_null(row) },
        }
    }
});

// ---------------------------------------------------------------------------
// Security Configuration Callbacks
// ---------------------------------------------------------------------------

// duck_net_set_ssrf_protection(enabled BOOLEAN) -> VARCHAR
quack_rs::scalar_callback!(cb_set_ssrf_protection, |_info, input, output| {
    let chunk = unsafe { DataChunk::from_raw(input) };
    let row_count = chunk.size();
    let bool_reader = unsafe { chunk.reader(0) };
    let mut writer = unsafe { VectorWriter::from_vector(output) };

    for row in 0..row_count {
        let enabled = unsafe { bool_reader.read_bool(row) };
        security::set_ssrf_protection(enabled);
        let msg = if enabled {
            "SSRF protection enabled: private/reserved IPs are blocked"
        } else {
            "SSRF protection disabled: all IPs are reachable (development mode)"
        };
        unsafe { writer.write_varchar(row, msg) };
    }
});

// duck_net_set_ssh_strict(enabled BOOLEAN) -> VARCHAR
quack_rs::scalar_callback!(cb_set_ssh_strict, |_info, input, output| {
    let chunk = unsafe { DataChunk::from_raw(input) };
    let row_count = chunk.size();
    let bool_reader = unsafe { chunk.reader(0) };
    let mut writer = unsafe { VectorWriter::from_vector(output) };

    for row in 0..row_count {
        let strict = unsafe { bool_reader.read_bool(row) };
        security::set_ssh_strict_commands(strict);
        let msg = if strict {
            "SSH strict mode enabled: shell metacharacters (;|&$`<>) are blocked in commands"
        } else {
            "SSH strict mode disabled: only null bytes and newlines are blocked in commands"
        };
        unsafe { writer.write_varchar(row, msg) };
    }
});

// duck_net_set_dns_block_private(enabled BOOLEAN) -> VARCHAR
quack_rs::scalar_callback!(cb_set_dns_block_private, |_info, input, output| {
    let chunk = unsafe { DataChunk::from_raw(input) };
    let row_count = chunk.size();
    let bool_reader = unsafe { chunk.reader(0) };
    let mut writer = unsafe { VectorWriter::from_vector(output) };

    for row in 0..row_count {
        let enabled = unsafe { bool_reader.read_bool(row) };
        security::set_dns_block_private(enabled);
        let msg = if enabled {
            "dns_lookup() filters private/reserved IP results (default; CWE-918)"
        } else {
            "dns_lookup() returns private/reserved IP results verbatim (warnings still emitted)"
        };
        unsafe { writer.write_varchar(row, msg) };
    }
});

// duck_net_set_egress_allowlist(patterns VARCHAR) -> VARCHAR
// Accepts comma-separated list of hostnames / patterns:
//   "api.example.com,*.internal.net,.trusted.org"
// An empty string clears the allowlist (reverts to deny-private-only mode).
quack_rs::scalar_callback!(cb_set_egress_allowlist, |_info, input, output| {
    let chunk = unsafe { DataChunk::from_raw(input) };
    let row_count = chunk.size();
    let patterns_reader = unsafe { chunk.reader(0) };
    let mut writer = unsafe { VectorWriter::from_vector(output) };

    for row in 0..row_count {
        let patterns = unsafe { patterns_reader.read_str(row) };
        let parsed: Vec<String> = patterns
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        let count = parsed.len();
        security::set_egress_allowlist(&parsed);
        let msg = if count == 0 {
            "Egress allowlist cleared (deny-private-only mode)".to_string()
        } else {
            format!("Egress allowlist set: {} pattern(s)", count)
        };
        unsafe { writer.write_varchar(row, &msg) };
    }
});

// duck_net_egress_allowlist() -> VARCHAR (comma-separated list, or empty)
quack_rs::scalar_callback!(cb_egress_allowlist, |_info, _input, output| {
    let list = security::egress_allowlist();
    let joined = list.join(",");
    let mut writer = unsafe { VectorWriter::from_vector(output) };
    unsafe { writer.write_varchar(0, &joined) };
});

// duck_net_set_ssh_tofu(mode VARCHAR) -> VARCHAR
// mode is one of 'strict', 'warn', or 'auto' (case-insensitive).
quack_rs::scalar_callback!(cb_set_ssh_tofu, |_info, input, output| {
    let chunk = unsafe { DataChunk::from_raw(input) };
    let row_count = chunk.size();
    let mode_reader = unsafe { chunk.reader(0) };
    let mut writer = unsafe { VectorWriter::from_vector(output) };

    for row in 0..row_count {
        let mode_str = unsafe { mode_reader.read_str(row) };
        let (mode, msg) = match mode_str.trim().to_ascii_lowercase().as_str() {
            "strict" => (
                Some(security::TofuMode::Strict),
                "SSH TOFU mode: strict — unknown hosts are rejected".to_string(),
            ),
            "warn" => (
                Some(security::TofuMode::Warn),
                "SSH TOFU mode: warn — unknown hosts are accepted per-session but not persisted"
                    .to_string(),
            ),
            "auto" => (
                Some(security::TofuMode::Auto),
                "SSH TOFU mode: auto — unknown hosts are accepted and persisted to ~/.ssh/known_hosts"
                    .to_string(),
            ),
            other => (
                None,
                format!("Error: invalid TOFU mode '{other}' — expected 'strict', 'warn', or 'auto'"),
            ),
        };
        if let Some(m) = mode {
            security::set_ssh_tofu_mode(m);
        }
        unsafe { writer.write_varchar(row, &msg) };
    }
});

// duck_net_set_protocol_acl(protocols VARCHAR) -> VARCHAR
// Accepts comma-separated protocol names. Empty string clears the ACL.
quack_rs::scalar_callback!(cb_set_protocol_acl, |_info, input, output| {
    let chunk = unsafe { DataChunk::from_raw(input) };
    let row_count = chunk.size();
    let list_reader = unsafe { chunk.reader(0) };
    let mut writer = unsafe { VectorWriter::from_vector(output) };

    for row in 0..row_count {
        let list_str = unsafe { list_reader.read_str(row) };
        let parsed: Vec<String> = list_str
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        let count = parsed.len();
        security::set_protocol_acl(&parsed);
        let msg = if count == 0 {
            "Runtime protocol ACL cleared (all registered protocols allowed)".to_string()
        } else {
            format!("Runtime protocol ACL set: {} protocol(s) allowed", count)
        };
        unsafe { writer.write_varchar(row, &msg) };
    }
});

// duck_net_protocol_acl() -> VARCHAR (comma-separated list, or empty)
quack_rs::scalar_callback!(cb_protocol_acl, |_info, _input, output| {
    let list = security::protocol_acl();
    let joined = list.join(",");
    let mut writer = unsafe { VectorWriter::from_vector(output) };
    unsafe { writer.write_varchar(0, &joined) };
});

// duck_net_security_status() -> VARCHAR
// Returns a JSON summary of current security configuration for auditing.
quack_rs::scalar_callback!(cb_security_status, |_info, _input, output| {
    let ssrf = security::ssrf_protection_enabled();
    let ssh_strict = security::ssh_strict_commands();
    let warnings_enabled = crate::security_warnings::warnings_enabled();
    let warnings_count = crate::security_warnings::list_warnings().len();
    let secrets_count = secrets::list_secrets().len();
    let rate_limit = crate::rate_limit::get_global_rps();
    let timeout = crate::http::get_timeout_secs();
    let retries = crate::http::get_max_retries();

    let status = format!(
        concat!(
            "{{",
            "\"ssrf_protection\":{},",
            "\"ssh_strict_commands\":{},",
            "\"security_warnings_enabled\":{},",
            "\"active_warnings\":{},",
            "\"secrets_stored\":{},",
            "\"global_rate_limit_rps\":{},",
            "\"http_timeout_secs\":{},",
            "\"http_max_retries\":{},",
            "\"zeroize_on_drop\":true,",
            "\"duckdb_native_secrets\":\"Use CREATE SECRET (TYPE s3/http/gcs/r2) for cloud protocols\",",
            "\"duck_net_secrets\":\"Use duck_net_add_secret() for SMTP, SSH, LDAP, Redis, MQTT, etc.\",",
            "\"persistent_secret_warning\":\"DuckDB PERSISTENT secrets are stored UNENCRYPTED on disk\"",
            "}}"
        ),
        ssrf, ssh_strict, warnings_enabled, warnings_count,
        secrets_count, rate_limit, timeout, retries,
    );
    let mut writer = unsafe { VectorWriter::from_vector(output) };
    unsafe { writer.write_varchar(0, &status) };
});

// ---------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------

pub unsafe fn register_all(con: &Connection) -> Result<(), ExtensionError> {
    let v = TypeId::Varchar;

    // Initialize secrets store
    secrets::init();

    // --- Secrets Management Functions ---

    // duck_net_add_secret(name, type, config_json) -> VARCHAR
    ScalarFunctionBuilder::new("duck_net_add_secret")
        .param(v) // name
        .param(v) // type
        .param(v) // config_json
        .returns(TypeId::Varchar)
        .function(cb_add_secret)
        .register(con.as_raw_connection())?;

    // duck_net_clear_secret(name) -> VARCHAR
    ScalarFunctionBuilder::new("duck_net_clear_secret")
        .param(v) // name
        .returns(TypeId::Varchar)
        .function(cb_clear_secret)
        .register(con.as_raw_connection())?;

    // duck_net_rotate_secret(name, new_config_json) -> VARCHAR
    ScalarFunctionBuilder::new("duck_net_rotate_secret")
        .param(v) // name
        .param(v) // new_config_json
        .returns(TypeId::Varchar)
        .function(cb_rotate_secret)
        .register(con.as_raw_connection())?;

    // duck_net_clear_all_secrets() -> VARCHAR (no params, returns message)
    ScalarFunctionBuilder::new("duck_net_clear_all_secrets")
        .returns(TypeId::Varchar)
        .function(cb_clear_all_secrets)
        .register(con.as_raw_connection())?;

    // duck_net_secret(name, key) -> VARCHAR
    ScalarFunctionBuilder::new("duck_net_secret")
        .param(v) // name
        .param(v) // key
        .returns(TypeId::Varchar)
        .function(cb_get_secret_value)
        .null_handling(NullHandling::SpecialNullHandling)
        .register(con.as_raw_connection())?;

    // duck_net_secret_type(name) -> VARCHAR
    ScalarFunctionBuilder::new("duck_net_secret_type")
        .param(v) // name
        .returns(TypeId::Varchar)
        .function(cb_get_secret_type)
        .null_handling(NullHandling::SpecialNullHandling)
        .register(con.as_raw_connection())?;

    // duck_net_secret_redacted(name) -> VARCHAR (JSON with redacted values)
    ScalarFunctionBuilder::new("duck_net_secret_redacted")
        .param(v) // name
        .returns(TypeId::Varchar)
        .function(cb_get_secret_redacted)
        .register(con.as_raw_connection())?;

    // duck_net_scrub_url(url) -> VARCHAR
    ScalarFunctionBuilder::new("duck_net_scrub_url")
        .param(v)
        .returns(TypeId::Varchar)
        .function(cb_scrub_url)
        .register(con.as_raw_connection())?;

    // duck_net_scrub_error(msg) -> VARCHAR
    ScalarFunctionBuilder::new("duck_net_scrub_error")
        .param(v)
        .returns(TypeId::Varchar)
        .function(cb_scrub_error)
        .register(con.as_raw_connection())?;

    // --- Security Configuration Functions ---

    // duck_net_security_status() -> VARCHAR (audit current security config)
    ScalarFunctionBuilder::new("duck_net_security_status")
        .returns(TypeId::Varchar)
        .function(cb_security_status)
        .register(con.as_raw_connection())?;

    // duck_net_set_ssrf_protection(enabled BOOLEAN) -> VARCHAR
    ScalarFunctionBuilder::new("duck_net_set_ssrf_protection")
        .param(TypeId::Boolean)
        .returns(TypeId::Varchar)
        .function(cb_set_ssrf_protection)
        .register(con.as_raw_connection())?;

    // duck_net_set_ssh_strict(enabled BOOLEAN) -> VARCHAR
    ScalarFunctionBuilder::new("duck_net_set_ssh_strict")
        .param(TypeId::Boolean)
        .returns(TypeId::Varchar)
        .function(cb_set_ssh_strict)
        .register(con.as_raw_connection())?;

    // duck_net_set_dns_block_private(enabled BOOLEAN) -> VARCHAR
    ScalarFunctionBuilder::new("duck_net_set_dns_block_private")
        .param(TypeId::Boolean)
        .returns(TypeId::Varchar)
        .function(cb_set_dns_block_private)
        .register(con.as_raw_connection())?;

    // duck_net_set_egress_allowlist(patterns VARCHAR) -> VARCHAR
    ScalarFunctionBuilder::new("duck_net_set_egress_allowlist")
        .param(v)
        .returns(TypeId::Varchar)
        .function(cb_set_egress_allowlist)
        .register(con.as_raw_connection())?;

    // duck_net_egress_allowlist() -> VARCHAR
    ScalarFunctionBuilder::new("duck_net_egress_allowlist")
        .returns(TypeId::Varchar)
        .function(cb_egress_allowlist)
        .register(con.as_raw_connection())?;

    // duck_net_set_ssh_tofu(mode VARCHAR) -> VARCHAR
    ScalarFunctionBuilder::new("duck_net_set_ssh_tofu")
        .param(v)
        .returns(TypeId::Varchar)
        .function(cb_set_ssh_tofu)
        .register(con.as_raw_connection())?;

    // duck_net_set_protocol_acl(protocols VARCHAR) -> VARCHAR
    ScalarFunctionBuilder::new("duck_net_set_protocol_acl")
        .param(v)
        .returns(TypeId::Varchar)
        .function(cb_set_protocol_acl)
        .register(con.as_raw_connection())?;

    // duck_net_protocol_acl() -> VARCHAR
    ScalarFunctionBuilder::new("duck_net_protocol_acl")
        .returns(TypeId::Varchar)
        .function(cb_protocol_acl)
        .register(con.as_raw_connection())?;

    // --- Protocol-specific overloads (S3, SMTP, Vault, SSH, Consul, InfluxDB, HTTP, etc.) ---
    super::secrets_protocols::register_all(con)?;

    Ok(())
}
