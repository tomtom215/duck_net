// SPDX-License-Identifier: MIT
// Copyright 2026 Tom F. <tomf@tomtomtech.net> (https://github.com/tomtom215)

//! FFI bindings for the duck_net secrets manager and security configuration.

use libduckdb_sys::*;
use quack_rs::prelude::*;

use crate::secrets;
use crate::security;

use super::scalars::write_varchar;

// ---------------------------------------------------------------------------
// Secrets Manager Callbacks
// ---------------------------------------------------------------------------

/// duck_net_add_secret(name, type, config_json) -> VARCHAR
unsafe extern "C" fn cb_add_secret(
    _info: duckdb_function_info,
    input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    let chunk = DataChunk::from_raw(input);
    let row_count = chunk.size();
    let name_reader = chunk.reader(0);
    let type_reader = chunk.reader(1);
    let config_reader = chunk.reader(2);

    for row in 0..row_count {
        let name = name_reader.read_str(row as usize);
        let secret_type = type_reader.read_str(row as usize);
        let config_json = config_reader.read_str(row as usize);

        let msg = match secrets::add_secret(name, secret_type, config_json) {
            Ok(m) => m,
            Err(e) => format!("Error: {}", e),
        };
        write_varchar(output, row, &msg);
    }
}

/// duck_net_clear_secret(name) -> VARCHAR
unsafe extern "C" fn cb_clear_secret(
    _info: duckdb_function_info,
    input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    let chunk = DataChunk::from_raw(input);
    let row_count = chunk.size();
    let name_reader = chunk.reader(0);

    for row in 0..row_count {
        let name = name_reader.read_str(row as usize);
        let msg = match secrets::clear_secret(name) {
            Ok(m) => m,
            Err(e) => format!("Error: {}", e),
        };
        write_varchar(output, row, &msg);
    }
}

/// duck_net_clear_all_secrets() -> VARCHAR
unsafe extern "C" fn cb_clear_all_secrets(
    _info: duckdb_function_info,
    _input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    let msg = secrets::clear_all_secrets();
    write_varchar(output, 0, &msg);
}

/// duck_net_secret_type(name) -> VARCHAR
/// Returns the type of a named secret, or NULL if not found.
unsafe extern "C" fn cb_get_secret_type(
    _info: duckdb_function_info,
    input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    let chunk = DataChunk::from_raw(input);
    let row_count = chunk.size();
    let name_reader = chunk.reader(0);

    let validity = duckdb_vector_get_validity(output);

    for row in 0..row_count {
        let name = name_reader.read_str(row as usize);
        match secrets::get_type(name) {
            Some(stype) => write_varchar(output, row, &stype),
            None => {
                if validity.is_null() {
                    duckdb_vector_ensure_validity_writable(output);
                    let validity = duckdb_vector_get_validity(output);
                    duckdb_validity_set_row_invalid(validity, row as idx_t);
                } else {
                    duckdb_validity_set_row_invalid(validity, row as idx_t);
                }
            }
        }
    }
}

/// duck_net_secret_redacted(name) -> VARCHAR
/// Returns a JSON representation of a secret with sensitive values redacted.
unsafe extern "C" fn cb_get_secret_redacted(
    _info: duckdb_function_info,
    input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    let chunk = DataChunk::from_raw(input);
    let row_count = chunk.size();
    let name_reader = chunk.reader(0);

    for row in 0..row_count {
        let name = name_reader.read_str(row as usize);
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
        write_varchar(output, row, &msg);
    }
}

/// duck_net_scrub_url(url) -> VARCHAR
/// Scrub credentials from a URL for safe logging.
unsafe extern "C" fn cb_scrub_url(
    _info: duckdb_function_info,
    input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    let chunk = DataChunk::from_raw(input);
    let row_count = chunk.size();
    let url_reader = chunk.reader(0);

    for row in 0..row_count {
        let url = url_reader.read_str(row as usize);
        let scrubbed = security::scrub_url(url);
        write_varchar(output, row, &scrubbed);
    }
}

/// duck_net_scrub_error(msg) -> VARCHAR
/// Scrub known credential patterns from an error message.
unsafe extern "C" fn cb_scrub_error(
    _info: duckdb_function_info,
    input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    let chunk = DataChunk::from_raw(input);
    let row_count = chunk.size();
    let msg_reader = chunk.reader(0);

    for row in 0..row_count {
        let msg = msg_reader.read_str(row as usize);
        let scrubbed = security::scrub_error(msg);
        write_varchar(output, row, &scrubbed);
    }
}

/// duck_net_secret(name, key) -> VARCHAR
/// Returns a specific value from a named secret, or NULL if not found.
unsafe extern "C" fn cb_get_secret_value(
    _info: duckdb_function_info,
    input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    let chunk = DataChunk::from_raw(input);
    let row_count = chunk.size();
    let name_reader = chunk.reader(0);
    let key_reader = chunk.reader(1);

    let validity = duckdb_vector_get_validity(output);

    for row in 0..row_count {
        let name = name_reader.read_str(row as usize);
        let key = key_reader.read_str(row as usize);

        match secrets::get_value(name, key) {
            Some(value) => {
                write_varchar(output, row, &value);
            }
            None => {
                // Set NULL for missing secrets
                if validity.is_null() {
                    duckdb_vector_ensure_validity_writable(output);
                    let validity = duckdb_vector_get_validity(output);
                    duckdb_validity_set_row_invalid(validity, row as idx_t);
                } else {
                    duckdb_validity_set_row_invalid(validity, row as idx_t);
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Security Configuration Callbacks
// ---------------------------------------------------------------------------

/// duck_net_set_ssrf_protection(enabled BOOLEAN) -> VARCHAR
unsafe extern "C" fn cb_set_ssrf_protection(
    _info: duckdb_function_info,
    input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    let chunk = DataChunk::from_raw(input);
    let row_count = chunk.size();
    let data = duckdb_vector_get_data(duckdb_data_chunk_get_vector(input, 0)) as *const bool;

    for row in 0..row_count {
        let enabled = *data.add(row as usize);
        security::set_ssrf_protection(enabled);
        let msg = if enabled {
            "SSRF protection enabled: private/reserved IPs are blocked"
        } else {
            "SSRF protection disabled: all IPs are reachable (development mode)"
        };
        write_varchar(output, row, msg);
    }
}

/// duck_net_set_ssh_strict(enabled BOOLEAN) -> VARCHAR
unsafe extern "C" fn cb_set_ssh_strict(
    _info: duckdb_function_info,
    input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    let chunk = DataChunk::from_raw(input);
    let row_count = chunk.size();
    let data = duckdb_vector_get_data(duckdb_data_chunk_get_vector(input, 0)) as *const bool;

    for row in 0..row_count {
        let strict = *data.add(row as usize);
        security::set_ssh_strict_commands(strict);
        let msg = if strict {
            "SSH strict mode enabled: shell metacharacters (;|&$`<>) are blocked in commands"
        } else {
            "SSH strict mode disabled: only null bytes and newlines are blocked in commands"
        };
        write_varchar(output, row, msg);
    }
}

/// duck_net_security_status() -> VARCHAR
/// Returns a JSON summary of current security configuration for auditing.
unsafe extern "C" fn cb_security_status(
    _info: duckdb_function_info,
    _input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    let ssrf = security::ssrf_protection_enabled();
    let ssh_strict = security::ssh_strict_commands();
    let secrets_count = secrets::list_secrets().len();
    let rate_limit = crate::rate_limit::get_global_rps();
    let timeout = crate::http::get_timeout_secs();
    let retries = crate::http::get_max_retries();

    let status = format!(
        concat!(
            "{{",
            "\"ssrf_protection\":{},",
            "\"ssh_strict_commands\":{},",
            "\"secrets_stored\":{},",
            "\"global_rate_limit_rps\":{},",
            "\"http_timeout_secs\":{},",
            "\"http_max_retries\":{},",
            "\"duckdb_native_secrets\":\"Use CREATE SECRET (TYPE s3/http) for S3 and HTTP protocols\",",
            "\"duck_net_secrets\":\"Use duck_net_add_secret() for SMTP, SSH, LDAP, Redis, MQTT, etc.\"",
            "}}"
        ),
        ssrf, ssh_strict, secrets_count, rate_limit, timeout, retries,
    );
    write_varchar(output, 0, &status);
}

// ---------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------

pub unsafe fn register_all(con: duckdb_connection) -> Result<(), ExtensionError> {
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
        .register(con)?;

    // duck_net_clear_secret(name) -> VARCHAR
    ScalarFunctionBuilder::new("duck_net_clear_secret")
        .param(v) // name
        .returns(TypeId::Varchar)
        .function(cb_clear_secret)
        .register(con)?;

    // duck_net_clear_all_secrets() -> VARCHAR (no params, returns message)
    ScalarFunctionBuilder::new("duck_net_clear_all_secrets")
        .returns(TypeId::Varchar)
        .function(cb_clear_all_secrets)
        .register(con)?;

    // duck_net_secret(name, key) -> VARCHAR
    ScalarFunctionBuilder::new("duck_net_secret")
        .param(v) // name
        .param(v) // key
        .returns(TypeId::Varchar)
        .function(cb_get_secret_value)
        .null_handling(NullHandling::SpecialNullHandling)
        .register(con)?;

    // duck_net_secret_type(name) -> VARCHAR
    ScalarFunctionBuilder::new("duck_net_secret_type")
        .param(v) // name
        .returns(TypeId::Varchar)
        .function(cb_get_secret_type)
        .null_handling(NullHandling::SpecialNullHandling)
        .register(con)?;

    // duck_net_secret_redacted(name) -> VARCHAR (JSON with redacted values)
    ScalarFunctionBuilder::new("duck_net_secret_redacted")
        .param(v) // name
        .returns(TypeId::Varchar)
        .function(cb_get_secret_redacted)
        .register(con)?;

    // duck_net_scrub_url(url) -> VARCHAR
    ScalarFunctionBuilder::new("duck_net_scrub_url")
        .param(v)
        .returns(TypeId::Varchar)
        .function(cb_scrub_url)
        .register(con)?;

    // duck_net_scrub_error(msg) -> VARCHAR
    ScalarFunctionBuilder::new("duck_net_scrub_error")
        .param(v)
        .returns(TypeId::Varchar)
        .function(cb_scrub_error)
        .register(con)?;

    // --- Security Configuration Functions ---

    // duck_net_security_status() -> VARCHAR (audit current security config)
    ScalarFunctionBuilder::new("duck_net_security_status")
        .returns(TypeId::Varchar)
        .function(cb_security_status)
        .register(con)?;

    // duck_net_set_ssrf_protection(enabled BOOLEAN) -> VARCHAR
    ScalarFunctionBuilder::new("duck_net_set_ssrf_protection")
        .param(TypeId::Boolean)
        .returns(TypeId::Varchar)
        .function(cb_set_ssrf_protection)
        .register(con)?;

    // duck_net_set_ssh_strict(enabled BOOLEAN) -> VARCHAR
    ScalarFunctionBuilder::new("duck_net_set_ssh_strict")
        .param(TypeId::Boolean)
        .returns(TypeId::Varchar)
        .function(cb_set_ssh_strict)
        .register(con)?;

    // --- Protocol-specific overloads (S3, SMTP, Vault, SSH, Consul, InfluxDB, HTTP, etc.) ---
    super::secrets_protocols::register_all(con)?;

    Ok(())
}
