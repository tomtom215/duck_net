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
    let row_count = duckdb_data_chunk_get_size(input);
    let name_reader = VectorReader::new(input, 0);
    let type_reader = VectorReader::new(input, 1);
    let config_reader = VectorReader::new(input, 2);

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
    let row_count = duckdb_data_chunk_get_size(input);
    let name_reader = VectorReader::new(input, 0);

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
    let row_count = duckdb_data_chunk_get_size(input);
    let name_reader = VectorReader::new(input, 0);

    let validity = duckdb_vector_get_validity(output);

    for row in 0..row_count {
        let name = name_reader.read_str(row as usize);
        match secrets::get_type(name) {
            Some(stype) => write_varchar(output, row, &stype),
            None => {
                if validity.is_null() {
                    duckdb_vector_ensure_validity_writable(output);
                    let validity = duckdb_vector_get_validity(output);
                    duckdb_validity_set_row_invalid(validity, row);
                } else {
                    duckdb_validity_set_row_invalid(validity, row);
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
    let row_count = duckdb_data_chunk_get_size(input);
    let name_reader = VectorReader::new(input, 0);

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
    let row_count = duckdb_data_chunk_get_size(input);
    let url_reader = VectorReader::new(input, 0);

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
    let row_count = duckdb_data_chunk_get_size(input);
    let msg_reader = VectorReader::new(input, 0);

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
    let row_count = duckdb_data_chunk_get_size(input);
    let name_reader = VectorReader::new(input, 0);
    let key_reader = VectorReader::new(input, 1);

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
                    duckdb_validity_set_row_invalid(validity, row);
                } else {
                    duckdb_validity_set_row_invalid(validity, row);
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
    let row_count = duckdb_data_chunk_get_size(input);
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
    let row_count = duckdb_data_chunk_get_size(input);
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
// Secrets-Aware S3 Overloads
// ---------------------------------------------------------------------------

/// s3_get_secret(secret_name, bucket, key) -> STRUCT
unsafe extern "C" fn cb_s3_get_secret(
    _info: duckdb_function_info,
    input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    let row_count = duckdb_data_chunk_get_size(input);
    let secret_reader = VectorReader::new(input, 0);
    let bucket_reader = VectorReader::new(input, 1);
    let key_reader = VectorReader::new(input, 2);

    let success_vec = duckdb_struct_vector_get_child(output, 0);
    let body_vec = duckdb_struct_vector_get_child(output, 1);
    let status_vec = duckdb_struct_vector_get_child(output, 2);
    let message_vec = duckdb_struct_vector_get_child(output, 3);

    for row in 0..row_count {
        let secret_name = secret_reader.read_str(row as usize);
        let bucket = bucket_reader.read_str(row as usize);
        let key = key_reader.read_str(row as usize);

        let result = match secrets::resolve_s3(secret_name) {
            Ok((endpoint, access_key, secret_key, region)) => {
                crate::s3::s3_get(&endpoint, bucket, key, &access_key, &secret_key, &region)
            }
            Err(e) => crate::s3::S3Result {
                success: false,
                body: String::new(),
                status: 0,
                message: e,
            },
        };

        let sd = duckdb_vector_get_data(success_vec) as *mut bool;
        *sd.add(row as usize) = result.success;
        write_varchar(body_vec, row, &result.body);
        let st = duckdb_vector_get_data(status_vec) as *mut i32;
        *st.add(row as usize) = result.status;
        write_varchar(message_vec, row, &result.message);
    }
}

/// s3_put_secret(secret_name, bucket, key, body) -> STRUCT
unsafe extern "C" fn cb_s3_put_secret(
    _info: duckdb_function_info,
    input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    let row_count = duckdb_data_chunk_get_size(input);
    let secret_reader = VectorReader::new(input, 0);
    let bucket_reader = VectorReader::new(input, 1);
    let key_reader = VectorReader::new(input, 2);
    let body_reader = VectorReader::new(input, 3);

    let success_vec = duckdb_struct_vector_get_child(output, 0);
    let body_vec = duckdb_struct_vector_get_child(output, 1);
    let status_vec = duckdb_struct_vector_get_child(output, 2);
    let message_vec = duckdb_struct_vector_get_child(output, 3);

    for row in 0..row_count {
        let secret_name = secret_reader.read_str(row as usize);
        let bucket = bucket_reader.read_str(row as usize);
        let key = key_reader.read_str(row as usize);
        let body = body_reader.read_str(row as usize);

        let result = match secrets::resolve_s3(secret_name) {
            Ok((endpoint, access_key, secret_key, region)) => {
                crate::s3::s3_put(&endpoint, bucket, key, body, &access_key, &secret_key, &region)
            }
            Err(e) => crate::s3::S3Result {
                success: false,
                body: String::new(),
                status: 0,
                message: e,
            },
        };

        let sd = duckdb_vector_get_data(success_vec) as *mut bool;
        *sd.add(row as usize) = result.success;
        write_varchar(body_vec, row, &result.body);
        let st = duckdb_vector_get_data(status_vec) as *mut i32;
        *st.add(row as usize) = result.status;
        write_varchar(message_vec, row, &result.message);
    }
}

/// s3_list_secret(secret_name, bucket, prefix) -> STRUCT
unsafe extern "C" fn cb_s3_list_secret(
    _info: duckdb_function_info,
    input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    let row_count = duckdb_data_chunk_get_size(input);
    let secret_reader = VectorReader::new(input, 0);
    let bucket_reader = VectorReader::new(input, 1);
    let prefix_reader = VectorReader::new(input, 2);

    let success_vec = duckdb_struct_vector_get_child(output, 0);
    let keys_vec = duckdb_struct_vector_get_child(output, 1);
    let message_vec = duckdb_struct_vector_get_child(output, 2);
    let mut list_offset: idx_t = 0;

    for row in 0..row_count {
        let secret_name = secret_reader.read_str(row as usize);
        let bucket = bucket_reader.read_str(row as usize);
        let prefix = prefix_reader.read_str(row as usize);

        let result = match secrets::resolve_s3(secret_name) {
            Ok((endpoint, access_key, secret_key, region)) => {
                crate::s3::s3_list(&endpoint, bucket, prefix, &access_key, &secret_key, &region)
            }
            Err(e) => crate::s3::S3ListResult {
                success: false,
                keys: Vec::new(),
                message: e,
            },
        };

        let sd = duckdb_vector_get_data(success_vec) as *mut bool;
        *sd.add(row as usize) = result.success;
        super::dns::write_string_list(keys_vec, row, &result.keys, &mut list_offset);
        write_varchar(message_vec, row, &result.message);
    }
}

// ---------------------------------------------------------------------------
// Secrets-Aware SMTP Overload
// ---------------------------------------------------------------------------

/// smtp_send_secret(secret_name, from, to, subject, body) -> STRUCT(success, message)
unsafe extern "C" fn cb_smtp_send_secret(
    _info: duckdb_function_info,
    input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    let row_count = duckdb_data_chunk_get_size(input);
    let secret_reader = VectorReader::new(input, 0);
    let from_reader = VectorReader::new(input, 1);
    let to_reader = VectorReader::new(input, 2);
    let subject_reader = VectorReader::new(input, 3);
    let body_reader = VectorReader::new(input, 4);

    let success_vec = duckdb_struct_vector_get_child(output, 0);
    let message_vec = duckdb_struct_vector_get_child(output, 1);

    for row in 0..row_count {
        let secret_name = secret_reader.read_str(row as usize);

        let (success, message) = match resolve_smtp_config(
            secret_name,
            from_reader.read_str(row as usize),
            to_reader.read_str(row as usize),
            subject_reader.read_str(row as usize),
            body_reader.read_str(row as usize),
        ) {
            Ok(config) => {
                let r = crate::smtp::send(&config);
                (r.success, r.message)
            }
            Err(e) => (false, e),
        };

        let sd = duckdb_vector_get_data(success_vec) as *mut bool;
        *sd.add(row as usize) = success;
        write_varchar(message_vec, row, &message);
    }
}

fn resolve_smtp_config(
    secret_name: &str,
    from: &str,
    to: &str,
    subject: &str,
    body: &str,
) -> Result<crate::smtp::SmtpConfig, String> {
    let host = secrets::get_value(secret_name, "host")
        .ok_or_else(|| format!("Secret '{}' missing 'host'", secret_name))?;
    let port: u16 = secrets::get_value(secret_name, "port")
        .unwrap_or_else(|| "587".to_string())
        .parse()
        .map_err(|e| format!("Invalid port: {}", e))?;
    let use_tls = secrets::get_value(secret_name, "use_tls")
        .map(|v| v == "true" || v == "1")
        .unwrap_or(false);
    let username = secrets::get_value(secret_name, "username");
    let password = secrets::get_value(secret_name, "password");

    Ok(crate::smtp::SmtpConfig {
        host,
        port,
        use_tls,
        from: from.to_string(),
        to: to.to_string(),
        subject: subject.to_string(),
        body: body.to_string(),
        username,
        password,
    })
}

// ---------------------------------------------------------------------------
// Secrets-Aware Vault Overload
// ---------------------------------------------------------------------------

/// vault_read_secret(secret_name, vault_url, path) -> STRUCT
unsafe extern "C" fn cb_vault_read_secret(
    _info: duckdb_function_info,
    input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    let row_count = duckdb_data_chunk_get_size(input);
    let secret_reader = VectorReader::new(input, 0);
    let url_reader = VectorReader::new(input, 1);
    let path_reader = VectorReader::new(input, 2);

    let success_vec = duckdb_struct_vector_get_child(output, 0);
    let data_vec = duckdb_struct_vector_get_child(output, 1);
    let lease_vec = duckdb_struct_vector_get_child(output, 2);
    let renew_vec = duckdb_struct_vector_get_child(output, 3);
    let message_vec = duckdb_struct_vector_get_child(output, 4);

    for row in 0..row_count {
        let secret_name = secret_reader.read_str(row as usize);
        let url = url_reader.read_str(row as usize);
        let path = path_reader.read_str(row as usize);

        let result = match secrets::resolve_token(secret_name) {
            Ok(token) => crate::vault::read(url, &token, path),
            Err(e) => crate::vault::VaultResult {
                success: false,
                data: String::new(),
                lease_duration: 0,
                renewable: false,
                message: e,
            },
        };

        let sd = duckdb_vector_get_data(success_vec) as *mut bool;
        *sd.add(row as usize) = result.success;
        write_varchar(data_vec, row, &result.data);
        let ld = duckdb_vector_get_data(lease_vec) as *mut i64;
        *ld.add(row as usize) = result.lease_duration;
        let rd = duckdb_vector_get_data(renew_vec) as *mut bool;
        *rd.add(row as usize) = result.renewable;
        write_varchar(message_vec, row, &result.message);
    }
}

// ---------------------------------------------------------------------------
// Secrets-Aware SSH Overloads
// ---------------------------------------------------------------------------

fn ssh_result_type() -> LogicalType {
    LogicalType::struct_type_from_logical(&[
        ("success", LogicalType::new(TypeId::Boolean)),
        ("exit_code", LogicalType::new(TypeId::Integer)),
        ("stdout", LogicalType::new(TypeId::Varchar)),
        ("stderr", LogicalType::new(TypeId::Varchar)),
    ])
}

/// ssh_exec_secret(secret_name, host, command) -> STRUCT
unsafe extern "C" fn cb_ssh_exec_secret(
    _info: duckdb_function_info,
    input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    let row_count = duckdb_data_chunk_get_size(input);
    let secret_reader = VectorReader::new(input, 0);
    let host_reader = VectorReader::new(input, 1);
    let cmd_reader = VectorReader::new(input, 2);

    let success_vec = duckdb_struct_vector_get_child(output, 0);
    let exit_vec = duckdb_struct_vector_get_child(output, 1);
    let stdout_vec = duckdb_struct_vector_get_child(output, 2);
    let stderr_vec = duckdb_struct_vector_get_child(output, 3);

    for row in 0..row_count {
        let secret_name = secret_reader.read_str(row as usize);
        let host = host_reader.read_str(row as usize);
        let command = cmd_reader.read_str(row as usize);

        let result = match secrets::resolve_ssh(secret_name) {
            Ok((user, key_file, password)) => {
                if let Some(key_path) = key_file {
                    crate::ssh::exec(host, 22, &user, &key_path, command)
                } else if let Some(pass) = password {
                    crate::ssh::exec_password(host, 22, &user, &pass, command)
                } else {
                    crate::ssh::SshExecResult {
                        success: false,
                        exit_code: -1,
                        stdout: String::new(),
                        stderr: "Secret must have 'key_file' or 'password'".to_string(),
                    }
                }
            }
            Err(e) => crate::ssh::SshExecResult {
                success: false,
                exit_code: -1,
                stdout: String::new(),
                stderr: e,
            },
        };

        let sd = duckdb_vector_get_data(success_vec) as *mut bool;
        *sd.add(row as usize) = result.success;
        let ed = duckdb_vector_get_data(exit_vec) as *mut i32;
        *ed.add(row as usize) = result.exit_code;
        write_varchar(stdout_vec, row, &result.stdout);
        write_varchar(stderr_vec, row, &result.stderr);
    }
}

// ---------------------------------------------------------------------------
// Secrets-Aware Consul Overload
// ---------------------------------------------------------------------------

fn kv_result_type() -> LogicalType {
    LogicalType::struct_type_from_logical(&[
        ("success", LogicalType::new(TypeId::Boolean)),
        ("value", LogicalType::new(TypeId::Varchar)),
        ("message", LogicalType::new(TypeId::Varchar)),
    ])
}

/// consul_get_secret(secret_name, url, key) -> STRUCT
unsafe extern "C" fn cb_consul_get_secret(
    _info: duckdb_function_info,
    input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    let row_count = duckdb_data_chunk_get_size(input);
    let secret_reader = VectorReader::new(input, 0);
    let url_reader = VectorReader::new(input, 1);
    let key_reader = VectorReader::new(input, 2);

    let success_vec = duckdb_struct_vector_get_child(output, 0);
    let value_vec = duckdb_struct_vector_get_child(output, 1);
    let message_vec = duckdb_struct_vector_get_child(output, 2);

    for row in 0..row_count {
        let secret_name = secret_reader.read_str(row as usize);
        let url = url_reader.read_str(row as usize);
        let key = key_reader.read_str(row as usize);

        let result = match secrets::resolve_token(secret_name) {
            Ok(token) => crate::consul::consul_get(url, key, &token),
            Err(e) => crate::consul::KvResult {
                success: false,
                value: String::new(),
                message: e,
            },
        };

        let sd = duckdb_vector_get_data(success_vec) as *mut bool;
        *sd.add(row as usize) = result.success;
        write_varchar(value_vec, row, &result.value);
        write_varchar(message_vec, row, &result.message);
    }
}

// ---------------------------------------------------------------------------
// Secrets-Aware InfluxDB Overload
// ---------------------------------------------------------------------------

fn influx_result_type() -> LogicalType {
    LogicalType::struct_type_from_logical(&[
        ("success", LogicalType::new(TypeId::Boolean)),
        ("body", LogicalType::new(TypeId::Varchar)),
        ("message", LogicalType::new(TypeId::Varchar)),
    ])
}

/// influxdb_query_secret(secret_name, url, org, flux_query) -> STRUCT
unsafe extern "C" fn cb_influxdb_query_secret(
    _info: duckdb_function_info,
    input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    let row_count = duckdb_data_chunk_get_size(input);
    let secret_reader = VectorReader::new(input, 0);
    let url_reader = VectorReader::new(input, 1);
    let org_reader = VectorReader::new(input, 2);
    let query_reader = VectorReader::new(input, 3);

    let success_vec = duckdb_struct_vector_get_child(output, 0);
    let body_vec = duckdb_struct_vector_get_child(output, 1);
    let message_vec = duckdb_struct_vector_get_child(output, 2);

    for row in 0..row_count {
        let secret_name = secret_reader.read_str(row as usize);
        let url = url_reader.read_str(row as usize);
        let org = org_reader.read_str(row as usize);
        let flux_query = query_reader.read_str(row as usize);

        let result = match secrets::resolve_token(secret_name) {
            Ok(token) => crate::influxdb::query(url, org, &token, flux_query),
            Err(e) => crate::influxdb::InfluxResult {
                success: false,
                body: String::new(),
                message: e,
            },
        };

        let sd = duckdb_vector_get_data(success_vec) as *mut bool;
        *sd.add(row as usize) = result.success;
        write_varchar(body_vec, row, &result.body);
        write_varchar(message_vec, row, &result.message);
    }
}

// ---------------------------------------------------------------------------
// Secrets-Aware HTTP Overload (for bearer token / basic auth from secrets)
// ---------------------------------------------------------------------------

/// http_get_secret(secret_name, url) -> response STRUCT
unsafe extern "C" fn cb_http_get_secret(
    _info: duckdb_function_info,
    input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    let row_count = duckdb_data_chunk_get_size(input);
    let secret_reader = VectorReader::new(input, 0);
    let url_reader = VectorReader::new(input, 1);
    let mut map_offset: idx_t = 0;

    for row in 0..row_count {
        let secret_name = secret_reader.read_str(row as usize);
        let url = url_reader.read_str(row as usize);

        let resp = match secrets::resolve_http(secret_name) {
            Ok(headers) => crate::http::execute(
                crate::http::Method::Get,
                url,
                &headers,
                None,
            ),
            Err(e) => crate::http::HttpResponse {
                status: 0,
                reason: e,
                headers: vec![],
                body: String::new(),
            },
        };
        super::scalars::write_response(output, row, &resp, &mut map_offset);
    }
}

/// http_post_secret(secret_name, url, body) -> response STRUCT
unsafe extern "C" fn cb_http_post_secret(
    _info: duckdb_function_info,
    input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    let row_count = duckdb_data_chunk_get_size(input);
    let secret_reader = VectorReader::new(input, 0);
    let url_reader = VectorReader::new(input, 1);
    let body_reader = VectorReader::new(input, 2);
    let mut map_offset: idx_t = 0;

    for row in 0..row_count {
        let secret_name = secret_reader.read_str(row as usize);
        let url = url_reader.read_str(row as usize);
        let body = body_reader.read_str(row as usize);

        let resp = match secrets::resolve_http(secret_name) {
            Ok(headers) => crate::http::execute(
                crate::http::Method::Post,
                url,
                &headers,
                Some(body),
            ),
            Err(e) => crate::http::HttpResponse {
                status: 0,
                reason: e,
                headers: vec![],
                body: String::new(),
            },
        };
        super::scalars::write_response(output, row, &resp, &mut map_offset);
    }
}

// ---------------------------------------------------------------------------
// Secrets-Aware SNMP Overload
// ---------------------------------------------------------------------------

/// snmp_get_secret(secret_name, host, oid) -> STRUCT(success, value)
unsafe extern "C" fn cb_snmp_get_secret(
    _info: duckdb_function_info,
    input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    let row_count = duckdb_data_chunk_get_size(input);
    let secret_reader = VectorReader::new(input, 0);
    let host_reader = VectorReader::new(input, 1);
    let oid_reader = VectorReader::new(input, 2);

    let success_vec = duckdb_struct_vector_get_child(output, 0);
    let value_vec = duckdb_struct_vector_get_child(output, 1);

    for row in 0..row_count {
        let secret_name = secret_reader.read_str(row as usize);
        let host = host_reader.read_str(row as usize);
        let oid = oid_reader.read_str(row as usize);

        let (success, value) = match secrets::resolve_community(secret_name) {
            Ok(community) => match crate::snmp::get(host, oid, &community) {
                Ok(r) => (true, r.value),
                Err(e) => (false, e),
            },
            Err(e) => (false, e),
        };

        let sd = duckdb_vector_get_data(success_vec) as *mut bool;
        *sd.add(row as usize) = success;
        write_varchar(value_vec, row, &value);
    }
}

// ---------------------------------------------------------------------------
// Secrets-Aware RADIUS Overload
// ---------------------------------------------------------------------------

/// radius_auth_secret(secret_name, host, username, password) -> STRUCT(success, message)
unsafe extern "C" fn cb_radius_auth_secret(
    _info: duckdb_function_info,
    input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    let row_count = duckdb_data_chunk_get_size(input);
    let secret_reader = VectorReader::new(input, 0);
    let host_reader = VectorReader::new(input, 1);
    let user_reader = VectorReader::new(input, 2);
    let pass_reader = VectorReader::new(input, 3);

    let success_vec = duckdb_struct_vector_get_child(output, 0);
    let message_vec = duckdb_struct_vector_get_child(output, 1);

    for row in 0..row_count {
        let secret_name = secret_reader.read_str(row as usize);
        let host = host_reader.read_str(row as usize);
        let username = user_reader.read_str(row as usize);
        let password = pass_reader.read_str(row as usize);

        let (success, message) = match secrets::resolve_shared_secret(secret_name) {
            Ok(shared_secret) => {
                let r = crate::radius::auth_default_port(host, &shared_secret, username, password);
                (r.success, r.message)
            }
            Err(e) => (false, e),
        };

        let sd = duckdb_vector_get_data(success_vec) as *mut bool;
        *sd.add(row as usize) = success;
        write_varchar(message_vec, row, &message);
    }
}

// ---------------------------------------------------------------------------
// Secrets-Aware IMAP Overload
// ---------------------------------------------------------------------------

/// imap_fetch_secret(secret_name, url, mailbox, uid) -> STRUCT(success, body, message)
unsafe extern "C" fn cb_imap_fetch_secret(
    _info: duckdb_function_info,
    input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    let row_count = duckdb_data_chunk_get_size(input);
    let secret_reader = VectorReader::new(input, 0);
    let url_reader = VectorReader::new(input, 1);
    let mailbox_reader = VectorReader::new(input, 2);
    let uid_data = duckdb_vector_get_data(duckdb_data_chunk_get_vector(input, 3)) as *const i64;

    let success_vec = duckdb_struct_vector_get_child(output, 0);
    let body_vec = duckdb_struct_vector_get_child(output, 1);
    let message_vec = duckdb_struct_vector_get_child(output, 2);

    for row in 0..row_count {
        let secret_name = secret_reader.read_str(row as usize);
        let url = url_reader.read_str(row as usize);
        let mailbox = mailbox_reader.read_str(row as usize);
        let uid = *uid_data.add(row as usize);

        let (success, body, message) = match secrets::resolve_credentials(secret_name) {
            Ok((Some(user), Some(pass))) => {
                let r = crate::imap::fetch_message(url, &user, &pass, mailbox, uid);
                (r.success, r.body, r.message)
            }
            Ok(_) => (
                false,
                String::new(),
                format!("Secret '{}' must have 'username' and 'password'", secret_name),
            ),
            Err(e) => (false, String::new(), e),
        };

        let sd = duckdb_vector_get_data(success_vec) as *mut bool;
        *sd.add(row as usize) = success;
        write_varchar(body_vec, row, &body);
        write_varchar(message_vec, row, &message);
    }
}

// ---------------------------------------------------------------------------
// Secrets List Table Function
// ---------------------------------------------------------------------------

struct SecretsListBindData;
struct SecretsListInitData {
    entries: Vec<(String, String, usize)>,
    idx: usize,
}

unsafe extern "C" fn secrets_list_bind(info: duckdb_bind_info) {
    let bind = BindInfo::new(info);
    bind.add_result_column("name", TypeId::Varchar);
    bind.add_result_column("type", TypeId::Varchar);
    bind.add_result_column("key_count", TypeId::Integer);
    FfiBindData::<SecretsListBindData>::set(info, SecretsListBindData);
}

unsafe extern "C" fn secrets_list_init(info: duckdb_init_info) {
    FfiInitData::<SecretsListInitData>::set(
        info,
        SecretsListInitData {
            entries: vec![],
            idx: 0,
        },
    );
}

unsafe extern "C" fn secrets_list_scan(info: duckdb_function_info, output: duckdb_data_chunk) {
    let init_data = match FfiInitData::<SecretsListInitData>::get_mut(info) {
        Some(d) => d,
        None => {
            duckdb_data_chunk_set_size(output, 0);
            return;
        }
    };

    if init_data.entries.is_empty() && init_data.idx == 0 {
        init_data.entries = secrets::list_secrets();
    }

    let name_vec = duckdb_data_chunk_get_vector(output, 0);
    let type_vec = duckdb_data_chunk_get_vector(output, 1);
    let count_vec = duckdb_data_chunk_get_vector(output, 2);

    let mut count: idx_t = 0;
    let max_chunk = 2048;

    while init_data.idx < init_data.entries.len() && count < max_chunk {
        let (name, stype, key_count) = &init_data.entries[init_data.idx];
        write_varchar(name_vec, count, name);
        write_varchar(type_vec, count, stype);
        let cd = duckdb_vector_get_data(count_vec) as *mut i32;
        *cd.add(count as usize) = *key_count as i32;
        init_data.idx += 1;
        count += 1;
    }

    duckdb_data_chunk_set_size(output, count);
}

// ---------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------

fn smtp_secret_result_type() -> LogicalType {
    LogicalType::struct_type_from_logical(&[
        ("success", LogicalType::new(TypeId::Boolean)),
        ("message", LogicalType::new(TypeId::Varchar)),
    ])
}

fn s3_result_type() -> LogicalType {
    LogicalType::struct_type_from_logical(&[
        ("success", LogicalType::new(TypeId::Boolean)),
        ("body", LogicalType::new(TypeId::Varchar)),
        ("status", LogicalType::new(TypeId::Integer)),
        ("message", LogicalType::new(TypeId::Varchar)),
    ])
}

fn s3_list_result_type() -> LogicalType {
    LogicalType::struct_type_from_logical(&[
        ("success", LogicalType::new(TypeId::Boolean)),
        (
            "keys",
            LogicalType::list_from_logical(&LogicalType::new(TypeId::Varchar)),
        ),
        ("message", LogicalType::new(TypeId::Varchar)),
    ])
}

fn vault_result_type() -> LogicalType {
    LogicalType::struct_type_from_logical(&[
        ("success", LogicalType::new(TypeId::Boolean)),
        ("data", LogicalType::new(TypeId::Varchar)),
        ("lease_duration", LogicalType::new(TypeId::BigInt)),
        ("renewable", LogicalType::new(TypeId::Boolean)),
        ("message", LogicalType::new(TypeId::Varchar)),
    ])
}

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

    // duck_net_secrets() table function - lists all secrets (redacted)
    TableFunctionBuilder::new("duck_net_secrets")
        .bind(secrets_list_bind)
        .init(secrets_list_init)
        .scan(secrets_list_scan)
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

    // --- Secrets-Aware Protocol Overloads ---

    // S3 with secrets
    ScalarFunctionBuilder::new("s3_get_secret")
        .param(v) // secret_name
        .param(v) // bucket
        .param(v) // key
        .returns_logical(s3_result_type())
        .function(cb_s3_get_secret)
        .null_handling(NullHandling::SpecialNullHandling)
        .register(con)?;

    ScalarFunctionBuilder::new("s3_put_secret")
        .param(v) // secret_name
        .param(v) // bucket
        .param(v) // key
        .param(v) // body
        .returns_logical(s3_result_type())
        .function(cb_s3_put_secret)
        .null_handling(NullHandling::SpecialNullHandling)
        .register(con)?;

    ScalarFunctionBuilder::new("s3_list_secret")
        .param(v) // secret_name
        .param(v) // bucket
        .param(v) // prefix
        .returns_logical(s3_list_result_type())
        .function(cb_s3_list_secret)
        .null_handling(NullHandling::SpecialNullHandling)
        .register(con)?;

    // SMTP with secrets
    ScalarFunctionBuilder::new("smtp_send_secret")
        .param(v) // secret_name
        .param(v) // from
        .param(v) // to
        .param(v) // subject
        .param(v) // body
        .returns_logical(smtp_secret_result_type())
        .function(cb_smtp_send_secret)
        .null_handling(NullHandling::SpecialNullHandling)
        .register(con)?;

    // Vault with secrets
    ScalarFunctionBuilder::new("vault_read_secret")
        .param(v) // secret_name (for vault token)
        .param(v) // vault_url
        .param(v) // path
        .returns_logical(vault_result_type())
        .function(cb_vault_read_secret)
        .null_handling(NullHandling::SpecialNullHandling)
        .register(con)?;

    // SSH with secrets
    ScalarFunctionBuilder::new("ssh_exec_secret")
        .param(v) // secret_name
        .param(v) // host
        .param(v) // command
        .returns_logical(ssh_result_type())
        .function(cb_ssh_exec_secret)
        .null_handling(NullHandling::SpecialNullHandling)
        .register(con)?;

    // Consul with secrets
    ScalarFunctionBuilder::new("consul_get_secret")
        .param(v) // secret_name
        .param(v) // url
        .param(v) // key
        .returns_logical(kv_result_type())
        .function(cb_consul_get_secret)
        .null_handling(NullHandling::SpecialNullHandling)
        .register(con)?;

    // InfluxDB with secrets
    ScalarFunctionBuilder::new("influxdb_query_secret")
        .param(v) // secret_name
        .param(v) // url
        .param(v) // org
        .param(v) // flux_query
        .returns_logical(influx_result_type())
        .function(cb_influxdb_query_secret)
        .null_handling(NullHandling::SpecialNullHandling)
        .register(con)?;

    // HTTP with secrets (bearer/basic auth from secret store)
    ScalarFunctionBuilder::new("http_get_secret")
        .param(v) // secret_name
        .param(v) // url
        .returns_logical(super::scalars::response_type())
        .function(cb_http_get_secret)
        .null_handling(NullHandling::SpecialNullHandling)
        .register(con)?;

    ScalarFunctionBuilder::new("http_post_secret")
        .param(v) // secret_name
        .param(v) // url
        .param(v) // body
        .returns_logical(super::scalars::response_type())
        .function(cb_http_post_secret)
        .null_handling(NullHandling::SpecialNullHandling)
        .register(con)?;

    // SNMP with secrets (community string from secret store)
    ScalarFunctionBuilder::new("snmp_get_secret")
        .param(v) // secret_name
        .param(v) // host
        .param(v) // oid
        .returns_logical(LogicalType::struct_type_from_logical(&[
            ("success", LogicalType::new(TypeId::Boolean)),
            ("value", LogicalType::new(TypeId::Varchar)),
        ]))
        .function(cb_snmp_get_secret)
        .null_handling(NullHandling::SpecialNullHandling)
        .register(con)?;

    // RADIUS with secrets (shared secret from secret store)
    ScalarFunctionBuilder::new("radius_auth_secret")
        .param(v) // secret_name (for shared_secret)
        .param(v) // host
        .param(v) // username
        .param(v) // password
        .returns_logical(smtp_secret_result_type()) // same shape: (success, message)
        .function(cb_radius_auth_secret)
        .null_handling(NullHandling::SpecialNullHandling)
        .register(con)?;

    // IMAP with secrets (username/password from secret store)
    ScalarFunctionBuilder::new("imap_fetch_secret")
        .param(v) // secret_name
        .param(v) // url
        .param(v) // mailbox
        .param(TypeId::BigInt) // uid
        .returns_logical(LogicalType::struct_type_from_logical(&[
            ("success", LogicalType::new(TypeId::Boolean)),
            ("body", LogicalType::new(TypeId::Varchar)),
            ("message", LogicalType::new(TypeId::Varchar)),
        ]))
        .function(cb_imap_fetch_secret)
        .null_handling(NullHandling::SpecialNullHandling)
        .register(con)?;

    Ok(())
}
