// SPDX-License-Identifier: MIT
// Copyright 2026 Tom F. <tomf@tomtomtech.net> (https://github.com/tomtom215)

//! Protocol-specific secrets-aware FFI overloads (Redis, LDAP, S3, SMTP,
//! Vault) and the secrets list table function.

use libduckdb_sys::*;
use quack_rs::prelude::*;

use crate::secrets;
use crate::security;

use super::scalars::write_varchar;

// ---------------------------------------------------------------------------
// Secrets-Aware Redis Overload
// ---------------------------------------------------------------------------

/// redis_get_secret(secret_name, key) -> STRUCT(success, value)
unsafe extern "C" fn cb_redis_get_secret(
    _info: duckdb_function_info,
    input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    let row_count = duckdb_data_chunk_get_size(input);
    let secret_reader = VectorReader::new(input, 0);
    let key_reader = VectorReader::new(input, 1);

    let success_vec = duckdb_struct_vector_get_child(output, 0);
    let value_vec = duckdb_struct_vector_get_child(output, 1);

    for row in 0..row_count {
        let secret_name = secret_reader.read_str(row as usize);
        let key = key_reader.read_str(row as usize);

        let result = match build_redis_url(secret_name) {
            Ok(url) => crate::redis_client::get(&url, key),
            Err(e) => crate::redis_client::RedisResult {
                success: false,
                value: e,
            },
        };

        let sd = duckdb_vector_get_data(success_vec) as *mut bool;
        *sd.add(row as usize) = result.success;
        write_varchar(value_vec, row, &result.value);
    }
}

/// redis_set_secret(secret_name, key, value) -> STRUCT(success, value)
unsafe extern "C" fn cb_redis_set_secret(
    _info: duckdb_function_info,
    input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    let row_count = duckdb_data_chunk_get_size(input);
    let secret_reader = VectorReader::new(input, 0);
    let key_reader = VectorReader::new(input, 1);
    let val_reader = VectorReader::new(input, 2);

    let success_vec = duckdb_struct_vector_get_child(output, 0);
    let value_vec = duckdb_struct_vector_get_child(output, 1);

    for row in 0..row_count {
        let secret_name = secret_reader.read_str(row as usize);
        let key = key_reader.read_str(row as usize);
        let value = val_reader.read_str(row as usize);

        let result = match build_redis_url(secret_name) {
            Ok(url) => crate::redis_client::set(&url, key, value),
            Err(e) => crate::redis_client::RedisResult {
                success: false,
                value: e,
            },
        };

        let sd = duckdb_vector_get_data(success_vec) as *mut bool;
        *sd.add(row as usize) = result.success;
        write_varchar(value_vec, row, &result.value);
    }
}

/// Build a Redis URL from a named secret.
fn build_redis_url(secret_name: &str) -> Result<String, String> {
    let host = secrets::get_value(secret_name, "host")
        .ok_or_else(|| format!("Secret '{}' missing 'host'", secret_name))?;
    let port = secrets::get_value(secret_name, "port").unwrap_or_else(|| "6379".to_string());
    let password = secrets::get_value(secret_name, "password");
    let db = secrets::get_value(secret_name, "db");

    let mut url = String::from("redis://");
    if let Some(pass) = password {
        url.push_str(&pass);
        url.push('@');
    }
    url.push_str(&host);
    url.push(':');
    url.push_str(&port);
    if let Some(db_num) = db {
        url.push('/');
        url.push_str(&db_num);
    }
    Ok(url)
}

// ---------------------------------------------------------------------------
// Secrets-Aware LDAP Overload
// ---------------------------------------------------------------------------

/// ldap_search_secret(secret_name, url, base_dn, filter, attributes) -> VARCHAR
unsafe extern "C" fn cb_ldap_search_secret(
    _info: duckdb_function_info,
    input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    let row_count = duckdb_data_chunk_get_size(input);
    let secret_reader = VectorReader::new(input, 0);
    let url_reader = VectorReader::new(input, 1);
    let base_reader = VectorReader::new(input, 2);
    let filter_reader = VectorReader::new(input, 3);
    let attrs_reader = VectorReader::new(input, 4);

    for row in 0..row_count {
        let secret_name = secret_reader.read_str(row as usize);
        let url = url_reader.read_str(row as usize);
        let base_dn = base_reader.read_str(row as usize);
        let filter = filter_reader.read_str(row as usize);
        let attrs_str = attrs_reader.read_str(row as usize);

        let msg = match crate::secrets_resolve::resolve_credentials(secret_name) {
            Ok((Some(user), Some(pass))) => {
                // First bind, then search
                let bind_result = crate::ldap::bind(url, &user, &pass);
                if !bind_result.success {
                    security::scrub_error(&bind_result.message)
                } else {
                    let attr_vec: Vec<&str> = attrs_str.split(',').map(|s| s.trim()).collect();
                    let result = crate::ldap::search(url, base_dn, filter, &attr_vec);
                    if result.success {
                        // Format entries as JSON
                        let entries_json: Vec<String> = result
                            .entries
                            .iter()
                            .map(|e| {
                                let attrs: Vec<String> = e
                                    .attributes
                                    .iter()
                                    .map(|(k, vals)| {
                                        let v_json = vals
                                            .iter()
                                            .map(|v| format!("\"{}\"", security::json_escape(v)))
                                            .collect::<Vec<_>>()
                                            .join(",");
                                        format!("\"{}\":[{}]", security::json_escape(k), v_json)
                                    })
                                    .collect();
                                format!(
                                    "{{\"dn\":\"{}\",{}}}",
                                    security::json_escape(&e.dn),
                                    attrs.join(",")
                                )
                            })
                            .collect();
                        format!("[{}]", entries_json.join(","))
                    } else {
                        security::scrub_error(&result.message)
                    }
                }
            }
            Ok(_) => format!(
                "Secret '{}' must have 'username' and 'password'",
                secret_name
            ),
            Err(e) => e,
        };

        write_varchar(output, row, &msg);
    }
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

        let result = match crate::secrets_resolve::resolve_s3(secret_name) {
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

        let result = match crate::secrets_resolve::resolve_s3(secret_name) {
            Ok((endpoint, access_key, secret_key, region)) => crate::s3::s3_put(
                &endpoint,
                bucket,
                key,
                body,
                &access_key,
                &secret_key,
                &region,
            ),
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

        let result = match crate::secrets_resolve::resolve_s3(secret_name) {
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

        let result = match crate::secrets_resolve::resolve_token(secret_name) {
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

    // duck_net_secrets() table function
    TableFunctionBuilder::new("duck_net_secrets")
        .bind(secrets_list_bind)
        .init(secrets_list_init)
        .scan(secrets_list_scan)
        .register(con)?;

    let redis_kv_type = || {
        LogicalType::struct_type_from_logical(&[
            ("success", LogicalType::new(TypeId::Boolean)),
            ("value", LogicalType::new(TypeId::Varchar)),
        ])
    };

    // S3
    ScalarFunctionBuilder::new("s3_get_secret")
        .param(v).param(v).param(v)
        .returns_logical(s3_result_type())
        .function(cb_s3_get_secret)
        .null_handling(NullHandling::SpecialNullHandling)
        .register(con)?;
    ScalarFunctionBuilder::new("s3_put_secret")
        .param(v).param(v).param(v).param(v)
        .returns_logical(s3_result_type())
        .function(cb_s3_put_secret)
        .null_handling(NullHandling::SpecialNullHandling)
        .register(con)?;
    ScalarFunctionBuilder::new("s3_list_secret")
        .param(v).param(v).param(v)
        .returns_logical(s3_list_result_type())
        .function(cb_s3_list_secret)
        .null_handling(NullHandling::SpecialNullHandling)
        .register(con)?;

    // SMTP
    ScalarFunctionBuilder::new("smtp_send_secret")
        .param(v).param(v).param(v).param(v).param(v)
        .returns_logical(smtp_secret_result_type())
        .function(cb_smtp_send_secret)
        .null_handling(NullHandling::SpecialNullHandling)
        .register(con)?;

    // Vault
    ScalarFunctionBuilder::new("vault_read_secret")
        .param(v).param(v).param(v)
        .returns_logical(vault_result_type())
        .function(cb_vault_read_secret)
        .null_handling(NullHandling::SpecialNullHandling)
        .register(con)?;

    // Redis
    ScalarFunctionBuilder::new("redis_get_secret")
        .param(v).param(v)
        .returns_logical(redis_kv_type())
        .function(cb_redis_get_secret)
        .null_handling(NullHandling::SpecialNullHandling)
        .register(con)?;
    ScalarFunctionBuilder::new("redis_set_secret")
        .param(v).param(v).param(v)
        .returns_logical(redis_kv_type())
        .function(cb_redis_set_secret)
        .null_handling(NullHandling::SpecialNullHandling)
        .register(con)?;

    // LDAP
    ScalarFunctionBuilder::new("ldap_search_secret")
        .param(v).param(v).param(v).param(v).param(v)
        .returns(TypeId::Varchar)
        .function(cb_ldap_search_secret)
        .null_handling(NullHandling::SpecialNullHandling)
        .register(con)?;

    Ok(())
}
