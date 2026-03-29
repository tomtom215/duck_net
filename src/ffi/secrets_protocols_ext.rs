// SPDX-License-Identifier: MIT
// Copyright 2026 Tom F. <tomf@tomtomtech.net> (https://github.com/tomtom215)

//! Extended secrets-aware FFI overloads (Redis, S3, SMTP, Vault) and the
//! secrets list table function.

use libduckdb_sys::*;
use quack_rs::prelude::*;

use crate::secrets;

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
    let chunk = DataChunk::from_raw(input);
    let row_count = chunk.size();
    let secret_reader = chunk.reader(0);
    let key_reader = chunk.reader(1);

    let mut success_w = StructVector::field_writer(output, 0);
    let value_vec = duckdb_struct_vector_get_child(output, 1);

    for row in 0..row_count {
        let secret_name = secret_reader.read_str(row);
        let key = key_reader.read_str(row);

        let result = match build_redis_url(secret_name) {
            Ok(url) => crate::redis_client::get(&url, key),
            Err(e) => crate::redis_client::RedisResult {
                success: false,
                value: e,
            },
        };

        success_w.write_bool(row, result.success);
        write_varchar(value_vec, row, &result.value);
    }
}

/// redis_set_secret(secret_name, key, value) -> STRUCT(success, value)
unsafe extern "C" fn cb_redis_set_secret(
    _info: duckdb_function_info,
    input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    let chunk = DataChunk::from_raw(input);
    let row_count = chunk.size();
    let secret_reader = chunk.reader(0);
    let key_reader = chunk.reader(1);
    let val_reader = chunk.reader(2);

    let mut success_w = StructVector::field_writer(output, 0);
    let value_vec = duckdb_struct_vector_get_child(output, 1);

    for row in 0..row_count {
        let secret_name = secret_reader.read_str(row);
        let key = key_reader.read_str(row);
        let value = val_reader.read_str(row);

        let result = match build_redis_url(secret_name) {
            Ok(url) => crate::redis_client::set(&url, key, value),
            Err(e) => crate::redis_client::RedisResult {
                success: false,
                value: e,
            },
        };

        success_w.write_bool(row, result.success);
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
// Secrets-Aware S3 Overloads
// ---------------------------------------------------------------------------

/// s3_get_secret(secret_name, bucket, key) -> STRUCT
unsafe extern "C" fn cb_s3_get_secret(
    _info: duckdb_function_info,
    input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    let chunk = DataChunk::from_raw(input);
    let row_count = chunk.size();
    let secret_reader = chunk.reader(0);
    let bucket_reader = chunk.reader(1);
    let key_reader = chunk.reader(2);

    let mut success_w = StructVector::field_writer(output, 0);
    let body_vec = duckdb_struct_vector_get_child(output, 1);
    let mut status_w = StructVector::field_writer(output, 2);
    let message_vec = duckdb_struct_vector_get_child(output, 3);

    for row in 0..row_count {
        let secret_name = secret_reader.read_str(row);
        let bucket = bucket_reader.read_str(row);
        let key = key_reader.read_str(row);

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

        success_w.write_bool(row, result.success);
        write_varchar(body_vec, row, &result.body);
        status_w.write_i32(row, result.status);
        write_varchar(message_vec, row, &result.message);
    }
}

/// s3_put_secret(secret_name, bucket, key, body) -> STRUCT
unsafe extern "C" fn cb_s3_put_secret(
    _info: duckdb_function_info,
    input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    let chunk = DataChunk::from_raw(input);
    let row_count = chunk.size();
    let secret_reader = chunk.reader(0);
    let bucket_reader = chunk.reader(1);
    let key_reader = chunk.reader(2);
    let body_reader = chunk.reader(3);

    let mut success_w = StructVector::field_writer(output, 0);
    let body_vec = duckdb_struct_vector_get_child(output, 1);
    let mut status_w = StructVector::field_writer(output, 2);
    let message_vec = duckdb_struct_vector_get_child(output, 3);

    for row in 0..row_count {
        let secret_name = secret_reader.read_str(row);
        let bucket = bucket_reader.read_str(row);
        let key = key_reader.read_str(row);
        let body = body_reader.read_str(row);

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

        success_w.write_bool(row, result.success);
        write_varchar(body_vec, row, &result.body);
        status_w.write_i32(row, result.status);
        write_varchar(message_vec, row, &result.message);
    }
}

/// s3_list_secret(secret_name, bucket, prefix) -> STRUCT
unsafe extern "C" fn cb_s3_list_secret(
    _info: duckdb_function_info,
    input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    let chunk = DataChunk::from_raw(input);
    let row_count = chunk.size();
    let secret_reader = chunk.reader(0);
    let bucket_reader = chunk.reader(1);
    let prefix_reader = chunk.reader(2);

    let mut success_w = StructVector::field_writer(output, 0);
    let keys_vec = duckdb_struct_vector_get_child(output, 1);
    let message_vec = duckdb_struct_vector_get_child(output, 2);
    let mut list_offset: usize = 0;

    for row in 0..row_count {
        let secret_name = secret_reader.read_str(row);
        let bucket = bucket_reader.read_str(row);
        let prefix = prefix_reader.read_str(row);

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

        success_w.write_bool(row, result.success);
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
    let chunk = DataChunk::from_raw(input);
    let row_count = chunk.size();
    let secret_reader = chunk.reader(0);
    let from_reader = chunk.reader(1);
    let to_reader = chunk.reader(2);
    let subject_reader = chunk.reader(3);
    let body_reader = chunk.reader(4);

    let mut success_w = StructVector::field_writer(output, 0);
    let message_vec = duckdb_struct_vector_get_child(output, 1);

    for row in 0..row_count {
        let secret_name = secret_reader.read_str(row);

        let (success, message) = match resolve_smtp_config(
            secret_name,
            from_reader.read_str(row),
            to_reader.read_str(row),
            subject_reader.read_str(row),
            body_reader.read_str(row),
        ) {
            Ok(config) => {
                let r = crate::smtp::send(&config);
                (r.success, r.message)
            }
            Err(e) => (false, e),
        };

        success_w.write_bool(row, success);
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
    let chunk = DataChunk::from_raw(input);
    let row_count = chunk.size();
    let secret_reader = chunk.reader(0);
    let url_reader = chunk.reader(1);
    let path_reader = chunk.reader(2);

    let mut success_w = StructVector::field_writer(output, 0);
    let data_vec = duckdb_struct_vector_get_child(output, 1);
    let mut lease_w = StructVector::field_writer(output, 2);
    let mut renew_w = StructVector::field_writer(output, 3);
    let message_vec = duckdb_struct_vector_get_child(output, 4);

    for row in 0..row_count {
        let secret_name = secret_reader.read_str(row);
        let url = url_reader.read_str(row);
        let path = path_reader.read_str(row);

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

        success_w.write_bool(row, result.success);
        write_varchar(data_vec, row, &result.data);
        lease_w.write_i64(row, result.lease_duration);
        renew_w.write_bool(row, result.renewable);
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

    let out_chunk = DataChunk::from_raw(output);
    let mut name_w = out_chunk.writer(0);
    let mut type_w = out_chunk.writer(1);
    let mut count_w = out_chunk.writer(2);

    let mut count: usize = 0;
    let max_chunk = 2048;

    while init_data.idx < init_data.entries.len() && count < max_chunk {
        let (name, stype, key_count) = &init_data.entries[init_data.idx];
        name_w.write_varchar(count, name);
        type_w.write_varchar(count, stype);
        count_w.write_i32(count, *key_count as i32);
        init_data.idx += 1;
        count += 1;
    }

    duckdb_data_chunk_set_size(output, count as idx_t);
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
        .param(v)
        .param(v)
        .param(v)
        .returns_logical(s3_result_type())
        .function(cb_s3_get_secret)
        .null_handling(NullHandling::SpecialNullHandling)
        .register(con)?;
    ScalarFunctionBuilder::new("s3_put_secret")
        .param(v)
        .param(v)
        .param(v)
        .param(v)
        .returns_logical(s3_result_type())
        .function(cb_s3_put_secret)
        .null_handling(NullHandling::SpecialNullHandling)
        .register(con)?;
    ScalarFunctionBuilder::new("s3_list_secret")
        .param(v)
        .param(v)
        .param(v)
        .returns_logical(s3_list_result_type())
        .function(cb_s3_list_secret)
        .null_handling(NullHandling::SpecialNullHandling)
        .register(con)?;

    // SMTP
    ScalarFunctionBuilder::new("smtp_send_secret")
        .param(v)
        .param(v)
        .param(v)
        .param(v)
        .param(v)
        .returns_logical(smtp_secret_result_type())
        .function(cb_smtp_send_secret)
        .null_handling(NullHandling::SpecialNullHandling)
        .register(con)?;

    // Vault
    ScalarFunctionBuilder::new("vault_read_secret")
        .param(v)
        .param(v)
        .param(v)
        .returns_logical(vault_result_type())
        .function(cb_vault_read_secret)
        .null_handling(NullHandling::SpecialNullHandling)
        .register(con)?;

    // Redis
    ScalarFunctionBuilder::new("redis_get_secret")
        .param(v)
        .param(v)
        .returns_logical(redis_kv_type())
        .function(cb_redis_get_secret)
        .null_handling(NullHandling::SpecialNullHandling)
        .register(con)?;
    ScalarFunctionBuilder::new("redis_set_secret")
        .param(v)
        .param(v)
        .param(v)
        .returns_logical(redis_kv_type())
        .function(cb_redis_set_secret)
        .null_handling(NullHandling::SpecialNullHandling)
        .register(con)?;

    Ok(())
}
