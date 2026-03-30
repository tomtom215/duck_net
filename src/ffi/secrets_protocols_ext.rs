// SPDX-License-Identifier: MIT
// Copyright 2026 Tom F. <tomf@tomtomtech.net> (https://github.com/tomtom215)

//! Extended secrets-aware FFI overloads (Redis, S3, SMTP, Vault) and the
//! secrets list table function.

use libduckdb_sys::*;
use quack_rs::prelude::*;

use crate::secrets;

use super::scalars::StructWriter;

// ---------------------------------------------------------------------------
// Secrets-Aware Redis Overload
// ---------------------------------------------------------------------------

// redis_get_secret(secret_name, key) -> STRUCT(success, value)
quack_rs::scalar_callback!(cb_redis_get_secret, |_info, input, output| {
    let chunk = unsafe { DataChunk::from_raw(input) };
    let row_count = chunk.size();
    let secret_reader = unsafe { chunk.reader(0) };
    let key_reader = unsafe { chunk.reader(1) };

    let mut sw = unsafe { StructWriter::new(output, 2) };

    for row in 0..row_count {
        let secret_name = unsafe { secret_reader.read_str(row) };
        let key = unsafe { key_reader.read_str(row) };

        let result = match build_redis_url(secret_name) {
            Ok(url) => crate::redis_client::get(&url, key),
            Err(e) => crate::redis_client::RedisResult {
                success: false,
                value: e,
            },
        };

        unsafe { sw.write_bool(row, 0, result.success) };
        unsafe { sw.write_varchar(row, 1, &result.value) };
    }
});

// redis_set_secret(secret_name, key, value) -> STRUCT(success, value)
quack_rs::scalar_callback!(cb_redis_set_secret, |_info, input, output| {
    let chunk = unsafe { DataChunk::from_raw(input) };
    let row_count = chunk.size();
    let secret_reader = unsafe { chunk.reader(0) };
    let key_reader = unsafe { chunk.reader(1) };
    let val_reader = unsafe { chunk.reader(2) };

    let mut sw = unsafe { StructWriter::new(output, 2) };

    for row in 0..row_count {
        let secret_name = unsafe { secret_reader.read_str(row) };
        let key = unsafe { key_reader.read_str(row) };
        let value = unsafe { val_reader.read_str(row) };

        let result = match build_redis_url(secret_name) {
            Ok(url) => crate::redis_client::set(&url, key, value),
            Err(e) => crate::redis_client::RedisResult {
                success: false,
                value: e,
            },
        };

        unsafe { sw.write_bool(row, 0, result.success) };
        unsafe { sw.write_varchar(row, 1, &result.value) };
    }
});

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

// s3_get_secret(secret_name, bucket, key) -> STRUCT
quack_rs::scalar_callback!(cb_s3_get_secret, |_info, input, output| {
    let chunk = unsafe { DataChunk::from_raw(input) };
    let row_count = chunk.size();
    let secret_reader = unsafe { chunk.reader(0) };
    let bucket_reader = unsafe { chunk.reader(1) };
    let key_reader = unsafe { chunk.reader(2) };

    let mut sw = unsafe { StructWriter::new(output, 4) };

    for row in 0..row_count {
        let secret_name = unsafe { secret_reader.read_str(row) };
        let bucket = unsafe { bucket_reader.read_str(row) };
        let key = unsafe { key_reader.read_str(row) };

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

        unsafe { sw.write_bool(row, 0, result.success) };
        unsafe { sw.write_varchar(row, 1, &result.body) };
        unsafe { sw.write_i32(row, 2, result.status) };
        unsafe { sw.write_varchar(row, 3, &result.message) };
    }
});

// s3_put_secret(secret_name, bucket, key, body) -> STRUCT
quack_rs::scalar_callback!(cb_s3_put_secret, |_info, input, output| {
    let chunk = unsafe { DataChunk::from_raw(input) };
    let row_count = chunk.size();
    let secret_reader = unsafe { chunk.reader(0) };
    let bucket_reader = unsafe { chunk.reader(1) };
    let key_reader = unsafe { chunk.reader(2) };
    let body_reader = unsafe { chunk.reader(3) };

    let mut sw = unsafe { StructWriter::new(output, 4) };

    for row in 0..row_count {
        let secret_name = unsafe { secret_reader.read_str(row) };
        let bucket = unsafe { bucket_reader.read_str(row) };
        let key = unsafe { key_reader.read_str(row) };
        let body = unsafe { body_reader.read_str(row) };

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

        unsafe { sw.write_bool(row, 0, result.success) };
        unsafe { sw.write_varchar(row, 1, &result.body) };
        unsafe { sw.write_i32(row, 2, result.status) };
        unsafe { sw.write_varchar(row, 3, &result.message) };
    }
});

// s3_list_secret(secret_name, bucket, prefix) -> STRUCT
quack_rs::scalar_callback!(cb_s3_list_secret, |_info, input, output| {
    let chunk = unsafe { DataChunk::from_raw(input) };
    let row_count = chunk.size();
    let secret_reader = unsafe { chunk.reader(0) };
    let bucket_reader = unsafe { chunk.reader(1) };
    let prefix_reader = unsafe { chunk.reader(2) };

    let mut sw = unsafe { StructWriter::new(output, 3) };
    let keys_vec = unsafe { duckdb_struct_vector_get_child(output, 1) };
    let mut list_offset: usize = 0;

    for row in 0..row_count {
        let secret_name = unsafe { secret_reader.read_str(row) };
        let bucket = unsafe { bucket_reader.read_str(row) };
        let prefix = unsafe { prefix_reader.read_str(row) };

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

        unsafe { sw.write_bool(row, 0, result.success) };
        unsafe { super::dns::write_string_list(keys_vec, row, &result.keys, &mut list_offset) };
        unsafe { sw.write_varchar(row, 2, &result.message) };
    }
});

// ---------------------------------------------------------------------------
// Secrets-Aware SMTP Overload
// ---------------------------------------------------------------------------

// smtp_send_secret(secret_name, from, to, subject, body) -> STRUCT(success, message)
quack_rs::scalar_callback!(cb_smtp_send_secret, |_info, input, output| {
    let chunk = unsafe { DataChunk::from_raw(input) };
    let row_count = chunk.size();
    let secret_reader = unsafe { chunk.reader(0) };
    let from_reader = unsafe { chunk.reader(1) };
    let to_reader = unsafe { chunk.reader(2) };
    let subject_reader = unsafe { chunk.reader(3) };
    let body_reader = unsafe { chunk.reader(4) };

    let mut sw = unsafe { StructWriter::new(output, 2) };

    for row in 0..row_count {
        let secret_name = unsafe { secret_reader.read_str(row) };

        let (success, message) = match resolve_smtp_config(
            secret_name,
            unsafe { from_reader.read_str(row) },
            unsafe { to_reader.read_str(row) },
            unsafe { subject_reader.read_str(row) },
            unsafe { body_reader.read_str(row) },
        ) {
            Ok(config) => {
                let r = crate::smtp::send(&config);
                (r.success, r.message)
            }
            Err(e) => (false, e),
        };

        unsafe { sw.write_bool(row, 0, success) };
        unsafe { sw.write_varchar(row, 1, &message) };
    }
});

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

// vault_read_secret(secret_name, vault_url, path) -> STRUCT
quack_rs::scalar_callback!(cb_vault_read_secret, |_info, input, output| {
    let chunk = unsafe { DataChunk::from_raw(input) };
    let row_count = chunk.size();
    let secret_reader = unsafe { chunk.reader(0) };
    let url_reader = unsafe { chunk.reader(1) };
    let path_reader = unsafe { chunk.reader(2) };

    let mut sw = unsafe { StructWriter::new(output, 5) };

    for row in 0..row_count {
        let secret_name = unsafe { secret_reader.read_str(row) };
        let url = unsafe { url_reader.read_str(row) };
        let path = unsafe { path_reader.read_str(row) };

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

        unsafe { sw.write_bool(row, 0, result.success) };
        unsafe { sw.write_varchar(row, 1, &result.data) };
        unsafe { sw.write_i64(row, 2, result.lease_duration) };
        unsafe { sw.write_bool(row, 3, result.renewable) };
        unsafe { sw.write_varchar(row, 4, &result.message) };
    }
});

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

// secrets_list_scan table scan callback
quack_rs::table_scan_callback!(secrets_list_scan, |info, output| {
    let init_data = match unsafe { FfiInitData::<SecretsListInitData>::get_mut(info) } {
        Some(d) => d,
        None => {
            unsafe { duckdb_data_chunk_set_size(output, 0) };
            return;
        }
    };

    if init_data.entries.is_empty() && init_data.idx == 0 {
        init_data.entries = secrets::list_secrets();
    }

    let out_chunk = unsafe { DataChunk::from_raw(output) };
    let mut name_w = unsafe { out_chunk.writer(0) };
    let mut type_w = unsafe { out_chunk.writer(1) };
    let mut count_w = unsafe { out_chunk.writer(2) };

    let mut count: usize = 0;
    let max_chunk = 2048;

    while init_data.idx < init_data.entries.len() && count < max_chunk {
        let (name, stype, key_count) = &init_data.entries[init_data.idx];
        unsafe { name_w.write_varchar(count, name) };
        unsafe { type_w.write_varchar(count, stype) };
        unsafe { count_w.write_i32(count, *key_count as i32) };
        init_data.idx += 1;
        count += 1;
    }

    unsafe { duckdb_data_chunk_set_size(output, count as idx_t) };
});

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
