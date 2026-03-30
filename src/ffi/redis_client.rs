// SPDX-License-Identifier: MIT
// Copyright 2026 Tom F. <tomf@tomtomtech.net> (https://github.com/tomtom215)

use libduckdb_sys::*;
use quack_rs::prelude::*;

use crate::redis_client;

use super::dns::write_string_list;

fn redis_result_type() -> LogicalType {
    LogicalType::struct_type_from_logical(&[
        ("success", LogicalType::new(TypeId::Boolean)),
        ("value", LogicalType::new(TypeId::Varchar)),
    ])
}

fn redis_keys_result_type() -> LogicalType {
    LogicalType::struct_type_from_logical(&[
        ("success", LogicalType::new(TypeId::Boolean)),
        (
            "keys",
            LogicalType::list_from_logical(&LogicalType::new(TypeId::Varchar)),
        ),
        ("message", LogicalType::new(TypeId::Varchar)),
    ])
}

// redis_get(url, key) -> STRUCT(success, value)
quack_rs::scalar_callback!(cb_redis_get, |_info, input, output| {
    let chunk = unsafe { DataChunk::from_raw(input) };
    let row_count = chunk.size();
    let url_reader = unsafe { chunk.reader(0) };
    let key_reader = unsafe { chunk.reader(1) };

    let mut sw = unsafe { StructWriter::new(output, 2) };

    for row in 0..row_count {
        let url = unsafe { url_reader.read_str(row) };
        let key = unsafe { key_reader.read_str(row) };

        let result = redis_client::get(url, key);

        unsafe { sw.write_bool(row, 0, result.success) };
        unsafe { sw.write_varchar(row, 1, &result.value) };
    }
});

// redis_set(url, key, value) -> STRUCT(success, value)
quack_rs::scalar_callback!(cb_redis_set, |_info, input, output| {
    let chunk = unsafe { DataChunk::from_raw(input) };
    let row_count = chunk.size();
    let url_reader = unsafe { chunk.reader(0) };
    let key_reader = unsafe { chunk.reader(1) };
    let value_reader = unsafe { chunk.reader(2) };

    let mut sw = unsafe { StructWriter::new(output, 2) };

    for row in 0..row_count {
        let url = unsafe { url_reader.read_str(row) };
        let key = unsafe { key_reader.read_str(row) };
        let value = unsafe { value_reader.read_str(row) };

        let result = redis_client::set(url, key, value);

        unsafe { sw.write_bool(row, 0, result.success) };
        unsafe { sw.write_varchar(row, 1, &result.value) };
    }
});

// redis_set(url, key, value, ttl_secs) -> STRUCT(success, value)
quack_rs::scalar_callback!(cb_redis_set_ex, |_info, input, output| {
    let chunk = unsafe { DataChunk::from_raw(input) };
    let row_count = chunk.size();
    let url_reader = unsafe { chunk.reader(0) };
    let key_reader = unsafe { chunk.reader(1) };
    let value_reader = unsafe { chunk.reader(2) };
    let ttl_reader = unsafe { chunk.reader(3) };

    let mut sw = unsafe { StructWriter::new(output, 2) };

    for row in 0..row_count {
        let url = unsafe { url_reader.read_str(row) };
        let key = unsafe { key_reader.read_str(row) };
        let value = unsafe { value_reader.read_str(row) };
        let ttl = unsafe { ttl_reader.read_i64(row) };

        let result = redis_client::set_ex(url, key, value, ttl);

        unsafe { sw.write_bool(row, 0, result.success) };
        unsafe { sw.write_varchar(row, 1, &result.value) };
    }
});

// redis_keys(url, pattern) -> STRUCT(success, keys, message)
quack_rs::scalar_callback!(cb_redis_keys, |_info, input, output| {
    let chunk = unsafe { DataChunk::from_raw(input) };
    let row_count = chunk.size();
    let url_reader = unsafe { chunk.reader(0) };
    let pattern_reader = unsafe { chunk.reader(1) };

    let mut sw = unsafe { StructWriter::new(output, 3) };
    let keys_vec = sw.child_vector(1);
    let mut list_offset: usize = 0;

    for row in 0..row_count {
        let url = unsafe { url_reader.read_str(row) };
        let pattern = unsafe { pattern_reader.read_str(row) };

        let result = redis_client::keys(url, pattern);

        unsafe { sw.write_bool(row, 0, result.success) };
        unsafe { write_string_list(keys_vec, row, &result.keys, &mut list_offset) };
        unsafe { sw.write_varchar(row, 2, &result.message) };
    }
});

// redis_del(url, key) -> STRUCT(success, value)
quack_rs::scalar_callback!(cb_redis_del, |_info, input, output| {
    let chunk = unsafe { DataChunk::from_raw(input) };
    let row_count = chunk.size();
    let url_reader = unsafe { chunk.reader(0) };
    let key_reader = unsafe { chunk.reader(1) };

    let mut sw = unsafe { StructWriter::new(output, 2) };

    for row in 0..row_count {
        let url = unsafe { url_reader.read_str(row) };
        let key = unsafe { key_reader.read_str(row) };

        let result = redis_client::del(url, key);

        unsafe { sw.write_bool(row, 0, result.success) };
        unsafe { sw.write_varchar(row, 1, &result.value) };
    }
});

// redis_expire(url, key, ttl_secs) -> STRUCT(success, value)
quack_rs::scalar_callback!(cb_redis_expire, |_info, input, output| {
    let chunk = unsafe { DataChunk::from_raw(input) };
    let row_count = chunk.size();
    let url_reader = unsafe { chunk.reader(0) };
    let key_reader = unsafe { chunk.reader(1) };
    let ttl_reader = unsafe { chunk.reader(2) };

    let mut sw = unsafe { StructWriter::new(output, 2) };

    for row in 0..row_count {
        let url = unsafe { url_reader.read_str(row) };
        let key = unsafe { key_reader.read_str(row) };
        let ttl = unsafe { ttl_reader.read_i64(row) };

        let result = redis_client::expire(url, key, ttl);

        unsafe { sw.write_bool(row, 0, result.success) };
        unsafe { sw.write_varchar(row, 1, &result.value) };
    }
});

// redis_hget(url, key, field) -> STRUCT(success, value)
quack_rs::scalar_callback!(cb_redis_hget, |_info, input, output| {
    let chunk = unsafe { DataChunk::from_raw(input) };
    let row_count = chunk.size();
    let url_reader = unsafe { chunk.reader(0) };
    let key_reader = unsafe { chunk.reader(1) };
    let field_reader = unsafe { chunk.reader(2) };

    let mut sw = unsafe { StructWriter::new(output, 2) };

    for row in 0..row_count {
        let url = unsafe { url_reader.read_str(row) };
        let key = unsafe { key_reader.read_str(row) };
        let field = unsafe { field_reader.read_str(row) };

        let result = redis_client::hget(url, key, field);

        unsafe { sw.write_bool(row, 0, result.success) };
        unsafe { sw.write_varchar(row, 1, &result.value) };
    }
});

// redis_hset(url, key, field, value) -> STRUCT(success, value)
quack_rs::scalar_callback!(cb_redis_hset, |_info, input, output| {
    let chunk = unsafe { DataChunk::from_raw(input) };
    let row_count = chunk.size();
    let url_reader = unsafe { chunk.reader(0) };
    let key_reader = unsafe { chunk.reader(1) };
    let field_reader = unsafe { chunk.reader(2) };
    let value_reader = unsafe { chunk.reader(3) };

    let mut sw = unsafe { StructWriter::new(output, 2) };

    for row in 0..row_count {
        let url = unsafe { url_reader.read_str(row) };
        let key = unsafe { key_reader.read_str(row) };
        let field = unsafe { field_reader.read_str(row) };
        let value = unsafe { value_reader.read_str(row) };

        let result = redis_client::hset(url, key, field, value);

        unsafe { sw.write_bool(row, 0, result.success) };
        unsafe { sw.write_varchar(row, 1, &result.value) };
    }
});

pub unsafe fn register_all(con: &Connection) -> Result<(), ExtensionError> {
    let v = TypeId::Varchar;

    // redis_get(url, key) -> STRUCT
    ScalarFunctionBuilder::new("redis_get")
        .param(v) // url
        .param(v) // key
        .returns_logical(redis_result_type())
        .function(cb_redis_get)
        .null_handling(NullHandling::SpecialNullHandling)
        .register(con.as_raw_connection())?;

    // redis_set: 3 or 4 params
    ScalarFunctionSetBuilder::new("redis_set")
        .overload(
            ScalarOverloadBuilder::new()
                .param(v) // url
                .param(v) // key
                .param(v) // value
                .returns_logical(redis_result_type())
                .function(cb_redis_set)
                .null_handling(NullHandling::SpecialNullHandling),
        )
        .overload(
            ScalarOverloadBuilder::new()
                .param(v) // url
                .param(v) // key
                .param(v) // value
                .param(TypeId::BigInt) // ttl_secs
                .returns_logical(redis_result_type())
                .function(cb_redis_set_ex)
                .null_handling(NullHandling::SpecialNullHandling),
        )
        .register(con.as_raw_connection())?;

    // redis_keys(url, pattern) -> STRUCT(success, keys, message)
    ScalarFunctionBuilder::new("redis_keys")
        .param(v) // url
        .param(v) // pattern
        .returns_logical(redis_keys_result_type())
        .function(cb_redis_keys)
        .null_handling(NullHandling::SpecialNullHandling)
        .register(con.as_raw_connection())?;

    // redis_del(url, key) -> STRUCT
    ScalarFunctionBuilder::new("redis_del")
        .param(v)
        .param(v)
        .returns_logical(redis_result_type())
        .function(cb_redis_del)
        .null_handling(NullHandling::SpecialNullHandling)
        .register(con.as_raw_connection())?;

    // redis_expire(url, key, ttl_secs) -> STRUCT
    ScalarFunctionBuilder::new("redis_expire")
        .param(v)
        .param(v)
        .param(TypeId::BigInt)
        .returns_logical(redis_result_type())
        .function(cb_redis_expire)
        .null_handling(NullHandling::SpecialNullHandling)
        .register(con.as_raw_connection())?;

    // redis_hget(url, key, field) -> STRUCT
    ScalarFunctionBuilder::new("redis_hget")
        .param(v)
        .param(v)
        .param(v)
        .returns_logical(redis_result_type())
        .function(cb_redis_hget)
        .null_handling(NullHandling::SpecialNullHandling)
        .register(con.as_raw_connection())?;

    // redis_hset(url, key, field, value) -> STRUCT
    ScalarFunctionBuilder::new("redis_hset")
        .param(v)
        .param(v)
        .param(v)
        .param(v)
        .returns_logical(redis_result_type())
        .function(cb_redis_hset)
        .null_handling(NullHandling::SpecialNullHandling)
        .register(con.as_raw_connection())?;

    // redis_subscribe(url, channel, [max_messages=1000], [timeout_secs=10])
    // -> TABLE(channel VARCHAR, payload VARCHAR)
    TableFunctionBuilder::new("redis_subscribe")
        .param(v) // url
        .param(v) // channel
        .named_param("max_messages", TypeId::BigInt)
        .named_param("timeout_secs", TypeId::BigInt)
        .bind(redis_subscribe_bind)
        .init(redis_subscribe_init)
        .scan(redis_subscribe_scan)
        .register(con.as_raw_connection())?;

    Ok(())
}

// ===== redis_subscribe table function =====

struct RedisSubscribeBindData {
    url: String,
    channel: String,
    max_messages: i64,
    timeout_secs: i64,
}

struct RedisSubscribeInitData {
    messages: Vec<redis_client::RedisSubMessage>,
    idx: usize,
    fetched: bool,
}

unsafe extern "C" fn redis_subscribe_bind(info: duckdb_bind_info) {
    let bind = BindInfo::new(info);
    let url = bind.get_parameter_value(0).as_str().unwrap_or_default();
    let channel = bind.get_parameter_value(1).as_str().unwrap_or_default();

    let max_val = bind.get_named_parameter_value("max_messages");
    let max_messages = if max_val.is_null() { 1000 } else { max_val.as_i64() };

    let timeout_val = bind.get_named_parameter_value("timeout_secs");
    let timeout_secs = if timeout_val.is_null() { 10 } else { timeout_val.as_i64() };

    bind.add_result_column("channel", TypeId::Varchar);
    bind.add_result_column("payload", TypeId::Varchar);

    FfiBindData::<RedisSubscribeBindData>::set(
        info,
        RedisSubscribeBindData {
            url,
            channel,
            max_messages,
            timeout_secs,
        },
    );
}

unsafe extern "C" fn redis_subscribe_init(info: duckdb_init_info) {
    FfiInitData::<RedisSubscribeInitData>::set(
        info,
        RedisSubscribeInitData {
            messages: vec![],
            idx: 0,
            fetched: false,
        },
    );
}

quack_rs::table_scan_callback!(redis_subscribe_scan, |info, output| {
    let bind_data =
        match unsafe { FfiBindData::<RedisSubscribeBindData>::get_from_function(info) } {
            Some(d) => d,
            None => {
                unsafe { DataChunk::from_raw(output).set_size(0) };
                return;
            }
        };
    let init_data =
        match unsafe { FfiInitData::<RedisSubscribeInitData>::get_mut(info) } {
            Some(d) => d,
            None => {
                unsafe { DataChunk::from_raw(output).set_size(0) };
                return;
            }
        };

    if !init_data.fetched {
        init_data.fetched = true;
        let result = redis_client::subscribe(
            &bind_data.url,
            &bind_data.channel,
            bind_data.max_messages,
            bind_data.timeout_secs,
        );
        if !result.success {
            let fi = FunctionInfo::new(info);
            fi.set_error(&result.message);
            unsafe { DataChunk::from_raw(output).set_size(0) };
            return;
        }
        init_data.messages = result.messages;
    }

    let out_chunk = unsafe { DataChunk::from_raw(output) };
    let mut ch_w = unsafe { out_chunk.writer(0) };
    let mut payload_w = unsafe { out_chunk.writer(1) };

    let mut count: idx_t = 0;
    let max_chunk = 2048;

    while init_data.idx < init_data.messages.len() && count < max_chunk {
        let m = &init_data.messages[init_data.idx];
        let row = count as usize;
        unsafe { ch_w.write_varchar(row, &m.channel) };
        unsafe { payload_w.write_varchar(row, &m.payload) };
        init_data.idx += 1;
        count += 1;
    }

    unsafe { out_chunk.set_size(count as usize) };
});
