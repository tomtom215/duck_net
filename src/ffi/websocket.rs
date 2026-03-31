// SPDX-License-Identifier: MIT
// Copyright 2026 Tom F. <tomf@tomtomtech.net> (https://github.com/tomtom215)

use libduckdb_sys::*;
use quack_rs::prelude::*;

use crate::websocket;

fn ws_result_type() -> LogicalType {
    LogicalType::struct_type_from_logical(&[
        ("success", LogicalType::new(TypeId::Boolean)),
        ("response", LogicalType::new(TypeId::Varchar)),
        ("message", LogicalType::new(TypeId::Varchar)),
    ])
}

// ws_request(url, message) -> STRUCT(success, response, message)
quack_rs::scalar_callback!(cb_ws_request, |_info, input, output| {
    let chunk = unsafe { DataChunk::from_raw(input) };
    let row_count = chunk.size();
    let url_reader = unsafe { chunk.reader(0) };
    let msg_reader = unsafe { chunk.reader(1) };

    let mut sw = unsafe { StructWriter::new(output, 3) };

    for row in 0..row_count {
        let url = unsafe { url_reader.read_str(row) };
        let msg = unsafe { msg_reader.read_str(row) };

        let result = websocket::request_default_timeout(url, msg);

        unsafe { sw.write_bool(row, 0, result.success) };
        unsafe { sw.write_varchar(row, 1, &result.response) };
        unsafe { sw.write_varchar(row, 2, &result.message) };
    }
});

// ws_request(url, message, timeout_secs) -> STRUCT
quack_rs::scalar_callback!(cb_ws_request_timeout, |_info, input, output| {
    let chunk = unsafe { DataChunk::from_raw(input) };
    let row_count = chunk.size();
    let url_reader = unsafe { chunk.reader(0) };
    let msg_reader = unsafe { chunk.reader(1) };
    let timeout_reader = unsafe { chunk.reader(2) };

    let mut sw = unsafe { StructWriter::new(output, 3) };

    for row in 0..row_count {
        let url = unsafe { url_reader.read_str(row) };
        let msg = unsafe { msg_reader.read_str(row) };
        let timeout = unsafe { timeout_reader.read_i32(row) } as u32;

        let result = websocket::request(url, msg, timeout);

        unsafe { sw.write_bool(row, 0, result.success) };
        unsafe { sw.write_varchar(row, 1, &result.response) };
        unsafe { sw.write_varchar(row, 2, &result.message) };
    }
});

fn ws_multi_result_type() -> LogicalType {
    LogicalType::struct_type_from_logical(&[
        ("success", LogicalType::new(TypeId::Boolean)),
        ("responses", LogicalType::new(TypeId::Varchar)),
        ("count", LogicalType::new(TypeId::Integer)),
        ("message", LogicalType::new(TypeId::Varchar)),
    ])
}

// ws_multi_request(url, messages, timeout_secs) -> STRUCT(success, responses, count, message)
// messages is newline-separated VARCHAR
quack_rs::scalar_callback!(cb_ws_multi_request, |_info, input, output| {
    let chunk = unsafe { DataChunk::from_raw(input) };
    let row_count = chunk.size();
    let url_reader = unsafe { chunk.reader(0) };
    let msgs_reader = unsafe { chunk.reader(1) };
    let timeout_reader = unsafe { chunk.reader(2) };

    let mut sw = unsafe { StructWriter::new(output, 4) };

    for row in 0..row_count {
        let url = unsafe { url_reader.read_str(row) };
        let msgs_str = unsafe { msgs_reader.read_str(row) };
        let timeout = unsafe { timeout_reader.read_i32(row) } as u32;

        let msgs: Vec<String> = msgs_str
            .split('\n')
            .map(|s| s.to_string())
            .filter(|s| !s.is_empty())
            .collect();

        let result = websocket::multi_request(url, &msgs, timeout);

        unsafe { sw.write_bool(row, 0, result.success) };
        unsafe { sw.write_varchar(row, 1, &result.responses.join("\n")) };
        unsafe { sw.write_i32(row, 2, result.responses.len() as i32) };
        unsafe { sw.write_varchar(row, 3, &result.message) };
    }
});

// ===== ws_subscribe table function =====

struct WsSubscribeBindData {
    url: String,
    subscribe_msg: String,
    max_messages: i64,
    timeout_secs: i32,
}

struct WsSubscribeInitData {
    messages: Vec<websocket::WsSubscribeMessage>,
    idx: usize,
    fetched: bool,
}

unsafe extern "C" fn ws_subscribe_bind(info: duckdb_bind_info) {
    let bind = BindInfo::new(info);
    let url = bind.get_parameter_value(0).as_str().unwrap_or_default();
    let subscribe_msg = bind.get_parameter_value(1).as_str().unwrap_or_default();

    let max_val = bind.get_named_parameter_value("max_messages");
    let max_messages = if max_val.is_null() {
        1000
    } else {
        max_val.as_i64()
    };

    let timeout_val = bind.get_named_parameter_value("timeout_secs");
    let timeout_secs = if timeout_val.is_null() {
        10i32
    } else {
        timeout_val.as_i64() as i32
    };

    bind.add_result_column("index", TypeId::BigInt);
    bind.add_result_column("data", TypeId::Varchar);

    FfiBindData::<WsSubscribeBindData>::set(
        info,
        WsSubscribeBindData {
            url,
            subscribe_msg,
            max_messages,
            timeout_secs,
        },
    );
}

unsafe extern "C" fn ws_subscribe_init(info: duckdb_init_info) {
    FfiInitData::<WsSubscribeInitData>::set(
        info,
        WsSubscribeInitData {
            messages: vec![],
            idx: 0,
            fetched: false,
        },
    );
}

quack_rs::table_scan_callback!(ws_subscribe_scan, |info, output| {
    let bind_data = match unsafe { FfiBindData::<WsSubscribeBindData>::get_from_function(info) } {
        Some(d) => d,
        None => {
            unsafe { DataChunk::from_raw(output).set_size(0) };
            return;
        }
    };
    let init_data = match unsafe { FfiInitData::<WsSubscribeInitData>::get_mut(info) } {
        Some(d) => d,
        None => {
            unsafe { DataChunk::from_raw(output).set_size(0) };
            return;
        }
    };

    if !init_data.fetched {
        init_data.fetched = true;
        let result = websocket::subscribe(
            &bind_data.url,
            &bind_data.subscribe_msg,
            bind_data.max_messages,
            bind_data.timeout_secs.max(1) as u32,
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
    let mut idx_w = unsafe { out_chunk.writer(0) };
    let mut data_w = unsafe { out_chunk.writer(1) };

    let mut count: idx_t = 0;
    let max_chunk = 2048;

    while init_data.idx < init_data.messages.len() && count < max_chunk {
        let m = &init_data.messages[init_data.idx];
        let row = count as usize;
        unsafe { idx_w.write_i64(row, m.index) };
        unsafe { data_w.write_varchar(row, &m.data) };
        init_data.idx += 1;
        count += 1;
    }

    unsafe { out_chunk.set_size(count as usize) };
});

pub unsafe fn register_all(con: &Connection) -> Result<(), ExtensionError> {
    let v = TypeId::Varchar;

    ScalarFunctionSetBuilder::new("ws_request")
        .overload(
            ScalarOverloadBuilder::new()
                .param(v) // url
                .param(v) // message
                .returns_logical(ws_result_type())
                .function(cb_ws_request)
                .null_handling(NullHandling::SpecialNullHandling),
        )
        .overload(
            ScalarOverloadBuilder::new()
                .param(v) // url
                .param(v) // message
                .param(TypeId::Integer) // timeout_secs
                .returns_logical(ws_result_type())
                .function(cb_ws_request_timeout)
                .null_handling(NullHandling::SpecialNullHandling),
        )
        .register(con.as_raw_connection())?;

    // ws_multi_request(url, messages, timeout_secs) -> STRUCT(success, responses, count, message)
    ScalarFunctionBuilder::new("ws_multi_request")
        .param(v) // url
        .param(v) // messages (newline-separated)
        .param(TypeId::Integer) // timeout_secs
        .returns_logical(ws_multi_result_type())
        .function(cb_ws_multi_request)
        .null_handling(NullHandling::SpecialNullHandling)
        .register(con.as_raw_connection())?;

    // ws_subscribe(url, subscribe_msg, [max_messages=1000], [timeout_secs=10])
    // -> TABLE(index BIGINT, data VARCHAR)
    TableFunctionBuilder::new("ws_subscribe")
        .param(v) // url
        .param(v) // subscribe_msg (sent on connect, empty = just listen)
        .named_param("max_messages", TypeId::BigInt)
        .named_param("timeout_secs", TypeId::Integer)
        .bind(ws_subscribe_bind)
        .init(ws_subscribe_init)
        .scan(ws_subscribe_scan)
        .register(con.as_raw_connection())?;

    Ok(())
}
