// SPDX-License-Identifier: MIT
// Copyright 2026 Tom F. <tomf@tomtomtech.net> (https://github.com/tomtom215)

use libduckdb_sys::*;
use quack_rs::prelude::*;

use crate::nats;

fn nats_result_type() -> LogicalType {
    LogicalType::struct_type_from_logical(&[
        ("success", LogicalType::new(TypeId::Boolean)),
        ("message", LogicalType::new(TypeId::Varchar)),
    ])
}

fn nats_request_result_type() -> LogicalType {
    LogicalType::struct_type_from_logical(&[
        ("success", LogicalType::new(TypeId::Boolean)),
        ("response", LogicalType::new(TypeId::Varchar)),
        ("message", LogicalType::new(TypeId::Varchar)),
    ])
}

// nats_publish(url, subject, payload) -> STRUCT(success, message)
quack_rs::scalar_callback!(cb_nats_publish, |_info, input, output| {
    let chunk = unsafe { DataChunk::from_raw(input) };
    let row_count = chunk.size();
    let url_reader = unsafe { chunk.reader(0) };
    let subject_reader = unsafe { chunk.reader(1) };
    let payload_reader = unsafe { chunk.reader(2) };

    let mut sw = unsafe { StructWriter::new(output, 2) };

    for row in 0..row_count {
        let url = unsafe { url_reader.read_str(row) };
        let subject = unsafe { subject_reader.read_str(row) };
        let payload = unsafe { payload_reader.read_str(row) };

        let result = nats::publish(url, subject, payload);

        unsafe { sw.write_bool(row, 0, result.success) };
        unsafe { sw.write_varchar(row, 1, &result.message) };
    }
});

// nats_request(url, subject, payload, timeout_ms) -> STRUCT(success, response, message)
quack_rs::scalar_callback!(cb_nats_request, |_info, input, output| {
    let chunk = unsafe { DataChunk::from_raw(input) };
    let row_count = chunk.size();
    let url_reader = unsafe { chunk.reader(0) };
    let subject_reader = unsafe { chunk.reader(1) };
    let payload_reader = unsafe { chunk.reader(2) };
    let timeout_reader = unsafe { chunk.reader(3) };

    let mut sw = unsafe { StructWriter::new(output, 3) };

    for row in 0..row_count {
        let url = unsafe { url_reader.read_str(row) };
        let subject = unsafe { subject_reader.read_str(row) };
        let payload = unsafe { payload_reader.read_str(row) };
        let timeout_ms = unsafe { timeout_reader.read_i32(row) };

        let result = nats::request(url, subject, payload, timeout_ms as u32);

        unsafe { sw.write_bool(row, 0, result.success) };
        unsafe { sw.write_varchar(row, 1, &result.response) };
        unsafe { sw.write_varchar(row, 2, &result.message) };
    }
});

// nats_request(url, subject, payload) -> STRUCT(success, response, message) with 5000ms default timeout
quack_rs::scalar_callback!(cb_nats_request_default, |_info, input, output| {
    let chunk = unsafe { DataChunk::from_raw(input) };
    let row_count = chunk.size();
    let url_reader = unsafe { chunk.reader(0) };
    let subject_reader = unsafe { chunk.reader(1) };
    let payload_reader = unsafe { chunk.reader(2) };

    let mut sw = unsafe { StructWriter::new(output, 3) };

    for row in 0..row_count {
        let url = unsafe { url_reader.read_str(row) };
        let subject = unsafe { subject_reader.read_str(row) };
        let payload = unsafe { payload_reader.read_str(row) };

        let result = nats::request(url, subject, payload, 5000);

        unsafe { sw.write_bool(row, 0, result.success) };
        unsafe { sw.write_varchar(row, 1, &result.response) };
        unsafe { sw.write_varchar(row, 2, &result.message) };
    }
});

// ===== nats_subscribe table function =====

struct NatsSubscribeBindData {
    url: String,
    subject: String,
    max_messages: i64,
    timeout_ms: i32,
}

struct NatsSubscribeInitData {
    messages: Vec<nats::NatsSubMessage>,
    idx: usize,
    fetched: bool,
}

unsafe extern "C" fn nats_subscribe_bind(info: duckdb_bind_info) {
    let bind = BindInfo::new(info);
    let url = bind.get_parameter_value(0).as_str().unwrap_or_default();
    let subject = bind.get_parameter_value(1).as_str().unwrap_or_default();

    let max_val = bind.get_named_parameter_value("max_messages");
    let max_messages = if max_val.is_null() {
        1000
    } else {
        max_val.as_i64()
    };

    let timeout_val = bind.get_named_parameter_value("timeout_ms");
    let timeout_ms = if timeout_val.is_null() {
        5000i32
    } else {
        timeout_val.as_i64() as i32
    };

    bind.add_result_column("subject", TypeId::Varchar);
    bind.add_result_column("reply_to", TypeId::Varchar);
    bind.add_result_column("payload", TypeId::Varchar);

    FfiBindData::<NatsSubscribeBindData>::set(
        info,
        NatsSubscribeBindData {
            url,
            subject,
            max_messages,
            timeout_ms,
        },
    );
}

unsafe extern "C" fn nats_subscribe_init(info: duckdb_init_info) {
    FfiInitData::<NatsSubscribeInitData>::set(
        info,
        NatsSubscribeInitData {
            messages: vec![],
            idx: 0,
            fetched: false,
        },
    );
}

quack_rs::table_scan_callback!(nats_subscribe_scan, |info, output| {
    let bind_data = match unsafe { FfiBindData::<NatsSubscribeBindData>::get_from_function(info) } {
        Some(d) => d,
        None => {
            unsafe { DataChunk::from_raw(output).set_size(0) };
            return;
        }
    };
    let init_data = match unsafe { FfiInitData::<NatsSubscribeInitData>::get_mut(info) } {
        Some(d) => d,
        None => {
            unsafe { DataChunk::from_raw(output).set_size(0) };
            return;
        }
    };

    if !init_data.fetched {
        init_data.fetched = true;
        let result = nats::subscribe(
            &bind_data.url,
            &bind_data.subject,
            bind_data.max_messages,
            bind_data.timeout_ms.max(100) as u32,
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
    let mut subj_w = unsafe { out_chunk.writer(0) };
    let mut reply_w = unsafe { out_chunk.writer(1) };
    let mut payload_w = unsafe { out_chunk.writer(2) };

    let mut count: idx_t = 0;
    let max_chunk = 2048;

    while init_data.idx < init_data.messages.len() && count < max_chunk {
        let m = &init_data.messages[init_data.idx];
        let row = count as usize;
        unsafe { subj_w.write_varchar(row, &m.subject) };
        unsafe { reply_w.write_varchar(row, &m.reply_to) };
        unsafe { payload_w.write_varchar(row, &m.payload) };
        init_data.idx += 1;
        count += 1;
    }

    unsafe { out_chunk.set_size(count as usize) };
});

pub unsafe fn register_all(con: &Connection) -> Result<(), ExtensionError> {
    let v = TypeId::Varchar;

    ScalarFunctionBuilder::new("nats_publish")
        .param(v) // url
        .param(v) // subject
        .param(v) // payload
        .returns_logical(nats_result_type())
        .function(cb_nats_publish)
        .null_handling(NullHandling::SpecialNullHandling)
        .register(con.as_raw_connection())?;

    // nats_request: 3-param (default 5s timeout) and 4-param overloads
    ScalarFunctionSetBuilder::new("nats_request")
        .overload(
            ScalarOverloadBuilder::new()
                .param(v) // url
                .param(v) // subject
                .param(v) // payload
                .returns_logical(nats_request_result_type())
                .function(cb_nats_request_default)
                .null_handling(NullHandling::SpecialNullHandling),
        )
        .overload(
            ScalarOverloadBuilder::new()
                .param(v) // url
                .param(v) // subject
                .param(v) // payload
                .param(TypeId::Integer) // timeout_ms
                .returns_logical(nats_request_result_type())
                .function(cb_nats_request)
                .null_handling(NullHandling::SpecialNullHandling),
        )
        .register(con.as_raw_connection())?;

    // nats_subscribe(url, subject, [max_messages=1000], [timeout_ms=5000])
    // -> TABLE(subject VARCHAR, reply_to VARCHAR, payload VARCHAR)
    TableFunctionBuilder::new("nats_subscribe")
        .param(v) // url
        .param(v) // subject
        .named_param("max_messages", TypeId::BigInt)
        .named_param("timeout_ms", TypeId::Integer)
        .bind(nats_subscribe_bind)
        .init(nats_subscribe_init)
        .scan(nats_subscribe_scan)
        .register(con.as_raw_connection())?;

    Ok(())
}
