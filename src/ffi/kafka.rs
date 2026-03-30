// SPDX-License-Identifier: MIT
// Copyright 2026 Tom F. <tomf@tomtomtech.net> (https://github.com/tomtom215)

use libduckdb_sys::*;
use quack_rs::prelude::*;

use crate::kafka;

fn kafka_result_type() -> LogicalType {
    LogicalType::struct_type_from_logical(&[
        ("success", LogicalType::new(TypeId::Boolean)),
        ("partition", LogicalType::new(TypeId::Integer)),
        ("offset", LogicalType::new(TypeId::BigInt)),
        ("message", LogicalType::new(TypeId::Varchar)),
    ])
}

// kafka_produce(brokers, topic, key, value) -> STRUCT(success, partition, offset, message)
quack_rs::scalar_callback!(cb_kafka_produce, |_info, input, output| {
    let chunk = unsafe { DataChunk::from_raw(input) };
    let row_count = chunk.size();
    let brokers_reader = unsafe { chunk.reader(0) };
    let topic_reader = unsafe { chunk.reader(1) };
    let key_reader = unsafe { chunk.reader(2) };
    let value_reader = unsafe { chunk.reader(3) };

    let mut sw = unsafe { StructWriter::new(output, 4) };

    for row in 0..row_count {
        let brokers = unsafe { brokers_reader.read_str(row) };
        let topic = unsafe { topic_reader.read_str(row) };
        let key = unsafe { key_reader.read_str(row) };
        let value = unsafe { value_reader.read_str(row) };

        let key_opt = if key.is_empty() { None } else { Some(key) };
        let result = kafka::produce(brokers, topic, key_opt, value);

        unsafe { sw.write_bool(row, 0, result.success) };
        unsafe { sw.write_i32(row, 1, result.partition) };
        unsafe { sw.write_i64(row, 2, result.offset) };
        unsafe { sw.write_varchar(row, 3, &result.message) };
    }
});

// kafka_produce(brokers, topic, value) -> STRUCT (no key)
quack_rs::scalar_callback!(cb_kafka_produce_no_key, |_info, input, output| {
    let chunk = unsafe { DataChunk::from_raw(input) };
    let row_count = chunk.size();
    let brokers_reader = unsafe { chunk.reader(0) };
    let topic_reader = unsafe { chunk.reader(1) };
    let value_reader = unsafe { chunk.reader(2) };

    let mut sw = unsafe { StructWriter::new(output, 4) };

    for row in 0..row_count {
        let brokers = unsafe { brokers_reader.read_str(row) };
        let topic = unsafe { topic_reader.read_str(row) };
        let value = unsafe { value_reader.read_str(row) };

        let result = kafka::produce(brokers, topic, None, value);

        unsafe { sw.write_bool(row, 0, result.success) };
        unsafe { sw.write_i32(row, 1, result.partition) };
        unsafe { sw.write_i64(row, 2, result.offset) };
        unsafe { sw.write_varchar(row, 3, &result.message) };
    }
});

// ===== kafka_consume table function =====

struct KafkaConsumeBindData {
    brokers: String,
    topic: String,
    partition: i32,
    start_offset: i64,
    max_messages: i64,
}

struct KafkaConsumeInitData {
    messages: Vec<kafka::KafkaConsumeMessage>,
    idx: usize,
    fetched: bool,
    error: Option<String>,
}

unsafe extern "C" fn kafka_consume_bind(info: duckdb_bind_info) {
    let bind = BindInfo::new(info);
    let brokers = bind.get_parameter_value(0).as_str().unwrap_or_default();
    let topic = bind.get_parameter_value(1).as_str().unwrap_or_default();

    let partition_val = bind.get_named_parameter_value("partition");
    let partition = if partition_val.is_null() { 0 } else { partition_val.as_i64() as i32 };

    let offset_val = bind.get_named_parameter_value("start_offset");
    let start_offset = if offset_val.is_null() { -2 } else { offset_val.as_i64() };

    let max_val = bind.get_named_parameter_value("max_messages");
    let max_messages = if max_val.is_null() { 1000 } else { max_val.as_i64() };

    bind.add_result_column("key", TypeId::Varchar);
    bind.add_result_column("value", TypeId::Varchar);
    bind.add_result_column("partition", TypeId::Integer);
    bind.add_result_column("offset", TypeId::BigInt);
    bind.add_result_column("timestamp_ms", TypeId::BigInt);

    FfiBindData::<KafkaConsumeBindData>::set(
        info,
        KafkaConsumeBindData {
            brokers,
            topic,
            partition,
            start_offset,
            max_messages,
        },
    );
}

unsafe extern "C" fn kafka_consume_init(info: duckdb_init_info) {
    FfiInitData::<KafkaConsumeInitData>::set(
        info,
        KafkaConsumeInitData {
            messages: vec![],
            idx: 0,
            fetched: false,
            error: None,
        },
    );
}

quack_rs::table_scan_callback!(kafka_consume_scan, |info, output| {
    let bind_data = match unsafe { FfiBindData::<KafkaConsumeBindData>::get_from_function(info) } {
        Some(d) => d,
        None => {
            unsafe { DataChunk::from_raw(output).set_size(0) };
            return;
        }
    };
    let init_data = match unsafe { FfiInitData::<KafkaConsumeInitData>::get_mut(info) } {
        Some(d) => d,
        None => {
            unsafe { DataChunk::from_raw(output).set_size(0) };
            return;
        }
    };

    if !init_data.fetched {
        init_data.fetched = true;
        let result = kafka::consume(
            &bind_data.brokers,
            &bind_data.topic,
            bind_data.partition,
            bind_data.start_offset,
            bind_data.max_messages,
        );
        if !result.success {
            let fi = FunctionInfo::new(info);
            fi.set_error(&result.message);
            unsafe { DataChunk::from_raw(output).set_size(0) };
            return;
        }
        init_data.messages = result.messages;
    }

    if let Some(ref err) = init_data.error {
        let fi = FunctionInfo::new(info);
        fi.set_error(err);
        unsafe { DataChunk::from_raw(output).set_size(0) };
        return;
    }

    let out_chunk = unsafe { DataChunk::from_raw(output) };
    let mut key_w = unsafe { out_chunk.writer(0) };
    let mut val_w = unsafe { out_chunk.writer(1) };
    let mut part_w = unsafe { out_chunk.writer(2) };
    let mut off_w = unsafe { out_chunk.writer(3) };
    let mut ts_w = unsafe { out_chunk.writer(4) };

    let mut count: idx_t = 0;
    let max_chunk = 2048;

    while init_data.idx < init_data.messages.len() && count < max_chunk {
        let m = &init_data.messages[init_data.idx];
        unsafe { key_w.write_varchar(count as usize, &m.key) };
        unsafe { val_w.write_varchar(count as usize, &m.value) };
        unsafe { part_w.write_i32(count as usize, m.partition) };
        unsafe { off_w.write_i64(count as usize, m.offset) };
        unsafe { ts_w.write_i64(count as usize, m.timestamp_ms) };
        init_data.idx += 1;
        count += 1;
    }

    unsafe { out_chunk.set_size(count as usize) };
});

pub unsafe fn register_all(con: &Connection) -> Result<(), ExtensionError> {
    let v = TypeId::Varchar;

    ScalarFunctionSetBuilder::new("kafka_produce")
        .overload(
            ScalarOverloadBuilder::new()
                .param(v) // brokers
                .param(v) // topic
                .param(v) // key
                .param(v) // value
                .returns_logical(kafka_result_type())
                .function(cb_kafka_produce)
                .null_handling(NullHandling::SpecialNullHandling),
        )
        .overload(
            ScalarOverloadBuilder::new()
                .param(v) // brokers
                .param(v) // topic
                .param(v) // value
                .returns_logical(kafka_result_type())
                .function(cb_kafka_produce_no_key)
                .null_handling(NullHandling::SpecialNullHandling),
        )
        .register(con.as_raw_connection())?;

    // kafka_consume(brokers, topic, [partition=0], [start_offset=-2], [max_messages=1000])
    TableFunctionBuilder::new("kafka_consume")
        .param(v) // brokers
        .param(v) // topic
        .named_param("partition", TypeId::Integer)
        .named_param("start_offset", TypeId::BigInt)
        .named_param("max_messages", TypeId::BigInt)
        .bind(kafka_consume_bind)
        .init(kafka_consume_init)
        .scan(kafka_consume_scan)
        .register(con.as_raw_connection())?;

    Ok(())
}
