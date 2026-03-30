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

pub unsafe fn register_all(con: duckdb_connection) -> Result<(), ExtensionError> {
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
        .register(con)?;

    Ok(())
}
