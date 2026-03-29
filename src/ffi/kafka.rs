// SPDX-License-Identifier: MIT
// Copyright 2026 Tom F. <tomf@tomtomtech.net> (https://github.com/tomtom215)

use libduckdb_sys::*;
use quack_rs::prelude::*;

use crate::kafka;

use super::scalars::write_varchar;

fn kafka_result_type() -> LogicalType {
    LogicalType::struct_type_from_logical(&[
        ("success", LogicalType::new(TypeId::Boolean)),
        ("partition", LogicalType::new(TypeId::Integer)),
        ("offset", LogicalType::new(TypeId::BigInt)),
        ("message", LogicalType::new(TypeId::Varchar)),
    ])
}

/// kafka_produce(brokers, topic, key, value) -> STRUCT(success, partition, offset, message)
unsafe extern "C" fn cb_kafka_produce(
    _info: duckdb_function_info,
    input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    let chunk = DataChunk::from_raw(input);
    let row_count = chunk.size();
    let brokers_reader = chunk.reader(0);
    let topic_reader = chunk.reader(1);
    let key_reader = chunk.reader(2);
    let value_reader = chunk.reader(3);

    let mut success_writer = StructVector::field_writer(output, 0);
    let mut partition_writer = StructVector::field_writer(output, 1);
    let mut offset_writer = StructVector::field_writer(output, 2);
    let message_vec = duckdb_struct_vector_get_child(output, 3);

    for row in 0..row_count {
        let brokers = brokers_reader.read_str(row as usize);
        let topic = topic_reader.read_str(row as usize);
        let key = key_reader.read_str(row as usize);
        let value = value_reader.read_str(row as usize);

        let key_opt = if key.is_empty() { None } else { Some(key) };
        let result = kafka::produce(brokers, topic, key_opt, value);

        unsafe { success_writer.write_bool(row as usize, result.success) };
        unsafe { partition_writer.write_i32(row as usize, result.partition) };
        unsafe { offset_writer.write_i64(row as usize, result.offset) };
        write_varchar(message_vec, row, &result.message);
    }
}

/// kafka_produce(brokers, topic, value) -> STRUCT (no key)
unsafe extern "C" fn cb_kafka_produce_no_key(
    _info: duckdb_function_info,
    input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    let chunk = DataChunk::from_raw(input);
    let row_count = chunk.size();
    let brokers_reader = chunk.reader(0);
    let topic_reader = chunk.reader(1);
    let value_reader = chunk.reader(2);

    let mut success_writer = StructVector::field_writer(output, 0);
    let mut partition_writer = StructVector::field_writer(output, 1);
    let mut offset_writer = StructVector::field_writer(output, 2);
    let message_vec = duckdb_struct_vector_get_child(output, 3);

    for row in 0..row_count {
        let brokers = brokers_reader.read_str(row as usize);
        let topic = topic_reader.read_str(row as usize);
        let value = value_reader.read_str(row as usize);

        let result = kafka::produce(brokers, topic, None, value);

        unsafe { success_writer.write_bool(row as usize, result.success) };
        unsafe { partition_writer.write_i32(row as usize, result.partition) };
        unsafe { offset_writer.write_i64(row as usize, result.offset) };
        write_varchar(message_vec, row, &result.message);
    }
}

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
