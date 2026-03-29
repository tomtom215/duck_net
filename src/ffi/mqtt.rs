// SPDX-License-Identifier: MIT
// Copyright 2026 Tom F. <tomf@tomtomtech.net> (https://github.com/tomtom215)

use libduckdb_sys::*;
use quack_rs::prelude::*;

use crate::mqtt;

use super::scalars::write_varchar;

fn mqtt_result_type() -> LogicalType {
    LogicalType::struct_type_from_logical(&[
        ("success", LogicalType::new(TypeId::Boolean)),
        ("message", LogicalType::new(TypeId::Varchar)),
    ])
}

/// mqtt_publish(broker, topic, payload) -> STRUCT(success, message)
unsafe extern "C" fn cb_mqtt_publish(
    _info: duckdb_function_info,
    input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    let chunk = DataChunk::from_raw(input);
    let row_count = chunk.size();
    let broker_reader = chunk.reader(0);
    let topic_reader = chunk.reader(1);
    let payload_reader = chunk.reader(2);

    let mut success_w = StructVector::field_writer(output, 0);
    let message_vec = duckdb_struct_vector_get_child(output, 1);

    for row in 0..row_count {
        let broker = broker_reader.read_str(row);
        let topic = topic_reader.read_str(row);
        let payload = payload_reader.read_str(row);

        let result = mqtt::publish(broker, topic, payload);

        success_w.write_bool(row, result.success);
        write_varchar(message_vec, row, &result.message);
    }
}

/// mqtt_publish_qos1(broker, topic, payload, retain) -> STRUCT(success, message)
unsafe extern "C" fn cb_mqtt_publish_qos1(
    _info: duckdb_function_info,
    input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    let chunk = DataChunk::from_raw(input);
    let row_count = chunk.size();
    let broker_reader = chunk.reader(0);
    let topic_reader = chunk.reader(1);
    let payload_reader = chunk.reader(2);
    let retain_reader = chunk.reader(3);

    let mut success_w = StructVector::field_writer(output, 0);
    let message_vec = duckdb_struct_vector_get_child(output, 1);

    for row in 0..row_count {
        let broker = broker_reader.read_str(row);
        let topic = topic_reader.read_str(row);
        let payload = payload_reader.read_str(row);
        let retain = retain_reader.read_bool(row);

        let result = mqtt::publish_qos1(broker, topic, payload, retain);

        success_w.write_bool(row, result.success);
        write_varchar(message_vec, row, &result.message);
    }
}

pub unsafe fn register_all(con: duckdb_connection) -> Result<(), ExtensionError> {
    let v = TypeId::Varchar;

    ScalarFunctionBuilder::new("mqtt_publish")
        .param(v) // broker
        .param(v) // topic
        .param(v) // payload
        .returns_logical(mqtt_result_type())
        .function(cb_mqtt_publish)
        .null_handling(NullHandling::SpecialNullHandling)
        .register(con)?;

    // mqtt_publish_qos1(broker, topic, payload, retain) -> STRUCT
    ScalarFunctionBuilder::new("mqtt_publish_qos1")
        .param(v)
        .param(v)
        .param(v)
        .param(TypeId::Boolean)
        .returns_logical(mqtt_result_type())
        .function(cb_mqtt_publish_qos1)
        .null_handling(NullHandling::SpecialNullHandling)
        .register(con)?;

    Ok(())
}
