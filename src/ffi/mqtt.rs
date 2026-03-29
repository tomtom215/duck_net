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
    let row_count = duckdb_data_chunk_get_size(input);
    let broker_reader = VectorReader::new(input, 0);
    let topic_reader = VectorReader::new(input, 1);
    let payload_reader = VectorReader::new(input, 2);

    let success_vec = duckdb_struct_vector_get_child(output, 0);
    let message_vec = duckdb_struct_vector_get_child(output, 1);

    for row in 0..row_count {
        let broker = broker_reader.read_str(row as usize);
        let topic = topic_reader.read_str(row as usize);
        let payload = payload_reader.read_str(row as usize);

        let result = mqtt::publish(broker, topic, payload);

        let sd = duckdb_vector_get_data(success_vec) as *mut bool;
        *sd.add(row as usize) = result.success;
        write_varchar(message_vec, row, &result.message);
    }
}

/// mqtt_publish_qos1(broker, topic, payload, retain) -> STRUCT(success, message)
unsafe extern "C" fn cb_mqtt_publish_qos1(
    _info: duckdb_function_info,
    input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    let row_count = duckdb_data_chunk_get_size(input);
    let broker_reader = VectorReader::new(input, 0);
    let topic_reader = VectorReader::new(input, 1);
    let payload_reader = VectorReader::new(input, 2);

    let success_vec = duckdb_struct_vector_get_child(output, 0);
    let message_vec = duckdb_struct_vector_get_child(output, 1);

    for row in 0..row_count {
        let broker = broker_reader.read_str(row as usize);
        let topic = topic_reader.read_str(row as usize);
        let payload = payload_reader.read_str(row as usize);

        let retain_data = duckdb_vector_get_data(duckdb_data_chunk_get_vector(input, 3)) as *const bool;
        let retain = *retain_data.add(row as usize);

        let result = mqtt::publish_qos1(broker, topic, payload, retain);

        let sd = duckdb_vector_get_data(success_vec) as *mut bool;
        *sd.add(row as usize) = result.success;
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
        .param(v).param(v).param(v).param(TypeId::Boolean)
        .returns_logical(mqtt_result_type())
        .function(cb_mqtt_publish_qos1)
        .null_handling(NullHandling::SpecialNullHandling)
        .register(con)?;

    Ok(())
}
