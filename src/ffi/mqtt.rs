// SPDX-License-Identifier: MIT
// Copyright 2026 Tom F. <tomf@tomtomtech.net> (https://github.com/tomtom215)

use libduckdb_sys::*;
use quack_rs::prelude::*;

use crate::mqtt;

fn mqtt_result_type() -> LogicalType {
    LogicalType::struct_type_from_logical(&[
        ("success", LogicalType::new(TypeId::Boolean)),
        ("message", LogicalType::new(TypeId::Varchar)),
    ])
}

// mqtt_publish(broker, topic, payload) -> STRUCT(success, message)
quack_rs::scalar_callback!(cb_mqtt_publish, |_info, input, output| {
    let chunk = unsafe { DataChunk::from_raw(input) };
    let row_count = chunk.size();
    let broker_reader = unsafe { chunk.reader(0) };
    let topic_reader = unsafe { chunk.reader(1) };
    let payload_reader = unsafe { chunk.reader(2) };

    let mut sw = unsafe { StructWriter::new(output, 2) };

    for row in 0..row_count {
        let broker = unsafe { broker_reader.read_str(row) };
        let topic = unsafe { topic_reader.read_str(row) };
        let payload = unsafe { payload_reader.read_str(row) };

        let result = mqtt::publish(broker, topic, payload);

        unsafe { sw.write_bool(row, 0, result.success) };
        unsafe { sw.write_varchar(row, 1, &result.message) };
    }
});

// mqtt_publish_qos1(broker, topic, payload, retain) -> STRUCT(success, message)
quack_rs::scalar_callback!(cb_mqtt_publish_qos1, |_info, input, output| {
    let chunk = unsafe { DataChunk::from_raw(input) };
    let row_count = chunk.size();
    let broker_reader = unsafe { chunk.reader(0) };
    let topic_reader = unsafe { chunk.reader(1) };
    let payload_reader = unsafe { chunk.reader(2) };
    let retain_reader = unsafe { chunk.reader(3) };

    let mut sw = unsafe { StructWriter::new(output, 2) };

    for row in 0..row_count {
        let broker = unsafe { broker_reader.read_str(row) };
        let topic = unsafe { topic_reader.read_str(row) };
        let payload = unsafe { payload_reader.read_str(row) };
        let retain = unsafe { retain_reader.read_bool(row) };

        let result = mqtt::publish_qos1(broker, topic, payload, retain);

        unsafe { sw.write_bool(row, 0, result.success) };
        unsafe { sw.write_varchar(row, 1, &result.message) };
    }
});

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
