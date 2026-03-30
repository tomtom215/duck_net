// SPDX-License-Identifier: MIT
// Copyright 2026 Tom F. <tomf@tomtomtech.net> (https://github.com/tomtom215)

use libduckdb_sys::*;
use quack_rs::prelude::*;

use crate::amqp;


fn amqp_result_type() -> LogicalType {
    LogicalType::struct_type_from_logical(&[
        ("success", LogicalType::new(TypeId::Boolean)),
        ("message", LogicalType::new(TypeId::Varchar)),
    ])
}

// amqp_publish(url, exchange, routing_key, message) -> STRUCT(success, message)
quack_rs::scalar_callback!(cb_amqp_publish, |_info, input, output| {
    let chunk = unsafe { DataChunk::from_raw(input) };
    let row_count = chunk.size();
    let url_reader = unsafe { chunk.reader(0) };
    let exchange_reader = unsafe { chunk.reader(1) };
    let rk_reader = unsafe { chunk.reader(2) };
    let msg_reader = unsafe { chunk.reader(3) };

    let mut sw = unsafe { StructWriter::new(output, 2) };

    for row in 0..row_count {
        let url = unsafe { url_reader.read_str(row) };
        let exchange = unsafe { exchange_reader.read_str(row) };
        let routing_key = unsafe { rk_reader.read_str(row) };
        let msg = unsafe { msg_reader.read_str(row) };

        let result = amqp::publish(url, exchange, routing_key, msg, None);
        unsafe { sw.write_bool(row, 0, result.success) };
        unsafe { sw.write_varchar(row, 1, &result.message) };
    }
});

// amqp_publish(url, exchange, routing_key, message, content_type) -> STRUCT
quack_rs::scalar_callback!(cb_amqp_publish_ct, |_info, input, output| {
    let chunk = unsafe { DataChunk::from_raw(input) };
    let row_count = chunk.size();
    let url_reader = unsafe { chunk.reader(0) };
    let exchange_reader = unsafe { chunk.reader(1) };
    let rk_reader = unsafe { chunk.reader(2) };
    let msg_reader = unsafe { chunk.reader(3) };
    let ct_reader = unsafe { chunk.reader(4) };

    let mut sw = unsafe { StructWriter::new(output, 2) };

    for row in 0..row_count {
        let url = unsafe { url_reader.read_str(row) };
        let exchange = unsafe { exchange_reader.read_str(row) };
        let routing_key = unsafe { rk_reader.read_str(row) };
        let msg = unsafe { msg_reader.read_str(row) };
        let ct = unsafe { ct_reader.read_str(row) };

        let result = amqp::publish(url, exchange, routing_key, msg, Some(ct));
        unsafe { sw.write_bool(row, 0, result.success) };
        unsafe { sw.write_varchar(row, 1, &result.message) };
    }
});

pub unsafe fn register_all(con: duckdb_connection) -> Result<(), ExtensionError> {
    let v = TypeId::Varchar;

    ScalarFunctionSetBuilder::new("amqp_publish")
        .overload(
            ScalarOverloadBuilder::new()
                .param(v) // url
                .param(v) // exchange
                .param(v) // routing_key
                .param(v) // message
                .returns_logical(amqp_result_type())
                .function(cb_amqp_publish)
                .null_handling(NullHandling::SpecialNullHandling),
        )
        .overload(
            ScalarOverloadBuilder::new()
                .param(v) // url
                .param(v) // exchange
                .param(v) // routing_key
                .param(v) // message
                .param(v) // content_type
                .returns_logical(amqp_result_type())
                .function(cb_amqp_publish_ct)
                .null_handling(NullHandling::SpecialNullHandling),
        )
        .register(con)?;

    Ok(())
}
