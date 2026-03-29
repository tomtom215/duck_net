// SPDX-License-Identifier: MIT
// Copyright 2026 Tom F. <tomf@tomtomtech.net> (https://github.com/tomtom215)

use libduckdb_sys::*;
use quack_rs::prelude::*;

use crate::amqp;

use super::scalars::write_varchar;

fn amqp_result_type() -> LogicalType {
    LogicalType::struct_type_from_logical(&[
        ("success", LogicalType::new(TypeId::Boolean)),
        ("message", LogicalType::new(TypeId::Varchar)),
    ])
}

/// amqp_publish(url, exchange, routing_key, message) -> STRUCT(success, message)
unsafe extern "C" fn cb_amqp_publish(
    _info: duckdb_function_info,
    input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    let chunk = DataChunk::from_raw(input);
    let row_count = chunk.size();
    let url_reader = chunk.reader(0);
    let exchange_reader = chunk.reader(1);
    let rk_reader = chunk.reader(2);
    let msg_reader = chunk.reader(3);

    let mut success_w = StructVector::field_writer(output, 0);
    let message_vec = duckdb_struct_vector_get_child(output, 1);

    for row in 0..row_count {
        let url = url_reader.read_str(row);
        let exchange = exchange_reader.read_str(row);
        let routing_key = rk_reader.read_str(row);
        let msg = msg_reader.read_str(row);

        let result = amqp::publish(url, exchange, routing_key, msg, None);
        success_w.write_bool(row, result.success);
        write_varchar(message_vec, row, &result.message);
    }
}

/// amqp_publish(url, exchange, routing_key, message, content_type) -> STRUCT
unsafe extern "C" fn cb_amqp_publish_ct(
    _info: duckdb_function_info,
    input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    let chunk = DataChunk::from_raw(input);
    let row_count = chunk.size();
    let url_reader = chunk.reader(0);
    let exchange_reader = chunk.reader(1);
    let rk_reader = chunk.reader(2);
    let msg_reader = chunk.reader(3);
    let ct_reader = chunk.reader(4);

    let mut success_w = StructVector::field_writer(output, 0);
    let message_vec = duckdb_struct_vector_get_child(output, 1);

    for row in 0..row_count {
        let url = url_reader.read_str(row);
        let exchange = exchange_reader.read_str(row);
        let routing_key = rk_reader.read_str(row);
        let msg = msg_reader.read_str(row);
        let ct = ct_reader.read_str(row);

        let result = amqp::publish(url, exchange, routing_key, msg, Some(ct));
        success_w.write_bool(row, result.success);
        write_varchar(message_vec, row, &result.message);
    }
}

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
