// SPDX-License-Identifier: MIT
// Copyright 2026 Tom F. <tomf@tomtomtech.net> (https://github.com/tomtom215)

use libduckdb_sys::*;
use quack_rs::prelude::*;

use crate::zeromq;

use super::scalars::write_varchar;

fn zmq_result_type() -> LogicalType {
    LogicalType::struct_type_from_logical(&[
        ("success", LogicalType::new(TypeId::Boolean)),
        ("response", LogicalType::new(TypeId::Varchar)),
        ("message", LogicalType::new(TypeId::Varchar)),
    ])
}

/// zmq_request(endpoint, message) -> STRUCT(success, response, message)
unsafe extern "C" fn cb_zmq_request(
    _info: duckdb_function_info,
    input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    let chunk = DataChunk::from_raw(input);
    let row_count = chunk.size();
    let endpoint_reader = chunk.reader(0);
    let message_reader = chunk.reader(1);

    let mut success_w = StructVector::field_writer(output, 0);
    let response_vec = duckdb_struct_vector_get_child(output, 1);
    let message_vec = duckdb_struct_vector_get_child(output, 2);

    for row in 0..row_count {
        let endpoint = endpoint_reader.read_str(row);
        let message = message_reader.read_str(row);

        let result = zeromq::request(endpoint, message);

        success_w.write_bool(row, result.success);
        write_varchar(response_vec, row, &result.response);
        write_varchar(message_vec, row, &result.message);
    }
}

pub unsafe fn register_all(con: duckdb_connection) -> Result<(), ExtensionError> {
    let v = TypeId::Varchar;

    ScalarFunctionBuilder::new("zmq_request")
        .param(v) // endpoint
        .param(v) // message
        .returns_logical(zmq_result_type())
        .function(cb_zmq_request)
        .null_handling(NullHandling::SpecialNullHandling)
        .register(con)?;

    Ok(())
}
