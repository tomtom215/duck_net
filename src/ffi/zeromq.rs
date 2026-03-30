// SPDX-License-Identifier: MIT
// Copyright 2026 Tom F. <tomf@tomtomtech.net> (https://github.com/tomtom215)

use libduckdb_sys::*;
use quack_rs::prelude::*;

use crate::zeromq;

fn zmq_result_type() -> LogicalType {
    LogicalType::struct_type_from_logical(&[
        ("success", LogicalType::new(TypeId::Boolean)),
        ("response", LogicalType::new(TypeId::Varchar)),
        ("message", LogicalType::new(TypeId::Varchar)),
    ])
}

// zmq_request(endpoint, message) -> STRUCT(success, response, message)
quack_rs::scalar_callback!(cb_zmq_request, |_info, input, output| {
    let chunk = unsafe { DataChunk::from_raw(input) };
    let row_count = chunk.size();
    let endpoint_reader = unsafe { chunk.reader(0) };
    let message_reader = unsafe { chunk.reader(1) };

    let mut sw = unsafe { StructWriter::new(output, 3) };

    for row in 0..row_count {
        let endpoint = unsafe { endpoint_reader.read_str(row) };
        let message = unsafe { message_reader.read_str(row) };

        let result = zeromq::request(endpoint, message);

        unsafe { sw.write_bool(row, 0, result.success) };
        unsafe { sw.write_varchar(row, 1, &result.response) };
        unsafe { sw.write_varchar(row, 2, &result.message) };
    }
});

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
