// SPDX-License-Identifier: MIT
// Copyright 2026 Tom F. <tomf@tomtomtech.net> (https://github.com/tomtom215)

use quack_rs::prelude::*;

use crate::zeromq;

// duck_net_allow_zeromq_plaintext(allowed BOOLEAN) -> VARCHAR
// Explicitly opt in (or out) of NULL-security ZeroMQ.
// Required before zmq_request will succeed (secure-by-default).
quack_rs::scalar_callback!(cb_allow_zeromq_plaintext, |_info, input, output| {
    let chunk = unsafe { DataChunk::from_raw(input) };
    let row_count = chunk.size();
    let bool_reader = unsafe { chunk.reader(0) };
    let mut writer = unsafe { VectorWriter::from_vector(output) };

    for row in 0..row_count {
        let allowed = unsafe { bool_reader.read_bool(row) };
        zeromq::set_plaintext_allowed(allowed);
        let msg = if allowed {
            "ZeroMQ plaintext (NULL security) ENABLED. \
             All ZeroMQ messages will be sent unencrypted. \
             Only use on fully trusted networks. \
             CURVE encryption is not yet available in duck_net."
        } else {
            "ZeroMQ plaintext (NULL security) DISABLED (default). \
             zmq_request calls will be blocked until re-enabled."
        };
        unsafe { writer.write_varchar(row, msg) };
    }
});

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

pub unsafe fn register_all(con: &Connection) -> Result<(), ExtensionError> {
    let v = TypeId::Varchar;

    // zmq_request(endpoint, message) -> STRUCT(success, response, message)
    ScalarFunctionBuilder::new("zmq_request")
        .param(v) // endpoint
        .param(v) // message
        .returns_logical(zmq_result_type())
        .function(cb_zmq_request)
        .null_handling(NullHandling::SpecialNullHandling)
        .register(con.as_raw_connection())?;

    // duck_net_allow_zeromq_plaintext(allowed BOOLEAN) -> VARCHAR
    // Explicit opt-in required; plaintext ZeroMQ is blocked by default.
    ScalarFunctionBuilder::new("duck_net_allow_zeromq_plaintext")
        .param(TypeId::Boolean)
        .returns(TypeId::Varchar)
        .function(cb_allow_zeromq_plaintext)
        .register(con.as_raw_connection())?;

    Ok(())
}
