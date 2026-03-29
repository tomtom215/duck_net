// SPDX-License-Identifier: MIT
// Copyright 2026 Tom F. <tomf@tomtomtech.net> (https://github.com/tomtom215)

use libduckdb_sys::*;
use quack_rs::prelude::*;

use crate::stun;

use super::scalars::write_varchar;

fn stun_result_type() -> LogicalType {
    LogicalType::struct_type_from_logical(&[
        ("success", LogicalType::new(TypeId::Boolean)),
        ("public_ip", LogicalType::new(TypeId::Varchar)),
        ("public_port", LogicalType::new(TypeId::Integer)),
        ("message", LogicalType::new(TypeId::Varchar)),
    ])
}

/// stun_lookup(server) -> STRUCT(success, public_ip, public_port, message)
unsafe extern "C" fn cb_stun_lookup(
    _info: duckdb_function_info,
    input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    let chunk = DataChunk::from_raw(input);
    let row_count = chunk.size();
    let server_reader = chunk.reader(0);

    let mut success_w = StructVector::field_writer(output, 0);
    let ip_vec = duckdb_struct_vector_get_child(output, 1);
    let mut port_w = StructVector::field_writer(output, 2);
    let message_vec = duckdb_struct_vector_get_child(output, 3);

    for row in 0..row_count {
        let server = server_reader.read_str(row);

        let result = stun::lookup(server);

        success_w.write_bool(row, result.success);
        write_varchar(ip_vec, row, &result.public_ip);
        port_w.write_i32(row, result.public_port as i32);
        write_varchar(message_vec, row, &result.message);
    }
}

pub unsafe fn register_all(con: duckdb_connection) -> Result<(), ExtensionError> {
    ScalarFunctionBuilder::new("stun_lookup")
        .param(TypeId::Varchar) // server
        .returns_logical(stun_result_type())
        .function(cb_stun_lookup)
        .null_handling(NullHandling::SpecialNullHandling)
        .register(con)?;

    Ok(())
}
