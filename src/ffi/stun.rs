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
    let row_count = duckdb_data_chunk_get_size(input);
    let server_reader = VectorReader::new(input, 0);

    let success_vec = duckdb_struct_vector_get_child(output, 0);
    let ip_vec = duckdb_struct_vector_get_child(output, 1);
    let port_vec = duckdb_struct_vector_get_child(output, 2);
    let message_vec = duckdb_struct_vector_get_child(output, 3);

    for row in 0..row_count {
        let server = server_reader.read_str(row as usize);

        let result = stun::lookup(server);

        let sd = duckdb_vector_get_data(success_vec) as *mut bool;
        *sd.add(row as usize) = result.success;
        write_varchar(ip_vec, row, &result.public_ip);
        let pd = duckdb_vector_get_data(port_vec) as *mut i32;
        *pd.add(row as usize) = result.public_port as i32;
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
