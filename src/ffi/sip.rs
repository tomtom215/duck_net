// SPDX-License-Identifier: MIT
// Copyright 2026 Tom F. <tomf@tomtomtech.net> (https://github.com/tomtom215)

use libduckdb_sys::*;
use quack_rs::prelude::*;

use crate::sip;

use super::scalars::write_varchar;

fn sip_result_type() -> LogicalType {
    LogicalType::struct_type_from_logical(&[
        ("alive", LogicalType::new(TypeId::Boolean)),
        ("status_code", LogicalType::new(TypeId::Integer)),
        ("status_text", LogicalType::new(TypeId::Varchar)),
        ("user_agent", LogicalType::new(TypeId::Varchar)),
        ("allow_methods", LogicalType::new(TypeId::Varchar)),
    ])
}

/// sip_options(host) -> STRUCT
unsafe extern "C" fn cb_sip_options(
    _info: duckdb_function_info,
    input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    let chunk = DataChunk::from_raw(input);
    let row_count = chunk.size();
    let host_reader = chunk.reader(0);

    let mut alive_writer = StructVector::field_writer(output, 0);
    let mut code_writer = StructVector::field_writer(output, 1);
    let text_vec = duckdb_struct_vector_get_child(output, 2);
    let ua_vec = duckdb_struct_vector_get_child(output, 3);
    let allow_vec = duckdb_struct_vector_get_child(output, 4);

    for row in 0..row_count {
        let host = host_reader.read_str(row as usize);
        let result = sip::options_ping(host, 0);

        unsafe { alive_writer.write_bool(row as usize, result.alive) };
        unsafe { code_writer.write_i32(row as usize, result.status_code) };
        write_varchar(text_vec, row, &result.status_text);
        write_varchar(ua_vec, row, &result.user_agent);
        write_varchar(allow_vec, row, &result.allow_methods);
    }
}

/// sip_options(host, port) -> STRUCT
unsafe extern "C" fn cb_sip_options_port(
    _info: duckdb_function_info,
    input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    let chunk = DataChunk::from_raw(input);
    let row_count = chunk.size();
    let host_reader = chunk.reader(0);
    let port_reader = chunk.reader(1);

    let mut alive_writer = StructVector::field_writer(output, 0);
    let mut code_writer = StructVector::field_writer(output, 1);
    let text_vec = duckdb_struct_vector_get_child(output, 2);
    let ua_vec = duckdb_struct_vector_get_child(output, 3);
    let allow_vec = duckdb_struct_vector_get_child(output, 4);

    for row in 0..row_count {
        let host = host_reader.read_str(row as usize);
        let port = port_reader.read_i32(row as usize) as u16;
        let result = sip::options_ping(host, port);

        unsafe { alive_writer.write_bool(row as usize, result.alive) };
        unsafe { code_writer.write_i32(row as usize, result.status_code) };
        write_varchar(text_vec, row, &result.status_text);
        write_varchar(ua_vec, row, &result.user_agent);
        write_varchar(allow_vec, row, &result.allow_methods);
    }
}

pub unsafe fn register_all(con: duckdb_connection) -> Result<(), ExtensionError> {
    let v = TypeId::Varchar;

    ScalarFunctionSetBuilder::new("sip_options")
        .overload(
            ScalarOverloadBuilder::new()
                .param(v)
                .returns_logical(sip_result_type())
                .function(cb_sip_options)
                .null_handling(NullHandling::SpecialNullHandling),
        )
        .overload(
            ScalarOverloadBuilder::new()
                .param(v)
                .param(TypeId::Integer)
                .returns_logical(sip_result_type())
                .function(cb_sip_options_port)
                .null_handling(NullHandling::SpecialNullHandling),
        )
        .register(con)?;

    Ok(())
}
