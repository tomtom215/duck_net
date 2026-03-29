// SPDX-License-Identifier: MIT
// Copyright 2026 Tom F. <tomf@tomtomtech.net> (https://github.com/tomtom215)

use libduckdb_sys::*;
use quack_rs::prelude::*;

use crate::bgp;

use super::scalars::write_varchar;

fn bgp_result_type() -> LogicalType {
    LogicalType::struct_type_from_logical(&[
        ("success", LogicalType::new(TypeId::Boolean)),
        ("body", LogicalType::new(TypeId::Varchar)),
        ("message", LogicalType::new(TypeId::Varchar)),
    ])
}

/// bgp_route(prefix) -> STRUCT(success, body, message)
unsafe extern "C" fn cb_bgp_route(
    _info: duckdb_function_info,
    input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    let row_count = duckdb_data_chunk_get_size(input);
    let prefix_reader = VectorReader::new(input, 0);

    let success_vec = duckdb_struct_vector_get_child(output, 0);
    let body_vec = duckdb_struct_vector_get_child(output, 1);
    let message_vec = duckdb_struct_vector_get_child(output, 2);

    for row in 0..row_count {
        let prefix = prefix_reader.read_str(row as usize);

        let result = bgp::route(prefix);

        let sd = duckdb_vector_get_data(success_vec) as *mut bool;
        *sd.add(row as usize) = result.success;
        write_varchar(body_vec, row, &result.body);
        write_varchar(message_vec, row, &result.message);
    }
}

/// bgp_prefix_overview(prefix) -> STRUCT
unsafe extern "C" fn cb_bgp_prefix_overview(
    _info: duckdb_function_info,
    input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    let row_count = duckdb_data_chunk_get_size(input);
    let prefix_reader = VectorReader::new(input, 0);

    let success_vec = duckdb_struct_vector_get_child(output, 0);
    let body_vec = duckdb_struct_vector_get_child(output, 1);
    let message_vec = duckdb_struct_vector_get_child(output, 2);

    for row in 0..row_count {
        let prefix = prefix_reader.read_str(row as usize);

        let result = bgp::prefix_overview(prefix);

        let sd = duckdb_vector_get_data(success_vec) as *mut bool;
        *sd.add(row as usize) = result.success;
        write_varchar(body_vec, row, &result.body);
        write_varchar(message_vec, row, &result.message);
    }
}

/// bgp_asn_info(asn) -> STRUCT
unsafe extern "C" fn cb_bgp_asn_info(
    _info: duckdb_function_info,
    input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    let row_count = duckdb_data_chunk_get_size(input);
    let asn_reader = VectorReader::new(input, 0);

    let success_vec = duckdb_struct_vector_get_child(output, 0);
    let body_vec = duckdb_struct_vector_get_child(output, 1);
    let message_vec = duckdb_struct_vector_get_child(output, 2);

    for row in 0..row_count {
        let asn = asn_reader.read_str(row as usize);

        let result = bgp::asn_info(asn);

        let sd = duckdb_vector_get_data(success_vec) as *mut bool;
        *sd.add(row as usize) = result.success;
        write_varchar(body_vec, row, &result.body);
        write_varchar(message_vec, row, &result.message);
    }
}

pub unsafe fn register_all(con: duckdb_connection) -> Result<(), ExtensionError> {
    let v = TypeId::Varchar;

    // bgp_route(prefix)
    ScalarFunctionBuilder::new("bgp_route")
        .param(v)
        .returns_logical(bgp_result_type())
        .function(cb_bgp_route)
        .null_handling(NullHandling::SpecialNullHandling)
        .register(con)?;

    // bgp_prefix_overview(prefix)
    ScalarFunctionBuilder::new("bgp_prefix_overview")
        .param(v)
        .returns_logical(bgp_result_type())
        .function(cb_bgp_prefix_overview)
        .null_handling(NullHandling::SpecialNullHandling)
        .register(con)?;

    // bgp_asn_info(asn)
    ScalarFunctionBuilder::new("bgp_asn_info")
        .param(v)
        .returns_logical(bgp_result_type())
        .function(cb_bgp_asn_info)
        .null_handling(NullHandling::SpecialNullHandling)
        .register(con)?;

    Ok(())
}
