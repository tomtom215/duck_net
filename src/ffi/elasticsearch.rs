// SPDX-License-Identifier: MIT
// Copyright 2026 Tom F. <tomf@tomtomtech.net> (https://github.com/tomtom215)

use libduckdb_sys::*;
use quack_rs::prelude::*;

use crate::elasticsearch;

use super::scalars::write_varchar;

fn es_result_type() -> LogicalType {
    LogicalType::struct_type_from_logical(&[
        ("success", LogicalType::new(TypeId::Boolean)),
        ("body", LogicalType::new(TypeId::Varchar)),
        ("message", LogicalType::new(TypeId::Varchar)),
    ])
}

/// es_search(url, index, query_json) -> STRUCT(success, body, message)
unsafe extern "C" fn cb_es_search(
    _info: duckdb_function_info,
    input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    let chunk = DataChunk::from_raw(input);
    let row_count = chunk.size();
    let url_reader = chunk.reader(0);
    let index_reader = chunk.reader(1);
    let query_reader = chunk.reader(2);

    let mut success_w = StructVector::field_writer(output, 0);
    let body_vec = duckdb_struct_vector_get_child(output, 1);
    let message_vec = duckdb_struct_vector_get_child(output, 2);

    for row in 0..row_count {
        let url = url_reader.read_str(row as usize);
        let index = index_reader.read_str(row as usize);
        let query = query_reader.read_str(row as usize);

        let result = elasticsearch::search(url, index, query);

        success_w.write_bool(row as usize, result.success);
        write_varchar(body_vec, row, &result.body);
        write_varchar(message_vec, row, &result.message);
    }
}

/// es_count(url, index, query_json) -> STRUCT
unsafe extern "C" fn cb_es_count(
    _info: duckdb_function_info,
    input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    let chunk = DataChunk::from_raw(input);
    let row_count = chunk.size();
    let url_reader = chunk.reader(0);
    let index_reader = chunk.reader(1);
    let query_reader = chunk.reader(2);

    let mut success_w = StructVector::field_writer(output, 0);
    let body_vec = duckdb_struct_vector_get_child(output, 1);
    let message_vec = duckdb_struct_vector_get_child(output, 2);

    for row in 0..row_count {
        let url = url_reader.read_str(row as usize);
        let index = index_reader.read_str(row as usize);
        let query = query_reader.read_str(row as usize);

        let result = elasticsearch::count(url, index, query);

        success_w.write_bool(row as usize, result.success);
        write_varchar(body_vec, row, &result.body);
        write_varchar(message_vec, row, &result.message);
    }
}

/// es_cat(url, endpoint) -> STRUCT
unsafe extern "C" fn cb_es_cat(
    _info: duckdb_function_info,
    input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    let chunk = DataChunk::from_raw(input);
    let row_count = chunk.size();
    let url_reader = chunk.reader(0);
    let endpoint_reader = chunk.reader(1);

    let mut success_w = StructVector::field_writer(output, 0);
    let body_vec = duckdb_struct_vector_get_child(output, 1);
    let message_vec = duckdb_struct_vector_get_child(output, 2);

    for row in 0..row_count {
        let url = url_reader.read_str(row as usize);
        let endpoint = endpoint_reader.read_str(row as usize);

        let result = elasticsearch::cat(url, endpoint);

        success_w.write_bool(row as usize, result.success);
        write_varchar(body_vec, row, &result.body);
        write_varchar(message_vec, row, &result.message);
    }
}

pub unsafe fn register_all(con: duckdb_connection) -> Result<(), ExtensionError> {
    let v = TypeId::Varchar;

    // es_search(url, index, query_json)
    ScalarFunctionBuilder::new("es_search")
        .param(v) // url
        .param(v) // index
        .param(v) // query_json
        .returns_logical(es_result_type())
        .function(cb_es_search)
        .null_handling(NullHandling::SpecialNullHandling)
        .register(con)?;

    // es_count(url, index, query_json)
    ScalarFunctionBuilder::new("es_count")
        .param(v) // url
        .param(v) // index
        .param(v) // query_json
        .returns_logical(es_result_type())
        .function(cb_es_count)
        .null_handling(NullHandling::SpecialNullHandling)
        .register(con)?;

    // es_cat(url, endpoint)
    ScalarFunctionBuilder::new("es_cat")
        .param(v) // url
        .param(v) // endpoint
        .returns_logical(es_result_type())
        .function(cb_es_cat)
        .null_handling(NullHandling::SpecialNullHandling)
        .register(con)?;

    Ok(())
}
