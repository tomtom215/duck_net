// SPDX-License-Identifier: MIT
// Copyright 2026 Tom F. <tomf@tomtomtech.net> (https://github.com/tomtom215)

use libduckdb_sys::*;
use quack_rs::prelude::*;

use crate::prometheus;

use super::scalars::write_varchar;

fn prometheus_result_type() -> LogicalType {
    LogicalType::struct_type_from_logical(&[
        ("success", LogicalType::new(TypeId::Boolean)),
        ("result_type", LogicalType::new(TypeId::Varchar)),
        ("body", LogicalType::new(TypeId::Varchar)),
        ("message", LogicalType::new(TypeId::Varchar)),
    ])
}

/// prometheus_query(url, promql) -> STRUCT(success, result_type, body, message)
unsafe extern "C" fn cb_prometheus_query(
    _info: duckdb_function_info,
    input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    let row_count = duckdb_data_chunk_get_size(input);
    let url_reader = VectorReader::new(input, 0);
    let promql_reader = VectorReader::new(input, 1);

    let success_vec = duckdb_struct_vector_get_child(output, 0);
    let rtype_vec = duckdb_struct_vector_get_child(output, 1);
    let body_vec = duckdb_struct_vector_get_child(output, 2);
    let message_vec = duckdb_struct_vector_get_child(output, 3);

    for row in 0..row_count {
        let url = url_reader.read_str(row as usize);
        let promql = promql_reader.read_str(row as usize);

        let result = prometheus::query(url, promql);

        let sd = duckdb_vector_get_data(success_vec) as *mut bool;
        *sd.add(row as usize) = result.success;
        write_varchar(rtype_vec, row, &result.result_type);
        write_varchar(body_vec, row, &result.body);
        write_varchar(message_vec, row, &result.message);
    }
}

/// prometheus_query_range(url, promql, start, end, step) -> STRUCT
unsafe extern "C" fn cb_prometheus_query_range(
    _info: duckdb_function_info,
    input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    let row_count = duckdb_data_chunk_get_size(input);
    let url_reader = VectorReader::new(input, 0);
    let promql_reader = VectorReader::new(input, 1);
    let start_reader = VectorReader::new(input, 2);
    let end_reader = VectorReader::new(input, 3);
    let step_reader = VectorReader::new(input, 4);

    let success_vec = duckdb_struct_vector_get_child(output, 0);
    let rtype_vec = duckdb_struct_vector_get_child(output, 1);
    let body_vec = duckdb_struct_vector_get_child(output, 2);
    let message_vec = duckdb_struct_vector_get_child(output, 3);

    for row in 0..row_count {
        let url = url_reader.read_str(row as usize);
        let promql = promql_reader.read_str(row as usize);
        let start = start_reader.read_str(row as usize);
        let end = end_reader.read_str(row as usize);
        let step = step_reader.read_str(row as usize);

        let result = prometheus::query_range(url, promql, start, end, step);

        let sd = duckdb_vector_get_data(success_vec) as *mut bool;
        *sd.add(row as usize) = result.success;
        write_varchar(rtype_vec, row, &result.result_type);
        write_varchar(body_vec, row, &result.body);
        write_varchar(message_vec, row, &result.message);
    }
}

pub unsafe fn register_all(con: duckdb_connection) -> Result<(), ExtensionError> {
    let v = TypeId::Varchar;

    // prometheus_query(url, promql)
    ScalarFunctionBuilder::new("prometheus_query")
        .param(v) // url
        .param(v) // promql
        .returns_logical(prometheus_result_type())
        .function(cb_prometheus_query)
        .null_handling(NullHandling::SpecialNullHandling)
        .register(con)?;

    // prometheus_query_range(url, promql, start, end, step)
    ScalarFunctionBuilder::new("prometheus_query_range")
        .param(v) // url
        .param(v) // promql
        .param(v) // start
        .param(v) // end
        .param(v) // step
        .returns_logical(prometheus_result_type())
        .function(cb_prometheus_query_range)
        .null_handling(NullHandling::SpecialNullHandling)
        .register(con)?;

    Ok(())
}
