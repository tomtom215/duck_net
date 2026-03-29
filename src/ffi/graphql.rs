// SPDX-License-Identifier: MIT
// Copyright 2026 Tom F. <tomf@tomtomtech.net> (https://github.com/tomtom215)

use libduckdb_sys::*;
use quack_rs::prelude::*;

use crate::graphql;

use super::scalars::{map_varchar_varchar, read_headers_map, response_type, write_response};

/// graphql_query(url, query) -> STRUCT (HTTP response)
unsafe extern "C" fn cb_graphql_query_2(
    _info: duckdb_function_info,
    input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    let chunk = DataChunk::from_raw(input);
    let row_count = chunk.size();
    let url_reader = chunk.reader(0);
    let query_reader = chunk.reader(1);
    let mut map_offset: usize = 0;

    for row in 0..row_count {
        let url = url_reader.read_str(row);
        let query = query_reader.read_str(row);
        let resp = graphql::query(url, query, None, &[]);
        write_response(output, row, &resp, &mut map_offset);
    }
}

/// graphql_query(url, query, variables) -> STRUCT
unsafe extern "C" fn cb_graphql_query_3(
    _info: duckdb_function_info,
    input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    let chunk = DataChunk::from_raw(input);
    let row_count = chunk.size();
    let url_reader = chunk.reader(0);
    let query_reader = chunk.reader(1);
    let vars_reader = chunk.reader(2);
    let mut map_offset: usize = 0;

    for row in 0..row_count {
        let url = url_reader.read_str(row);
        let query = query_reader.read_str(row);
        let vars = vars_reader.read_str(row);
        let vars_opt = if vars.is_empty() { None } else { Some(vars) };
        let resp = graphql::query(url, query, vars_opt, &[]);
        write_response(output, row, &resp, &mut map_offset);
    }
}

/// graphql_query(url, query, variables, headers MAP) -> STRUCT
unsafe extern "C" fn cb_graphql_query_4(
    _info: duckdb_function_info,
    input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    let chunk = DataChunk::from_raw(input);
    let row_count = chunk.size();
    let url_reader = chunk.reader(0);
    let query_reader = chunk.reader(1);
    let vars_reader = chunk.reader(2);
    let mut map_offset: usize = 0;

    for row in 0..row_count {
        let url = url_reader.read_str(row);
        let query = query_reader.read_str(row);
        let vars = vars_reader.read_str(row);
        let headers = read_headers_map(input, 3, row);
        let vars_opt = if vars.is_empty() { None } else { Some(vars) };
        let resp = graphql::query(url, query, vars_opt, &headers);
        write_response(output, row, &resp, &mut map_offset);
    }
}

/// graphql_has_errors(body VARCHAR) -> BOOLEAN
unsafe extern "C" fn cb_graphql_has_errors(
    _info: duckdb_function_info,
    input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    let chunk = DataChunk::from_raw(input);
    let row_count = chunk.size();
    let body_reader = chunk.reader(0);
    let data = duckdb_vector_get_data(output) as *mut bool;

    for row in 0..row_count {
        let body = body_reader.read_str(row);
        *data.add(row) = graphql::has_errors(body);
    }
}

/// graphql_extract_errors(body VARCHAR) -> VARCHAR
unsafe extern "C" fn cb_graphql_extract_errors(
    _info: duckdb_function_info,
    input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    let chunk = DataChunk::from_raw(input);
    let row_count = chunk.size();
    let body_reader = chunk.reader(0);

    let mut writer = VectorWriter::from_vector(output);

    for row in 0..row_count {
        let body = body_reader.read_str(row);
        match graphql::extract_errors(body) {
            Some(errors) => writer.write_varchar(row, errors),
            None => writer.set_null(row),
        }
    }
}

pub unsafe fn register_all(con: duckdb_connection) -> Result<(), ExtensionError> {
    let v = TypeId::Varchar;

    ScalarFunctionSetBuilder::new("graphql_query")
        .overload(
            ScalarOverloadBuilder::new()
                .param(v)
                .param(v)
                .returns_logical(response_type())
                .function(cb_graphql_query_2)
                .null_handling(NullHandling::SpecialNullHandling),
        )
        .overload(
            ScalarOverloadBuilder::new()
                .param(v)
                .param(v)
                .param(v)
                .returns_logical(response_type())
                .function(cb_graphql_query_3)
                .null_handling(NullHandling::SpecialNullHandling),
        )
        .overload(
            ScalarOverloadBuilder::new()
                .param(v)
                .param(v)
                .param(v)
                .param_logical(map_varchar_varchar())
                .returns_logical(response_type())
                .function(cb_graphql_query_4)
                .null_handling(NullHandling::SpecialNullHandling),
        )
        .register(con)?;

    ScalarFunctionBuilder::new("graphql_has_errors")
        .param(v)
        .returns(TypeId::Boolean)
        .function(cb_graphql_has_errors)
        .register(con)?;

    ScalarFunctionBuilder::new("graphql_extract_errors")
        .param(v)
        .returns(v)
        .function(cb_graphql_extract_errors)
        .null_handling(NullHandling::SpecialNullHandling)
        .register(con)?;

    Ok(())
}
