// SPDX-License-Identifier: MIT
// Copyright 2026 Tom F. <tomf@tomtomtech.net> (https://github.com/tomtom215)

use libduckdb_sys::*;
use quack_rs::prelude::*;

use crate::graphql;

use super::scalars::{
    map_varchar_varchar, read_headers_map, response_type, write_response, write_varchar,
};

/// graphql_query(url, query) -> STRUCT (HTTP response)
unsafe extern "C" fn cb_graphql_query_2(
    _info: duckdb_function_info,
    input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    let row_count = duckdb_data_chunk_get_size(input);
    let url_reader = VectorReader::new(input, 0);
    let query_reader = VectorReader::new(input, 1);
    let mut map_offset: idx_t = 0;

    for row in 0..row_count {
        let url = url_reader.read_str(row as usize);
        let query = query_reader.read_str(row as usize);
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
    let row_count = duckdb_data_chunk_get_size(input);
    let url_reader = VectorReader::new(input, 0);
    let query_reader = VectorReader::new(input, 1);
    let vars_reader = VectorReader::new(input, 2);
    let mut map_offset: idx_t = 0;

    for row in 0..row_count {
        let url = url_reader.read_str(row as usize);
        let query = query_reader.read_str(row as usize);
        let vars = vars_reader.read_str(row as usize);
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
    let row_count = duckdb_data_chunk_get_size(input);
    let url_reader = VectorReader::new(input, 0);
    let query_reader = VectorReader::new(input, 1);
    let vars_reader = VectorReader::new(input, 2);
    let mut map_offset: idx_t = 0;

    for row in 0..row_count {
        let url = url_reader.read_str(row as usize);
        let query = query_reader.read_str(row as usize);
        let vars = vars_reader.read_str(row as usize);
        let headers = read_headers_map(input, 3, row as usize);
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
    let row_count = duckdb_data_chunk_get_size(input);
    let body_reader = VectorReader::new(input, 0);
    let data = duckdb_vector_get_data(output) as *mut bool;

    for row in 0..row_count {
        let body = body_reader.read_str(row as usize);
        *data.add(row as usize) = graphql::has_errors(body);
    }
}

/// graphql_extract_errors(body VARCHAR) -> VARCHAR
unsafe extern "C" fn cb_graphql_extract_errors(
    _info: duckdb_function_info,
    input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    let row_count = duckdb_data_chunk_get_size(input);
    let body_reader = VectorReader::new(input, 0);

    duckdb_vector_ensure_validity_writable(output);
    let validity = duckdb_vector_get_validity(output);

    for row in 0..row_count {
        let body = body_reader.read_str(row as usize);
        match graphql::extract_errors(body) {
            Some(errors) => write_varchar(output, row, errors),
            None => duckdb_validity_set_row_invalid(validity, row),
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
