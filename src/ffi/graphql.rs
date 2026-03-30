// SPDX-License-Identifier: MIT
// Copyright 2026 Tom F. <tomf@tomtomtech.net> (https://github.com/tomtom215)

use quack_rs::prelude::*;

use crate::graphql;

use super::scalars::{map_varchar_varchar, read_headers_map, response_type, write_response};

// graphql_query(url, query) -> STRUCT (HTTP response)
quack_rs::scalar_callback!(cb_graphql_query_2, |_info, input, output| {
    let chunk = unsafe { DataChunk::from_raw(input) };
    let row_count = chunk.size();
    let url_reader = unsafe { chunk.reader(0) };
    let query_reader = unsafe { chunk.reader(1) };
    let mut map_offset: usize = 0;

    for row in 0..row_count {
        let url = unsafe { url_reader.read_str(row) };
        let query = unsafe { query_reader.read_str(row) };
        let resp = graphql::query(url, query, None, &[]);
        unsafe { write_response(output, row, &resp, &mut map_offset) };
    }
});

// graphql_query(url, query, variables) -> STRUCT
quack_rs::scalar_callback!(cb_graphql_query_3, |_info, input, output| {
    let chunk = unsafe { DataChunk::from_raw(input) };
    let row_count = chunk.size();
    let url_reader = unsafe { chunk.reader(0) };
    let query_reader = unsafe { chunk.reader(1) };
    let vars_reader = unsafe { chunk.reader(2) };
    let mut map_offset: usize = 0;

    for row in 0..row_count {
        let url = unsafe { url_reader.read_str(row) };
        let query = unsafe { query_reader.read_str(row) };
        let vars = unsafe { vars_reader.read_str(row) };
        let vars_opt = if vars.is_empty() { None } else { Some(vars) };
        let resp = graphql::query(url, query, vars_opt, &[]);
        unsafe { write_response(output, row, &resp, &mut map_offset) };
    }
});

// graphql_query(url, query, variables, headers MAP) -> STRUCT
quack_rs::scalar_callback!(cb_graphql_query_4, |_info, input, output| {
    let chunk = unsafe { DataChunk::from_raw(input) };
    let row_count = chunk.size();
    let url_reader = unsafe { chunk.reader(0) };
    let query_reader = unsafe { chunk.reader(1) };
    let vars_reader = unsafe { chunk.reader(2) };
    let mut map_offset: usize = 0;

    for row in 0..row_count {
        let url = unsafe { url_reader.read_str(row) };
        let query = unsafe { query_reader.read_str(row) };
        let vars = unsafe { vars_reader.read_str(row) };
        let headers = unsafe { read_headers_map(&chunk, 3, row) };
        let vars_opt = if vars.is_empty() { None } else { Some(vars) };
        let resp = graphql::query(url, query, vars_opt, &headers);
        unsafe { write_response(output, row, &resp, &mut map_offset) };
    }
});

// graphql_has_errors(body VARCHAR) -> BOOLEAN
quack_rs::scalar_callback!(cb_graphql_has_errors, |_info, input, output| {
    let chunk = unsafe { DataChunk::from_raw(input) };
    let row_count = chunk.size();
    let body_reader = unsafe { chunk.reader(0) };
    let mut writer = unsafe { VectorWriter::from_vector(output) };

    for row in 0..row_count {
        let body = unsafe { body_reader.read_str(row) };
        unsafe { writer.write_bool(row, graphql::has_errors(body)) };
    }
});

// graphql_extract_errors(body VARCHAR) -> VARCHAR
quack_rs::scalar_callback!(cb_graphql_extract_errors, |_info, input, output| {
    let chunk = unsafe { DataChunk::from_raw(input) };
    let row_count = chunk.size();
    let body_reader = unsafe { chunk.reader(0) };

    let mut writer = unsafe { VectorWriter::from_vector(output) };

    for row in 0..row_count {
        let body = unsafe { body_reader.read_str(row) };
        match graphql::extract_errors(body) {
            Some(errors) => unsafe { writer.write_varchar(row, errors) },
            None => unsafe { writer.set_null(row) },
        }
    }
});

pub unsafe fn register_all(con: &Connection) -> Result<(), ExtensionError> {
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
        .register(con.as_raw_connection())?;

    ScalarFunctionBuilder::new("graphql_has_errors")
        .param(v)
        .returns(TypeId::Boolean)
        .function(cb_graphql_has_errors)
        .register(con.as_raw_connection())?;

    ScalarFunctionBuilder::new("graphql_extract_errors")
        .param(v)
        .returns(v)
        .function(cb_graphql_extract_errors)
        .null_handling(NullHandling::SpecialNullHandling)
        .register(con.as_raw_connection())?;

    Ok(())
}
