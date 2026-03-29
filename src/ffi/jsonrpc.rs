// SPDX-License-Identifier: MIT
// Copyright 2026 Tom F. <tomf@tomtomtech.net> (https://github.com/tomtom215)

use libduckdb_sys::*;
use quack_rs::prelude::*;

use crate::jsonrpc;

use super::scalars::{map_varchar_varchar, read_headers_map, response_type, write_response};

/// jsonrpc_call(url, method, params) -> STRUCT
unsafe extern "C" fn cb_jsonrpc_call_3(
    _info: duckdb_function_info,
    input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    let chunk = DataChunk::from_raw(input);
    let row_count = chunk.size();
    let url_reader = chunk.reader(0);
    let method_reader = chunk.reader(1);
    let params_reader = chunk.reader(2);
    let mut map_offset: usize = 0;

    for row in 0..row_count {
        let url = url_reader.read_str(row);
        let method = method_reader.read_str(row);
        let params = params_reader.read_str(row);
        let params_opt = if params.is_empty() {
            None
        } else {
            Some(params)
        };
        let resp = jsonrpc::call(url, method, params_opt, &[]);
        write_response(output, row, &resp, &mut map_offset);
    }
}

/// jsonrpc_call(url, method, params, headers MAP) -> STRUCT
unsafe extern "C" fn cb_jsonrpc_call_4(
    _info: duckdb_function_info,
    input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    let chunk = DataChunk::from_raw(input);
    let row_count = chunk.size();
    let url_reader = chunk.reader(0);
    let method_reader = chunk.reader(1);
    let params_reader = chunk.reader(2);
    let mut map_offset: usize = 0;

    for row in 0..row_count {
        let url = url_reader.read_str(row);
        let method = method_reader.read_str(row);
        let params = params_reader.read_str(row);
        let headers = read_headers_map(input, 3, row);
        let params_opt = if params.is_empty() {
            None
        } else {
            Some(params)
        };
        let resp = jsonrpc::call(url, method, params_opt, &headers);
        write_response(output, row, &resp, &mut map_offset);
    }
}

/// xmlrpc_call(url, method, params) -> STRUCT
unsafe extern "C" fn cb_xmlrpc_call(
    _info: duckdb_function_info,
    input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    let chunk = DataChunk::from_raw(input);
    let row_count = chunk.size();
    let url_reader = chunk.reader(0);
    let method_reader = chunk.reader(1);
    let params_reader = chunk.reader(2);
    let mut map_offset: usize = 0;

    for row in 0..row_count {
        let url = url_reader.read_str(row);
        let method = method_reader.read_str(row);
        let params_str = params_reader.read_str(row);
        let params: Vec<&str> = if params_str.is_empty() {
            vec![]
        } else {
            params_str.split(',').map(|s| s.trim()).collect()
        };
        let resp = jsonrpc::xmlrpc_call(url, method, &params, &[]);
        write_response(output, row, &resp, &mut map_offset);
    }
}

pub unsafe fn register_all(con: duckdb_connection) -> Result<(), ExtensionError> {
    let v = TypeId::Varchar;

    ScalarFunctionSetBuilder::new("jsonrpc_call")
        .overload(
            ScalarOverloadBuilder::new()
                .param(v)
                .param(v)
                .param(v)
                .returns_logical(response_type())
                .function(cb_jsonrpc_call_3)
                .null_handling(NullHandling::SpecialNullHandling),
        )
        .overload(
            ScalarOverloadBuilder::new()
                .param(v)
                .param(v)
                .param(v)
                .param_logical(map_varchar_varchar())
                .returns_logical(response_type())
                .function(cb_jsonrpc_call_4)
                .null_handling(NullHandling::SpecialNullHandling),
        )
        .register(con)?;

    ScalarFunctionBuilder::new("xmlrpc_call")
        .param(v)
        .param(v)
        .param(v)
        .returns_logical(response_type())
        .function(cb_xmlrpc_call)
        .null_handling(NullHandling::SpecialNullHandling)
        .register(con)?;

    Ok(())
}
