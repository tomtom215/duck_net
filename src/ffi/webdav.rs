// SPDX-License-Identifier: MIT
// Copyright 2026 Tom F. <tomf@tomtomtech.net> (https://github.com/tomtom215)

use libduckdb_sys::*;
use quack_rs::prelude::*;

use crate::webdav;

use super::scalars::{
    map_varchar_varchar, read_headers_map, response_type, write_response, write_varchar,
};

// ===== webdav_list table function =====

struct WebDavListBindData {
    url: String,
    headers: Vec<(String, String)>,
    depth: String,
}

struct WebDavListInitData {
    entries: Vec<webdav::WebDavEntry>,
    idx: usize,
}

unsafe extern "C" fn webdav_list_bind(info: duckdb_bind_info) {
    let bind = BindInfo::new(info);
    let url_val = bind.get_parameter(0);
    let url_cstr = duckdb_get_varchar(url_val);
    let url = std::ffi::CStr::from_ptr(url_cstr)
        .to_str()
        .unwrap_or("")
        .to_string();
    duckdb_free(url_cstr as *mut _);
    duckdb_destroy_value(&mut { url_val });

    bind.add_result_column("href", TypeId::Varchar);
    bind.add_result_column("name", TypeId::Varchar);
    bind.add_result_column("content_type", TypeId::Varchar);
    bind.add_result_column("size", TypeId::BigInt);
    bind.add_result_column("last_modified", TypeId::Varchar);
    bind.add_result_column("is_collection", TypeId::Boolean);

    FfiBindData::<WebDavListBindData>::set(
        info,
        WebDavListBindData {
            url,
            headers: vec![],
            depth: "1".to_string(),
        },
    );
}

unsafe extern "C" fn webdav_list_init(info: duckdb_init_info) {
    FfiInitData::<WebDavListInitData>::set(
        info,
        WebDavListInitData {
            entries: vec![],
            idx: 0,
        },
    );
}

unsafe extern "C" fn webdav_list_scan(info: duckdb_function_info, output: duckdb_data_chunk) {
    let bind_data = match FfiBindData::<WebDavListBindData>::get_from_function(info) {
        Some(d) => d,
        None => {
            duckdb_data_chunk_set_size(output, 0);
            return;
        }
    };
    let init_data = match FfiInitData::<WebDavListInitData>::get_mut(info) {
        Some(d) => d,
        None => {
            duckdb_data_chunk_set_size(output, 0);
            return;
        }
    };

    if init_data.entries.is_empty() && init_data.idx == 0 {
        match webdav::list(&bind_data.url, &bind_data.headers, &bind_data.depth) {
            Ok(entries) => init_data.entries = entries,
            Err(e) => {
                let fi = FunctionInfo::new(info);
                fi.set_error(&e);
                duckdb_data_chunk_set_size(output, 0);
                return;
            }
        }
    }

    let href_vec = duckdb_data_chunk_get_vector(output, 0);
    let name_vec = duckdb_data_chunk_get_vector(output, 1);
    let ct_vec = duckdb_data_chunk_get_vector(output, 2);
    let size_vec = duckdb_data_chunk_get_vector(output, 3);
    let lm_vec = duckdb_data_chunk_get_vector(output, 4);
    let ic_vec = duckdb_data_chunk_get_vector(output, 5);

    let mut count: idx_t = 0;
    let max_chunk = 2048;

    while init_data.idx < init_data.entries.len() && count < max_chunk {
        let entry = &init_data.entries[init_data.idx];
        write_varchar(href_vec, count, &entry.href);
        write_varchar(name_vec, count, &entry.name);
        write_varchar(ct_vec, count, &entry.content_type);
        let szd = duckdb_vector_get_data(size_vec) as *mut i64;
        *szd.add(count as usize) = entry.size;
        write_varchar(lm_vec, count, &entry.last_modified);
        let icd = duckdb_vector_get_data(ic_vec) as *mut bool;
        *icd.add(count as usize) = entry.is_collection;
        init_data.idx += 1;
        count += 1;
    }

    duckdb_data_chunk_set_size(output, count);
}

// ===== Scalar functions =====

/// webdav_read(url, headers MAP) -> STRUCT (HTTP response)
unsafe extern "C" fn cb_webdav_read(
    _info: duckdb_function_info,
    input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    let row_count = duckdb_data_chunk_get_size(input);
    let url_reader = VectorReader::new(input, 0);
    let mut map_offset: idx_t = 0;

    for row in 0..row_count {
        let url = url_reader.read_str(row as usize);
        let headers = read_headers_map(input, 1, row as usize);
        let resp = webdav::read(url, &headers);
        write_response(output, row, &resp, &mut map_offset);
    }
}

/// webdav_write(url, content, headers MAP) -> STRUCT
unsafe extern "C" fn cb_webdav_write(
    _info: duckdb_function_info,
    input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    let row_count = duckdb_data_chunk_get_size(input);
    let url_reader = VectorReader::new(input, 0);
    let content_reader = VectorReader::new(input, 1);
    let mut map_offset: idx_t = 0;

    for row in 0..row_count {
        let url = url_reader.read_str(row as usize);
        let content = content_reader.read_str(row as usize);
        let headers = read_headers_map(input, 2, row as usize);
        let resp = webdav::write(url, content, &headers);
        write_response(output, row, &resp, &mut map_offset);
    }
}

/// webdav_delete(url, headers MAP) -> STRUCT
unsafe extern "C" fn cb_webdav_delete(
    _info: duckdb_function_info,
    input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    let row_count = duckdb_data_chunk_get_size(input);
    let url_reader = VectorReader::new(input, 0);
    let mut map_offset: idx_t = 0;

    for row in 0..row_count {
        let url = url_reader.read_str(row as usize);
        let headers = read_headers_map(input, 1, row as usize);
        let resp = webdav::delete(url, &headers);
        write_response(output, row, &resp, &mut map_offset);
    }
}

/// webdav_mkcol(url, headers MAP) -> STRUCT
unsafe extern "C" fn cb_webdav_mkcol(
    _info: duckdb_function_info,
    input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    let row_count = duckdb_data_chunk_get_size(input);
    let url_reader = VectorReader::new(input, 0);
    let mut map_offset: idx_t = 0;

    for row in 0..row_count {
        let url = url_reader.read_str(row as usize);
        let headers = read_headers_map(input, 1, row as usize);
        let resp = webdav::mkcol(url, &headers);
        write_response(output, row, &resp, &mut map_offset);
    }
}

pub unsafe fn register_all(con: duckdb_connection) -> Result<(), ExtensionError> {
    let v = TypeId::Varchar;

    // webdav_list table function
    TableFunctionBuilder::new("webdav_list")
        .param(v)
        .bind(webdav_list_bind)
        .init(webdav_list_init)
        .scan(webdav_list_scan)
        .register(con)?;

    // webdav_read(url, headers MAP) -> STRUCT
    ScalarFunctionBuilder::new("webdav_read")
        .param(v)
        .param_logical(map_varchar_varchar())
        .returns_logical(response_type())
        .function(cb_webdav_read)
        .null_handling(NullHandling::SpecialNullHandling)
        .register(con)?;

    // webdav_write(url, content, headers MAP) -> STRUCT
    ScalarFunctionBuilder::new("webdav_write")
        .param(v)
        .param(v)
        .param_logical(map_varchar_varchar())
        .returns_logical(response_type())
        .function(cb_webdav_write)
        .null_handling(NullHandling::SpecialNullHandling)
        .register(con)?;

    // webdav_delete(url, headers MAP) -> STRUCT
    ScalarFunctionBuilder::new("webdav_delete")
        .param(v)
        .param_logical(map_varchar_varchar())
        .returns_logical(response_type())
        .function(cb_webdav_delete)
        .null_handling(NullHandling::SpecialNullHandling)
        .register(con)?;

    // webdav_mkcol(url, headers MAP) -> STRUCT
    ScalarFunctionBuilder::new("webdav_mkcol")
        .param(v)
        .param_logical(map_varchar_varchar())
        .returns_logical(response_type())
        .function(cb_webdav_mkcol)
        .null_handling(NullHandling::SpecialNullHandling)
        .register(con)?;

    Ok(())
}
