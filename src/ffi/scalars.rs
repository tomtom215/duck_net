// SPDX-License-Identifier: MIT
// Copyright 2026 Tom F. <tomf@tomtomtech.net> (https://github.com/tomtom215)

use std::ffi::c_void;

use libduckdb_sys::*;
use quack_rs::prelude::*;

use crate::http::{self, HttpResponse, Method};
use crate::json;

// ===== Type Builders =====

/// Creates the response type: STRUCT(status INTEGER, reason VARCHAR, headers MAP(VARCHAR, VARCHAR), body VARCHAR)
pub(crate) fn response_type() -> LogicalType {
    let headers_map = LogicalType::map_from_logical(
        &LogicalType::new(TypeId::Varchar),
        &LogicalType::new(TypeId::Varchar),
    );
    LogicalType::struct_type_from_logical(&[
        ("status", LogicalType::new(TypeId::Integer)),
        ("reason", LogicalType::new(TypeId::Varchar)),
        ("headers", headers_map),
        ("body", LogicalType::new(TypeId::Varchar)),
    ])
}

/// MAP(VARCHAR, VARCHAR) for header/field parameters.
pub(crate) fn map_varchar_varchar() -> LogicalType {
    LogicalType::map_from_logical(
        &LogicalType::new(TypeId::Varchar),
        &LogicalType::new(TypeId::Varchar),
    )
}

// ===== Input Helpers =====

/// Read a MAP(VARCHAR, VARCHAR) column from the input chunk at the given row.
pub(crate) unsafe fn read_headers_map(
    input: duckdb_data_chunk,
    col: idx_t,
    row: usize,
) -> Vec<(String, String)> {
    let map_vec = duckdb_data_chunk_get_vector(input, col);

    let validity = duckdb_vector_get_validity(map_vec);
    if !validity.is_null() && !duckdb_validity_row_is_valid(validity, row as idx_t) {
        return vec![];
    }

    let entry = MapVector::get_entry(map_vec, row);
    let offset = entry.offset as usize;
    let length = entry.length as usize;
    if length == 0 {
        return vec![];
    }

    let keys_vec = MapVector::keys(map_vec);
    let vals_vec = MapVector::values(map_vec);
    let max_idx = offset + length;
    let key_reader = VectorReader::from_vector(keys_vec, max_idx);
    let val_reader = VectorReader::from_vector(vals_vec, max_idx);

    let mut headers = Vec::with_capacity(length);
    for i in offset..max_idx {
        headers.push((
            key_reader.read_str(i).to_string(),
            val_reader.read_str(i).to_string(),
        ));
    }
    headers
}

// ===== Output Helpers =====

/// Write a string to a DuckDB VARCHAR vector at the given row.
pub(crate) unsafe fn write_varchar(vec: duckdb_vector, row: usize, s: &str) {
    let mut w = VectorWriter::from_vector(vec);
    w.write_varchar(row, s);
}

// StructWriter is provided by quack_rs::prelude::StructWriter (from quack-rs v0.10.0).
// All files should import it from the prelude, not from this module.

/// Write an HttpResponse into the output STRUCT vector at the given row.
/// `map_offset` tracks the cumulative offset into the MAP child vector across rows.
pub(crate) unsafe fn write_response(
    output: duckdb_vector,
    row: usize,
    resp: &HttpResponse,
    map_offset: &mut usize,
) {
    let mut status_w = StructVector::field_writer(output, 0);
    let mut reason_w = StructVector::field_writer(output, 1);
    let headers_vec = StructVector::get_child(output, 2);
    let mut body_w = StructVector::field_writer(output, 3);

    // Status (INTEGER)
    status_w.write_i32(row, resp.status as i32);

    // Reason (VARCHAR)
    reason_w.write_varchar(row, &resp.reason);

    // Headers (MAP(VARCHAR, VARCHAR))
    let n = resp.headers.len();
    let new_total = *map_offset + n;

    MapVector::reserve(headers_vec, new_total);
    let mut key_w = MapVector::key_writer(headers_vec);
    let mut val_w = MapVector::value_writer(headers_vec);

    for (i, (k, v)) in resp.headers.iter().enumerate() {
        let idx = *map_offset + i;
        key_w.write_varchar(idx, k);
        val_w.write_varchar(idx, v);
    }

    MapVector::set_entry(headers_vec, row, *map_offset as u64, n as u64);
    *map_offset = new_total;
    MapVector::set_size(headers_vec, new_total);

    // Body (VARCHAR)
    body_w.write_varchar(row, &resp.body);
}

// ===== Extra Info: Method Tag =====

/// Retrieve the HTTP Method stored as extra_info on a scalar function.
unsafe fn method_from_info(info: duckdb_function_info) -> Method {
    let fi = ScalarFunctionInfo::new(info);
    let ptr = fi.get_extra_info();
    let tag = ptr as u8;
    // SAFETY: tags are set by us and always valid Method discriminants
    std::mem::transmute::<u8, Method>(tag)
}

/// Stores a Method discriminant as the extra_info pointer (no heap allocation).
fn method_as_ptr(m: Method) -> *mut c_void {
    (m as u8) as usize as *mut c_void
}

// ===== Unified Callbacks =====

// Callback: (url VARCHAR) -> STRUCT
quack_rs::scalar_callback!(cb_url_only, |info, input, output| {
    let method = unsafe { method_from_info(info) };
    let chunk = unsafe { DataChunk::from_raw(input) };
    let row_count = chunk.size();
    let url_reader = unsafe { chunk.reader(0) };
    let mut map_offset: usize = 0;

    for row in 0..row_count {
        let url = unsafe { url_reader.read_str(row) };
        let resp = http::execute(method, url, &[], None);
        unsafe { write_response(output, row, &resp, &mut map_offset) };
    }
});

// Callback: (url VARCHAR, headers MAP) -> STRUCT
quack_rs::scalar_callback!(cb_url_headers, |info, input, output| {
    let method = unsafe { method_from_info(info) };
    let chunk = unsafe { DataChunk::from_raw(input) };
    let row_count = chunk.size();
    let url_reader = unsafe { chunk.reader(0) };
    let mut map_offset: usize = 0;

    for row in 0..row_count {
        let url = unsafe { url_reader.read_str(row) };
        let headers = unsafe { read_headers_map(input, 1, row) };
        let resp = http::execute(method, url, &headers, None);
        unsafe { write_response(output, row, &resp, &mut map_offset) };
    }
});

// Callback: (url VARCHAR, body VARCHAR) -> STRUCT
quack_rs::scalar_callback!(cb_url_body, |info, input, output| {
    let method = unsafe { method_from_info(info) };
    let chunk = unsafe { DataChunk::from_raw(input) };
    let row_count = chunk.size();
    let url_reader = unsafe { chunk.reader(0) };
    let body_reader = unsafe { chunk.reader(1) };
    let mut map_offset: usize = 0;

    for row in 0..row_count {
        let url = unsafe { url_reader.read_str(row) };
        let body = unsafe { body_reader.read_str(row) };
        let resp = http::execute(method, url, &[], Some(body));
        unsafe { write_response(output, row, &resp, &mut map_offset) };
    }
});

// Callback: (url VARCHAR, headers MAP, body VARCHAR) -> STRUCT
quack_rs::scalar_callback!(cb_url_headers_body, |info, input, output| {
    let method = unsafe { method_from_info(info) };
    let chunk = unsafe { DataChunk::from_raw(input) };
    let row_count = chunk.size();
    let url_reader = unsafe { chunk.reader(0) };
    let body_reader = unsafe { chunk.reader(2) };
    let mut map_offset: usize = 0;

    for row in 0..row_count {
        let url = unsafe { url_reader.read_str(row) };
        let headers = unsafe { read_headers_map(input, 1, row) };
        let body = unsafe { body_reader.read_str(row) };
        let resp = http::execute(method, url, &headers, Some(body));
        unsafe { write_response(output, row, &resp, &mut map_offset) };
    }
});

// Callback: http_request(method VARCHAR, url VARCHAR, headers MAP, body VARCHAR) -> STRUCT
quack_rs::scalar_callback!(cb_generic, |_info, input, output| {
    let chunk = unsafe { DataChunk::from_raw(input) };
    let row_count = chunk.size();
    let method_reader = unsafe { chunk.reader(0) };
    let url_reader = unsafe { chunk.reader(1) };
    let body_reader = unsafe { chunk.reader(3) };
    let mut map_offset: usize = 0;

    for row in 0..row_count {
        let method_str = unsafe { method_reader.read_str(row) };
        let method = match Method::from_str(method_str) {
            Some(m) => m,
            None => {
                let resp = HttpResponse {
                    status: 0,
                    reason: format!("Unsupported HTTP method: {method_str}"),
                    headers: vec![],
                    body: String::new(),
                };
                unsafe { write_response(output, row, &resp, &mut map_offset) };
                continue;
            }
        };
        let url = unsafe { url_reader.read_str(row) };
        let headers = unsafe { read_headers_map(input, 2, row) };
        let body = unsafe { body_reader.read_str(row) };
        let body_opt = if body.is_empty() { None } else { Some(body) };
        let resp = http::execute(method, url, &headers, body_opt);
        unsafe { write_response(output, row, &resp, &mut map_offset) };
    }
});

// Callback: http_post_multipart(url, form_fields MAP, file_fields MAP) -> STRUCT
quack_rs::scalar_callback!(cb_multipart, |_info, input, output| {
    let chunk = unsafe { DataChunk::from_raw(input) };
    let row_count = chunk.size();
    let url_reader = unsafe { chunk.reader(0) };
    let mut map_offset: usize = 0;

    for row in 0..row_count {
        let url = unsafe { url_reader.read_str(row) };
        let form_fields = unsafe { read_headers_map(input, 1, row) };
        let file_fields = unsafe { read_headers_map(input, 2, row) };
        let resp = http::execute_multipart(url, &[], &form_fields, &file_fields);
        unsafe { write_response(output, row, &resp, &mut map_offset) };
    }
});

// Callback: http_post_multipart(url, headers MAP, form_fields MAP, file_fields MAP) -> STRUCT
quack_rs::scalar_callback!(cb_multipart_hdrs, |_info, input, output| {
    let chunk = unsafe { DataChunk::from_raw(input) };
    let row_count = chunk.size();
    let url_reader = unsafe { chunk.reader(0) };
    let mut map_offset: usize = 0;

    for row in 0..row_count {
        let url = unsafe { url_reader.read_str(row) };
        let headers = unsafe { read_headers_map(input, 1, row) };
        let form_fields = unsafe { read_headers_map(input, 2, row) };
        let file_fields = unsafe { read_headers_map(input, 3, row) };
        let resp = http::execute_multipart(url, &headers, &form_fields, &file_fields);
        unsafe { write_response(output, row, &resp, &mut map_offset) };
    }
});

// ===== Auth Helper Callbacks =====

// Callback: http_basic_auth(username VARCHAR, password VARCHAR) -> VARCHAR
// Returns "Basic <base64(username:password)>"
quack_rs::scalar_callback!(cb_basic_auth, |_info, input, output| {
    use base64::Engine as _;
    let chunk = unsafe { DataChunk::from_raw(input) };
    let row_count = chunk.size();
    let user_reader = unsafe { chunk.reader(0) };
    let pass_reader = unsafe { chunk.reader(1) };
    let mut writer = unsafe { VectorWriter::from_vector(output) };

    for row in 0..row_count {
        let user = unsafe { user_reader.read_str(row) };
        let pass = unsafe { pass_reader.read_str(row) };
        let encoded = base64::engine::general_purpose::STANDARD.encode(format!("{user}:{pass}"));
        let header = format!("Basic {encoded}");
        unsafe { writer.write_varchar(row, &header) };
    }
});

// Callback: http_bearer_auth(token VARCHAR) -> VARCHAR
// Returns "Bearer <token>"
quack_rs::scalar_callback!(cb_bearer_auth, |_info, input, output| {
    let chunk = unsafe { DataChunk::from_raw(input) };
    let row_count = chunk.size();
    let token_reader = unsafe { chunk.reader(0) };
    let mut writer = unsafe { VectorWriter::from_vector(output) };

    for row in 0..row_count {
        let token = unsafe { token_reader.read_str(row) };
        let header = format!("Bearer {token}");
        unsafe { writer.write_varchar(row, &header) };
    }
});

// Callback: http_oauth2_token(token_url, client_id, client_secret) -> VARCHAR
quack_rs::scalar_callback!(cb_oauth2_token, |_info, input, output| {
    let chunk = unsafe { DataChunk::from_raw(input) };
    let row_count = chunk.size();
    let url_reader = unsafe { chunk.reader(0) };
    let id_reader = unsafe { chunk.reader(1) };
    let secret_reader = unsafe { chunk.reader(2) };
    let mut writer = unsafe { VectorWriter::from_vector(output) };

    for row in 0..row_count {
        let token_url = unsafe { url_reader.read_str(row) };
        let client_id = unsafe { id_reader.read_str(row) };
        let client_secret = unsafe { secret_reader.read_str(row) };

        let form_body = format!(
            "grant_type=client_credentials&client_id={}&client_secret={}",
            json::form_urlencode(client_id),
            json::form_urlencode(client_secret),
        );

        let resp = http::execute(
            Method::Post,
            token_url,
            &[(
                "Content-Type".into(),
                "application/x-www-form-urlencoded".into(),
            )],
            Some(&form_body),
        );

        let header = if resp.status == 200 {
            match json::extract_string(&resp.body, "access_token") {
                Some(token) => format!("Bearer {token}"),
                None => "OAuth2 error: no access_token in response body".to_string(),
            }
        } else {
            format!("OAuth2 error: {} {}", resp.status, resp.reason)
        };
        unsafe { writer.write_varchar(row, &header) };
    }
});

// Callback: http_oauth2_token(token_url, client_id, client_secret, scope) -> VARCHAR
quack_rs::scalar_callback!(cb_oauth2_token_scoped, |_info, input, output| {
    let chunk = unsafe { DataChunk::from_raw(input) };
    let row_count = chunk.size();
    let url_reader = unsafe { chunk.reader(0) };
    let id_reader = unsafe { chunk.reader(1) };
    let secret_reader = unsafe { chunk.reader(2) };
    let scope_reader = unsafe { chunk.reader(3) };
    let mut writer = unsafe { VectorWriter::from_vector(output) };

    for row in 0..row_count {
        let token_url = unsafe { url_reader.read_str(row) };
        let client_id = unsafe { id_reader.read_str(row) };
        let client_secret = unsafe { secret_reader.read_str(row) };
        let scope = unsafe { scope_reader.read_str(row) };

        let form_body = format!(
            "grant_type=client_credentials&client_id={}&client_secret={}&scope={}",
            json::form_urlencode(client_id),
            json::form_urlencode(client_secret),
            json::form_urlencode(scope),
        );

        let resp = http::execute(
            Method::Post,
            token_url,
            &[(
                "Content-Type".into(),
                "application/x-www-form-urlencoded".into(),
            )],
            Some(&form_body),
        );

        let header = if resp.status == 200 {
            match json::extract_string(&resp.body, "access_token") {
                Some(token) => format!("Bearer {token}"),
                None => "OAuth2 error: no access_token in response body".to_string(),
            }
        } else {
            format!("OAuth2 error: {} {}", resp.status, resp.reason)
        };
        unsafe { writer.write_varchar(row, &header) };
    }
});

// ===== Registration =====

/// Register a no-body HTTP method (GET, DELETE, HEAD, OPTIONS) with two overloads.
unsafe fn register_no_body_method(
    con: duckdb_connection,
    name: &str,
    method: Method,
) -> Result<(), ExtensionError> {
    let url_only = ScalarOverloadBuilder::new()
        .param(TypeId::Varchar)
        .returns_logical(response_type())
        .function(cb_url_only)
        .null_handling(NullHandling::SpecialNullHandling);
    let url_only = unsafe { url_only.extra_info(method_as_ptr(method), None) };

    let url_hdrs = ScalarOverloadBuilder::new()
        .param(TypeId::Varchar)
        .param_logical(map_varchar_varchar())
        .returns_logical(response_type())
        .function(cb_url_headers)
        .null_handling(NullHandling::SpecialNullHandling);
    let url_hdrs = unsafe { url_hdrs.extra_info(method_as_ptr(method), None) };

    ScalarFunctionSetBuilder::new(name)
        .overload(url_only)
        .overload(url_hdrs)
        .register(con)
}

/// Register a body HTTP method (POST, PUT, PATCH) with two overloads.
unsafe fn register_body_method(
    con: duckdb_connection,
    name: &str,
    method: Method,
) -> Result<(), ExtensionError> {
    let url_body = ScalarOverloadBuilder::new()
        .param(TypeId::Varchar)
        .param(TypeId::Varchar)
        .returns_logical(response_type())
        .function(cb_url_body)
        .null_handling(NullHandling::SpecialNullHandling);
    let url_body = unsafe { url_body.extra_info(method_as_ptr(method), None) };

    let url_hdrs_body = ScalarOverloadBuilder::new()
        .param(TypeId::Varchar)
        .param_logical(map_varchar_varchar())
        .param(TypeId::Varchar)
        .returns_logical(response_type())
        .function(cb_url_headers_body)
        .null_handling(NullHandling::SpecialNullHandling);
    let url_hdrs_body = unsafe { url_hdrs_body.extra_info(method_as_ptr(method), None) };

    ScalarFunctionSetBuilder::new(name)
        .overload(url_body)
        .overload(url_hdrs_body)
        .register(con)
}

pub unsafe fn register_all(con: duckdb_connection) -> Result<(), ExtensionError> {
    // No-body methods: GET, DELETE, HEAD, OPTIONS
    register_no_body_method(con, "http_get", Method::Get)?;
    register_no_body_method(con, "http_delete", Method::Delete)?;
    register_no_body_method(con, "http_head", Method::Head)?;
    register_no_body_method(con, "http_options", Method::Options)?;

    // Body methods: POST, PUT, PATCH
    register_body_method(con, "http_post", Method::Post)?;
    register_body_method(con, "http_put", Method::Put)?;
    register_body_method(con, "http_patch", Method::Patch)?;

    // Multipart: http_post_multipart
    ScalarFunctionSetBuilder::new("http_post_multipart")
        .overload(
            ScalarOverloadBuilder::new()
                .param(TypeId::Varchar)
                .param_logical(map_varchar_varchar())
                .param_logical(map_varchar_varchar())
                .returns_logical(response_type())
                .function(cb_multipart)
                .null_handling(NullHandling::SpecialNullHandling),
        )
        .overload(
            ScalarOverloadBuilder::new()
                .param(TypeId::Varchar)
                .param_logical(map_varchar_varchar())
                .param_logical(map_varchar_varchar())
                .param_logical(map_varchar_varchar())
                .returns_logical(response_type())
                .function(cb_multipart_hdrs)
                .null_handling(NullHandling::SpecialNullHandling),
        )
        .register(con)?;

    // Generic: http_request(method, url, headers, body)
    ScalarFunctionBuilder::new("http_request")
        .param(TypeId::Varchar)
        .param(TypeId::Varchar)
        .param_logical(map_varchar_varchar())
        .param(TypeId::Varchar)
        .returns_logical(response_type())
        .function(cb_generic)
        .null_handling(NullHandling::SpecialNullHandling)
        .register(con)?;

    // Auth helpers: http_basic_auth(username, password) -> VARCHAR
    ScalarFunctionBuilder::new("http_basic_auth")
        .param(TypeId::Varchar)
        .param(TypeId::Varchar)
        .returns(TypeId::Varchar)
        .function(cb_basic_auth)
        .register(con)?;

    // Auth helpers: http_bearer_auth(token) -> VARCHAR
    ScalarFunctionBuilder::new("http_bearer_auth")
        .param(TypeId::Varchar)
        .returns(TypeId::Varchar)
        .function(cb_bearer_auth)
        .register(con)?;

    // Auth helpers: http_oauth2_token (3-param and 4-param with scopes)
    ScalarFunctionSetBuilder::new("http_oauth2_token")
        .overload(
            ScalarOverloadBuilder::new()
                .param(TypeId::Varchar)
                .param(TypeId::Varchar)
                .param(TypeId::Varchar)
                .returns(TypeId::Varchar)
                .function(cb_oauth2_token),
        )
        .overload(
            ScalarOverloadBuilder::new()
                .param(TypeId::Varchar)
                .param(TypeId::Varchar)
                .param(TypeId::Varchar)
                .param(TypeId::Varchar)
                .returns(TypeId::Varchar)
                .function(cb_oauth2_token_scoped),
        )
        .register(con)?;

    // Config functions (rate limiting, retries, timeout)
    super::scalars_config::register_all(con)?;

    Ok(())
}
