use std::ffi::{c_char, CString};

use libduckdb_sys::*;
use quack_rs::prelude::*;
use quack_rs::vector::complex::MapVector;

use crate::http::{self, HttpResponse, Method};

// ===== DuckDB Type Creation =====

/// Creates: STRUCT(status INTEGER, reason VARCHAR, headers MAP(VARCHAR, VARCHAR), body VARCHAR)
///
/// Uses raw libduckdb-sys because quack-rs LogicalType::struct_type() only accepts TypeId,
/// not nested LogicalType (e.g. MAP). This is a known quack-rs gap.
unsafe fn create_response_type() -> duckdb_logical_type {
    let status_type = duckdb_create_logical_type(DUCKDB_TYPE_DUCKDB_TYPE_INTEGER);
    let reason_type = duckdb_create_logical_type(DUCKDB_TYPE_DUCKDB_TYPE_VARCHAR);
    let body_type = duckdb_create_logical_type(DUCKDB_TYPE_DUCKDB_TYPE_VARCHAR);

    let map_key = duckdb_create_logical_type(DUCKDB_TYPE_DUCKDB_TYPE_VARCHAR);
    let map_val = duckdb_create_logical_type(DUCKDB_TYPE_DUCKDB_TYPE_VARCHAR);
    let headers_type = duckdb_create_map_type(map_key, map_val);
    duckdb_destroy_logical_type(&mut { map_key });
    duckdb_destroy_logical_type(&mut { map_val });

    let mut member_types = [status_type, reason_type, headers_type, body_type];
    let names: [CString; 4] = [
        CString::new("status").unwrap(),
        CString::new("reason").unwrap(),
        CString::new("headers").unwrap(),
        CString::new("body").unwrap(),
    ];
    let mut name_ptrs: [*const c_char; 4] = [
        names[0].as_ptr(),
        names[1].as_ptr(),
        names[2].as_ptr(),
        names[3].as_ptr(),
    ];

    let struct_type = duckdb_create_struct_type(
        member_types.as_mut_ptr(),
        name_ptrs.as_mut_ptr(),
        4,
    );

    for t in &mut member_types {
        duckdb_destroy_logical_type(t);
    }

    struct_type
}

/// Creates MAP(VARCHAR, VARCHAR) for header parameters.
unsafe fn create_map_varchar_varchar() -> duckdb_logical_type {
    let k = duckdb_create_logical_type(DUCKDB_TYPE_DUCKDB_TYPE_VARCHAR);
    let v = duckdb_create_logical_type(DUCKDB_TYPE_DUCKDB_TYPE_VARCHAR);
    let m = duckdb_create_map_type(k, v);
    duckdb_destroy_logical_type(&mut { k });
    duckdb_destroy_logical_type(&mut { v });
    m
}

// ===== Input Helpers =====

/// Read a MAP(VARCHAR, VARCHAR) column from the input chunk at the given row.
unsafe fn read_headers_map(
    input: duckdb_data_chunk,
    col: idx_t,
    row: usize,
) -> Vec<(String, String)> {
    let map_vec = duckdb_data_chunk_get_vector(input, col);

    // Check NULL
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
unsafe fn write_varchar(vec: duckdb_vector, row: idx_t, s: &str) {
    duckdb_vector_assign_string_element_len(
        vec,
        row,
        s.as_ptr() as *const c_char,
        s.len() as idx_t,
    );
}

/// Write an HttpResponse into the output STRUCT vector at the given row.
/// `map_offset` tracks the cumulative offset into the MAP child vector across rows.
unsafe fn write_response(
    output: duckdb_vector,
    row: idx_t,
    resp: &HttpResponse,
    map_offset: &mut idx_t,
) {
    let status_vec = duckdb_struct_vector_get_child(output, 0);
    let reason_vec = duckdb_struct_vector_get_child(output, 1);
    let headers_vec = duckdb_struct_vector_get_child(output, 2);
    let body_vec = duckdb_struct_vector_get_child(output, 3);

    // Status (INTEGER)
    let status_data = duckdb_vector_get_data(status_vec) as *mut i32;
    *status_data.add(row as usize) = resp.status as i32;

    // Reason (VARCHAR)
    write_varchar(reason_vec, row, &resp.reason);

    // Headers (MAP(VARCHAR, VARCHAR))
    let n = resp.headers.len() as idx_t;
    let new_total = *map_offset + n;

    MapVector::reserve(headers_vec, new_total as usize);
    let keys_vec = MapVector::keys(headers_vec);
    let vals_vec = MapVector::values(headers_vec);

    for (i, (k, v)) in resp.headers.iter().enumerate() {
        let idx = *map_offset + i as idx_t;
        write_varchar(keys_vec, idx, k);
        write_varchar(vals_vec, idx, v);
    }

    MapVector::set_entry(headers_vec, row as usize, *map_offset, n);
    *map_offset = new_total;
    MapVector::set_size(headers_vec, new_total as usize);

    // Body (VARCHAR)
    write_varchar(body_vec, row, &resp.body);
}

// ===== Core Execution Functions =====
// These process entire chunks. Each variant reads different columns from input.

unsafe fn exec_url_only(method: Method, input: duckdb_data_chunk, output: duckdb_vector) {
    let row_count = duckdb_data_chunk_get_size(input);
    let url_reader = VectorReader::new(input, 0);
    let mut map_offset: idx_t = 0;

    for row in 0..row_count {
        let url = url_reader.read_str(row as usize);
        let resp = http::execute(method, url, &[], None);
        write_response(output, row, &resp, &mut map_offset);
    }
}

unsafe fn exec_url_headers(method: Method, input: duckdb_data_chunk, output: duckdb_vector) {
    let row_count = duckdb_data_chunk_get_size(input);
    let url_reader = VectorReader::new(input, 0);
    let mut map_offset: idx_t = 0;

    for row in 0..row_count {
        let url = url_reader.read_str(row as usize);
        let headers = read_headers_map(input, 1, row as usize);
        let resp = http::execute(method, url, &headers, None);
        write_response(output, row, &resp, &mut map_offset);
    }
}

unsafe fn exec_url_body(method: Method, input: duckdb_data_chunk, output: duckdb_vector) {
    let row_count = duckdb_data_chunk_get_size(input);
    let url_reader = VectorReader::new(input, 0);
    let body_reader = VectorReader::new(input, 1);
    let mut map_offset: idx_t = 0;

    for row in 0..row_count {
        let url = url_reader.read_str(row as usize);
        let body = body_reader.read_str(row as usize);
        let resp = http::execute(method, url, &[], Some(body));
        write_response(output, row, &resp, &mut map_offset);
    }
}

unsafe fn exec_url_headers_body(
    method: Method,
    input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    let row_count = duckdb_data_chunk_get_size(input);
    let url_reader = VectorReader::new(input, 0);
    let body_reader = VectorReader::new(input, 2);
    let mut map_offset: idx_t = 0;

    for row in 0..row_count {
        let url = url_reader.read_str(row as usize);
        let headers = read_headers_map(input, 1, row as usize);
        let body = body_reader.read_str(row as usize);
        let resp = http::execute(method, url, &headers, Some(body));
        write_response(output, row, &resp, &mut map_offset);
    }
}

unsafe fn exec_generic(input: duckdb_data_chunk, output: duckdb_vector) {
    let row_count = duckdb_data_chunk_get_size(input);
    let method_reader = VectorReader::new(input, 0);
    let url_reader = VectorReader::new(input, 1);
    let body_reader = VectorReader::new(input, 3);
    let mut map_offset: idx_t = 0;

    for row in 0..row_count {
        let method_str = method_reader.read_str(row as usize);
        let method = match Method::from_str(method_str) {
            Some(m) => m,
            None => {
                let resp = HttpResponse {
                    status: 0,
                    reason: format!("Unsupported HTTP method: {method_str}"),
                    headers: vec![],
                    body: String::new(),
                };
                write_response(output, row, &resp, &mut map_offset);
                continue;
            }
        };
        let url = url_reader.read_str(row as usize);
        let headers = read_headers_map(input, 2, row as usize);
        let body = body_reader.read_str(row as usize);
        let body_opt = if body.is_empty() { None } else { Some(body) };
        let resp = http::execute(method, url, &headers, body_opt);
        write_response(output, row, &resp, &mut map_offset);
    }
}

// ===== Callback Wrappers =====
// Thin extern "C" functions that delegate to the core execution functions above.
// Uses a macro to reduce boilerplate since each just forwards to an exec_ function.

macro_rules! callback {
    ($name:ident, $exec:ident, $method:expr) => {
        unsafe extern "C" fn $name(
            _info: duckdb_function_info,
            input: duckdb_data_chunk,
            output: duckdb_vector,
        ) {
            $exec($method, input, output);
        }
    };
}

// No-body methods: (url) and (url, headers)
callback!(cb_get_url, exec_url_only, Method::Get);
callback!(cb_get_url_hdrs, exec_url_headers, Method::Get);
callback!(cb_delete_url, exec_url_only, Method::Delete);
callback!(cb_delete_url_hdrs, exec_url_headers, Method::Delete);
callback!(cb_head_url, exec_url_only, Method::Head);
callback!(cb_head_url_hdrs, exec_url_headers, Method::Head);
callback!(cb_options_url, exec_url_only, Method::Options);
callback!(cb_options_url_hdrs, exec_url_headers, Method::Options);

// Body methods: (url, body) and (url, headers, body)
callback!(cb_post_url_body, exec_url_body, Method::Post);
callback!(cb_post_url_hdrs_body, exec_url_headers_body, Method::Post);
callback!(cb_put_url_body, exec_url_body, Method::Put);
callback!(cb_put_url_hdrs_body, exec_url_headers_body, Method::Put);
callback!(cb_patch_url_body, exec_url_body, Method::Patch);
callback!(cb_patch_url_hdrs_body, exec_url_headers_body, Method::Patch);

// Generic
unsafe extern "C" fn cb_generic(
    _info: duckdb_function_info,
    input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    exec_generic(input, output);
}

// ===== Registration Helpers =====

/// Create a scalar function handle with the given name, parameters, return type, and callback.
unsafe fn make_scalar(
    name: &CString,
    params: &[duckdb_logical_type],
    ret: duckdb_logical_type,
    func: duckdb_scalar_function_t,
) -> duckdb_scalar_function {
    let sf = duckdb_create_scalar_function();
    duckdb_scalar_function_set_name(sf, name.as_ptr());
    for p in params {
        duckdb_scalar_function_add_parameter(sf, *p);
    }
    duckdb_scalar_function_set_return_type(sf, ret);
    duckdb_scalar_function_set_function(sf, func);
    sf
}

/// Register a function set (multiple overloads under one name).
unsafe fn register_set(con: duckdb_connection, name: &str, funcs: &[duckdb_scalar_function]) {
    let cname = CString::new(name).unwrap();
    let set = duckdb_create_scalar_function_set(cname.as_ptr());
    for &f in funcs {
        duckdb_add_scalar_function_to_set(set, f);
    }
    duckdb_register_scalar_function_set(con, set);
    duckdb_destroy_scalar_function_set(&mut { set });
    for &f in funcs {
        duckdb_destroy_scalar_function(&mut { f });
    }
}

/// Register a single scalar function (no overloads).
unsafe fn register_single(con: duckdb_connection, func: duckdb_scalar_function) {
    duckdb_register_scalar_function(con, func);
    duckdb_destroy_scalar_function(&mut { func });
}

/// Register a no-body HTTP method with two overloads: (url) and (url, headers).
unsafe fn register_no_body_method(
    con: duckdb_connection,
    name: &str,
    url_cb: duckdb_scalar_function_t,
    url_hdrs_cb: duckdb_scalar_function_t,
    varchar: duckdb_logical_type,
    map: duckdb_logical_type,
    ret: duckdb_logical_type,
) {
    let cname = CString::new(name).unwrap();
    let f1 = make_scalar(&cname, &[varchar], ret, url_cb);
    let f2 = make_scalar(&cname, &[varchar, map], ret, url_hdrs_cb);
    register_set(con, name, &[f1, f2]);
}

/// Register a body HTTP method with two overloads: (url, body) and (url, headers, body).
unsafe fn register_body_method(
    con: duckdb_connection,
    name: &str,
    url_body_cb: duckdb_scalar_function_t,
    url_hdrs_body_cb: duckdb_scalar_function_t,
    varchar: duckdb_logical_type,
    map: duckdb_logical_type,
    ret: duckdb_logical_type,
) {
    let cname = CString::new(name).unwrap();
    let f1 = make_scalar(&cname, &[varchar, varchar], ret, url_body_cb);
    let f2 = make_scalar(&cname, &[varchar, map, varchar], ret, url_hdrs_body_cb);
    register_set(con, name, &[f1, f2]);
}

// ===== Public Registration Entry Point =====

pub unsafe fn register_all(con: duckdb_connection) -> Result<(), ExtensionError> {
    let ret = create_response_type();
    let varchar = duckdb_create_logical_type(DUCKDB_TYPE_DUCKDB_TYPE_VARCHAR);
    let map = create_map_varchar_varchar();

    // No-body methods: GET, DELETE, HEAD, OPTIONS
    register_no_body_method(
        con, "http_get",
        Some(cb_get_url), Some(cb_get_url_hdrs),
        varchar, map, ret,
    );
    register_no_body_method(
        con, "http_delete",
        Some(cb_delete_url), Some(cb_delete_url_hdrs),
        varchar, map, ret,
    );
    register_no_body_method(
        con, "http_head",
        Some(cb_head_url), Some(cb_head_url_hdrs),
        varchar, map, ret,
    );
    register_no_body_method(
        con, "http_options",
        Some(cb_options_url), Some(cb_options_url_hdrs),
        varchar, map, ret,
    );

    // Body methods: POST, PUT, PATCH
    register_body_method(
        con, "http_post",
        Some(cb_post_url_body), Some(cb_post_url_hdrs_body),
        varchar, map, ret,
    );
    register_body_method(
        con, "http_put",
        Some(cb_put_url_body), Some(cb_put_url_hdrs_body),
        varchar, map, ret,
    );
    register_body_method(
        con, "http_patch",
        Some(cb_patch_url_body), Some(cb_patch_url_hdrs_body),
        varchar, map, ret,
    );

    // Generic: http_request(method VARCHAR, url VARCHAR, headers MAP, body VARCHAR)
    {
        let cname = CString::new("http_request").unwrap();
        let f = make_scalar(&cname, &[varchar, varchar, map, varchar], ret, Some(cb_generic));
        register_single(con, f);
    }

    // Cleanup shared logical types
    duckdb_destroy_logical_type(&mut { ret });
    duckdb_destroy_logical_type(&mut { varchar });
    duckdb_destroy_logical_type(&mut { map });

    Ok(())
}
