use std::ffi::c_void;

use libduckdb_sys::*;
use quack_rs::prelude::*;

use crate::http::{self, HttpResponse, Method};
use crate::json;
use crate::rate_limit;

// ===== Type Builders (quack-rs 0.8.0) =====

/// Creates the response type: STRUCT(status INTEGER, reason VARCHAR, headers MAP(VARCHAR, VARCHAR), body VARCHAR)
///
/// quack-rs 0.8.0 added `struct_type_from_logical` and `map_from_logical`,
/// eliminating the need for raw libduckdb-sys type construction.
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
pub(crate) unsafe fn write_varchar(vec: duckdb_vector, row: idx_t, s: &str) {
    duckdb_vector_assign_string_element_len(
        vec,
        row,
        s.as_ptr() as *const std::ffi::c_char,
        s.len() as idx_t,
    );
}

/// Write an HttpResponse into the output STRUCT vector at the given row.
/// `map_offset` tracks the cumulative offset into the MAP child vector across rows.
pub(crate) unsafe fn write_response(
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

// ===== Extra Info: Method Tag =====
// Uses quack-rs 0.8.0 extra_info to store the HTTP method on each overload,
// allowing a single callback function to handle all HTTP methods of the same shape.

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
// One callback per parameter shape, using extra_info to determine the HTTP method.

/// Callback: (url VARCHAR) -> STRUCT
unsafe extern "C" fn cb_url_only(
    info: duckdb_function_info,
    input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    let method = method_from_info(info);
    let row_count = duckdb_data_chunk_get_size(input);
    let url_reader = VectorReader::new(input, 0);
    let mut map_offset: idx_t = 0;

    for row in 0..row_count {
        let url = url_reader.read_str(row as usize);
        let resp = http::execute(method, url, &[], None);
        write_response(output, row, &resp, &mut map_offset);
    }
}

/// Callback: (url VARCHAR, headers MAP) -> STRUCT
unsafe extern "C" fn cb_url_headers(
    info: duckdb_function_info,
    input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    let method = method_from_info(info);
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

/// Callback: (url VARCHAR, body VARCHAR) -> STRUCT
unsafe extern "C" fn cb_url_body(
    info: duckdb_function_info,
    input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    let method = method_from_info(info);
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

/// Callback: (url VARCHAR, headers MAP, body VARCHAR) -> STRUCT
unsafe extern "C" fn cb_url_headers_body(
    info: duckdb_function_info,
    input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    let method = method_from_info(info);
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

/// Callback: http_request(method VARCHAR, url VARCHAR, headers MAP, body VARCHAR) -> STRUCT
unsafe extern "C" fn cb_generic(
    _info: duckdb_function_info,
    input: duckdb_data_chunk,
    output: duckdb_vector,
) {
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

/// Callback: http_post_multipart(url, form_fields MAP, file_fields MAP) -> STRUCT
unsafe extern "C" fn cb_multipart(
    _info: duckdb_function_info,
    input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    let row_count = duckdb_data_chunk_get_size(input);
    let url_reader = VectorReader::new(input, 0);
    let mut map_offset: idx_t = 0;

    for row in 0..row_count {
        let url = url_reader.read_str(row as usize);
        let form_fields = read_headers_map(input, 1, row as usize);
        let file_fields = read_headers_map(input, 2, row as usize);
        let resp = http::execute_multipart(url, &[], &form_fields, &file_fields);
        write_response(output, row, &resp, &mut map_offset);
    }
}

/// Callback: http_post_multipart(url, headers MAP, form_fields MAP, file_fields MAP) -> STRUCT
unsafe extern "C" fn cb_multipart_hdrs(
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
        let form_fields = read_headers_map(input, 2, row as usize);
        let file_fields = read_headers_map(input, 3, row as usize);
        let resp = http::execute_multipart(url, &headers, &form_fields, &file_fields);
        write_response(output, row, &resp, &mut map_offset);
    }
}

// ===== Auth Helper Callbacks =====

/// Callback: http_basic_auth(username VARCHAR, password VARCHAR) -> VARCHAR
/// Returns "Basic <base64(username:password)>"
unsafe extern "C" fn cb_basic_auth(
    _info: duckdb_function_info,
    input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    use base64::Engine as _;
    let row_count = duckdb_data_chunk_get_size(input);
    let user_reader = VectorReader::new(input, 0);
    let pass_reader = VectorReader::new(input, 1);

    for row in 0..row_count {
        let user = user_reader.read_str(row as usize);
        let pass = pass_reader.read_str(row as usize);
        let encoded = base64::engine::general_purpose::STANDARD.encode(format!("{user}:{pass}"));
        let header = format!("Basic {encoded}");
        write_varchar(output, row, &header);
    }
}

/// Callback: http_bearer_auth(token VARCHAR) -> VARCHAR
/// Returns "Bearer <token>"
unsafe extern "C" fn cb_bearer_auth(
    _info: duckdb_function_info,
    input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    let row_count = duckdb_data_chunk_get_size(input);
    let token_reader = VectorReader::new(input, 0);

    for row in 0..row_count {
        let token = token_reader.read_str(row as usize);
        let header = format!("Bearer {token}");
        write_varchar(output, row, &header);
    }
}

/// Callback: http_oauth2_token(token_url, client_id, client_secret) -> VARCHAR
/// Performs OAuth2 Client Credentials grant and returns "Bearer <access_token>".
unsafe extern "C" fn cb_oauth2_token(
    _info: duckdb_function_info,
    input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    let row_count = duckdb_data_chunk_get_size(input);
    let url_reader = VectorReader::new(input, 0);
    let id_reader = VectorReader::new(input, 1);
    let secret_reader = VectorReader::new(input, 2);

    for row in 0..row_count {
        let token_url = url_reader.read_str(row as usize);
        let client_id = id_reader.read_str(row as usize);
        let client_secret = secret_reader.read_str(row as usize);

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
        write_varchar(output, row, &header);
    }
}

/// Callback: http_oauth2_token(token_url, client_id, client_secret, scope) -> VARCHAR
unsafe extern "C" fn cb_oauth2_token_scoped(
    _info: duckdb_function_info,
    input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    let row_count = duckdb_data_chunk_get_size(input);
    let url_reader = VectorReader::new(input, 0);
    let id_reader = VectorReader::new(input, 1);
    let secret_reader = VectorReader::new(input, 2);
    let scope_reader = VectorReader::new(input, 3);

    for row in 0..row_count {
        let token_url = url_reader.read_str(row as usize);
        let client_id = id_reader.read_str(row as usize);
        let client_secret = secret_reader.read_str(row as usize);
        let scope = scope_reader.read_str(row as usize);

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
        write_varchar(output, row, &header);
    }
}

/// Callback: duck_net_set_retry_statuses(statuses VARCHAR) -> VARCHAR
/// Accepts comma-separated status codes, e.g. "429,500,502,503,504"
unsafe extern "C" fn cb_set_retry_statuses(
    _info: duckdb_function_info,
    input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    let row_count = duckdb_data_chunk_get_size(input);
    let statuses_reader = VectorReader::new(input, 0);

    for row in 0..row_count {
        let input_str = statuses_reader.read_str(row as usize);
        let mut codes = Vec::new();
        let mut err = None;
        for part in input_str.split(',') {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }
            match part.parse::<u16>() {
                Ok(code) => codes.push(code),
                Err(_) => {
                    err = Some(format!("Invalid status code: {part}"));
                    break;
                }
            }
        }
        let msg = match err {
            Some(e) => format!("Error: {e}"),
            None => {
                let desc = codes
                    .iter()
                    .map(|c| c.to_string())
                    .collect::<Vec<_>>()
                    .join(",");
                http::set_retry_statuses(codes);
                format!("Retry statuses set to: {desc}")
            }
        };
        write_varchar(output, row, &msg);
    }
}

/// Callback: duck_net_set_domain_rate_limits(config VARCHAR) -> VARCHAR
unsafe extern "C" fn cb_set_domain_rate_limits(
    _info: duckdb_function_info,
    input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    let row_count = duckdb_data_chunk_get_size(input);
    let config_reader = VectorReader::new(input, 0);

    for row in 0..row_count {
        let config = config_reader.read_str(row as usize);
        let msg = match rate_limit::set_domain_limits(config) {
            Ok(m) => m,
            Err(e) => format!("Error: {e}"),
        };
        write_varchar(output, row, &msg);
    }
}

/// Callback: duck_net_set_rate_limit(requests_per_second INTEGER) -> VARCHAR
/// Sets the global rate limit and returns confirmation.
unsafe extern "C" fn cb_set_rate_limit(
    _info: duckdb_function_info,
    input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    let row_count = duckdb_data_chunk_get_size(input);
    let rps_data = duckdb_vector_get_data(duckdb_data_chunk_get_vector(input, 0)) as *const i32;

    for row in 0..row_count {
        let rps = *rps_data.add(row as usize);
        let rps = rps.max(0) as u32;
        rate_limit::set_global_rps(rps);
        let msg = if rps == 0 {
            "Rate limiting disabled".to_string()
        } else {
            format!("Rate limit set to {rps} requests/second")
        };
        write_varchar(output, row, &msg);
    }
}

/// Callback: duck_net_set_retries(max_retries INTEGER, backoff_ms INTEGER) -> VARCHAR
unsafe extern "C" fn cb_set_retries(
    _info: duckdb_function_info,
    input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    let row_count = duckdb_data_chunk_get_size(input);
    let retries_data = duckdb_vector_get_data(duckdb_data_chunk_get_vector(input, 0)) as *const i32;
    let backoff_data = duckdb_vector_get_data(duckdb_data_chunk_get_vector(input, 1)) as *const i32;

    for row in 0..row_count {
        let retries = (*retries_data.add(row as usize)).max(0) as u32;
        let backoff_ms = (*backoff_data.add(row as usize)).max(100) as u64;
        http::set_max_retries(retries);
        http::set_retry_backoff_ms(backoff_ms);
        let msg = if retries == 0 {
            "Retries disabled".to_string()
        } else {
            format!("Retries set to {retries} with {backoff_ms}ms base backoff")
        };
        write_varchar(output, row, &msg);
    }
}

/// Callback: duck_net_set_timeout(seconds INTEGER) -> VARCHAR
unsafe extern "C" fn cb_set_timeout(
    _info: duckdb_function_info,
    input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    let row_count = duckdb_data_chunk_get_size(input);
    let secs_data = duckdb_vector_get_data(duckdb_data_chunk_get_vector(input, 0)) as *const i32;

    for row in 0..row_count {
        let secs = (*secs_data.add(row as usize)).max(1) as u64;
        http::set_timeout_secs(secs);
        write_varchar(output, row, &format!("Timeout set to {secs} seconds"));
    }
}

// ===== Registration (quack-rs 0.8.0 builders) =====
// LogicalType is RAII (Drop destroys the handle), so we create fresh instances
// for each builder call via the helper functions above.

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

    // Rate limiting: duck_net_set_rate_limit(requests_per_second INTEGER) -> VARCHAR
    ScalarFunctionBuilder::new("duck_net_set_rate_limit")
        .param(TypeId::Integer)
        .returns(TypeId::Varchar)
        .function(cb_set_rate_limit)
        .register(con)?;

    // Retry config: duck_net_set_retries(max_retries INTEGER, backoff_ms INTEGER) -> VARCHAR
    ScalarFunctionBuilder::new("duck_net_set_retries")
        .param(TypeId::Integer)
        .param(TypeId::Integer)
        .returns(TypeId::Varchar)
        .function(cb_set_retries)
        .register(con)?;

    // Timeout config: duck_net_set_timeout(seconds INTEGER) -> VARCHAR
    ScalarFunctionBuilder::new("duck_net_set_timeout")
        .param(TypeId::Integer)
        .returns(TypeId::Varchar)
        .function(cb_set_timeout)
        .register(con)?;

    // Retry status codes: duck_net_set_retry_statuses(statuses VARCHAR) -> VARCHAR
    ScalarFunctionBuilder::new("duck_net_set_retry_statuses")
        .param(TypeId::Varchar)
        .returns(TypeId::Varchar)
        .function(cb_set_retry_statuses)
        .register(con)?;

    // Per-domain rate limiting: duck_net_set_domain_rate_limits(config VARCHAR) -> VARCHAR
    ScalarFunctionBuilder::new("duck_net_set_domain_rate_limits")
        .param(TypeId::Varchar)
        .returns(TypeId::Varchar)
        .function(cb_set_domain_rate_limits)
        .register(con)?;

    Ok(())
}
