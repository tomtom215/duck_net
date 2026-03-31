// SPDX-License-Identifier: MIT
// Copyright 2026 Tom F. <tomf@tomtomtech.net> (https://github.com/tomtom215)

use quack_rs::prelude::*;

use super::*;
use crate::http::Method;

/// Register a no-body HTTP method (GET, DELETE, HEAD, OPTIONS) with two overloads.
unsafe fn register_no_body_method(
    con: &Connection,
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
        .register(con.as_raw_connection())
}

/// Register a body HTTP method (POST, PUT, PATCH) with two overloads.
unsafe fn register_body_method(
    con: &Connection,
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
        .register(con.as_raw_connection())
}

pub unsafe fn register_all(con: &Connection) -> Result<(), ExtensionError> {
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
        .register(con.as_raw_connection())?;

    // Generic: http_request(method, url, headers, body)
    ScalarFunctionBuilder::new("http_request")
        .param(TypeId::Varchar)
        .param(TypeId::Varchar)
        .param_logical(map_varchar_varchar())
        .param(TypeId::Varchar)
        .returns_logical(response_type())
        .function(cb_generic)
        .null_handling(NullHandling::SpecialNullHandling)
        .register(con.as_raw_connection())?;

    // Auth helpers: http_basic_auth(username, password) -> VARCHAR
    ScalarFunctionBuilder::new("http_basic_auth")
        .param(TypeId::Varchar)
        .param(TypeId::Varchar)
        .returns(TypeId::Varchar)
        .function(cb_basic_auth)
        .register(con.as_raw_connection())?;

    // Auth helpers: http_bearer_auth(token) -> VARCHAR
    ScalarFunctionBuilder::new("http_bearer_auth")
        .param(TypeId::Varchar)
        .returns(TypeId::Varchar)
        .function(cb_bearer_auth)
        .register(con.as_raw_connection())?;

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
        .register(con.as_raw_connection())?;

    // Config functions (rate limiting, retries, timeout)
    super::super::scalars_config::register_all(con)?;

    Ok(())
}
