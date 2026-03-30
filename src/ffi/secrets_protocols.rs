// SPDX-License-Identifier: MIT
// Copyright 2026 Tom F. <tomf@tomtomtech.net> (https://github.com/tomtom215)

//! Protocol-specific secrets-aware FFI overloads (SSH, Consul, InfluxDB, HTTP,
//! SNMP, RADIUS, IMAP, LDAP). See also `secrets_protocols_ext` for the
//! remaining overloads (Redis, S3, SMTP, Vault) and the secrets list table.

use libduckdb_sys::*;
use quack_rs::prelude::*;

use crate::security;

use super::scalars::write_varchar;

// ---------------------------------------------------------------------------
// Secrets-Aware SSH Overloads
// ---------------------------------------------------------------------------

fn ssh_result_type() -> LogicalType {
    LogicalType::struct_type_from_logical(&[
        ("success", LogicalType::new(TypeId::Boolean)),
        ("exit_code", LogicalType::new(TypeId::Integer)),
        ("stdout", LogicalType::new(TypeId::Varchar)),
        ("stderr", LogicalType::new(TypeId::Varchar)),
    ])
}

// ssh_exec_secret(secret_name, host, command) -> STRUCT
quack_rs::scalar_callback!(cb_ssh_exec_secret, |_info, input, output| {
    let chunk = unsafe { DataChunk::from_raw(input) };
    let row_count = chunk.size();
    let secret_reader = unsafe { chunk.reader(0) };
    let host_reader = unsafe { chunk.reader(1) };
    let cmd_reader = unsafe { chunk.reader(2) };

    let mut sw = unsafe { StructWriter::new(output, 4) };

    for row in 0..row_count {
        let secret_name = unsafe { secret_reader.read_str(row) };
        let host = unsafe { host_reader.read_str(row) };
        let command = unsafe { cmd_reader.read_str(row) };

        let result = match crate::secrets_resolve::resolve_ssh(secret_name) {
            Ok((user, key_file, password)) => {
                if let Some(key_path) = key_file {
                    crate::ssh::exec(host, 22, &user, &key_path, command)
                } else if let Some(pass) = password {
                    crate::ssh::exec_password(host, 22, &user, &pass, command)
                } else {
                    crate::ssh::SshExecResult {
                        success: false,
                        exit_code: -1,
                        stdout: String::new(),
                        stderr: "Secret must have 'key_file' or 'password'".to_string(),
                    }
                }
            }
            Err(e) => crate::ssh::SshExecResult {
                success: false,
                exit_code: -1,
                stdout: String::new(),
                stderr: e,
            },
        };

        unsafe { sw.write_bool(row, 0, result.success) };
        unsafe { sw.write_i32(row, 1, result.exit_code) };
        unsafe { sw.write_varchar(row, 2, &result.stdout) };
        unsafe { sw.write_varchar(row, 3, &result.stderr) };
    }
});

// ---------------------------------------------------------------------------
// Secrets-Aware Consul Overload
// ---------------------------------------------------------------------------

fn kv_result_type() -> LogicalType {
    LogicalType::struct_type_from_logical(&[
        ("success", LogicalType::new(TypeId::Boolean)),
        ("value", LogicalType::new(TypeId::Varchar)),
        ("message", LogicalType::new(TypeId::Varchar)),
    ])
}

// consul_get_secret(secret_name, url, key) -> STRUCT
quack_rs::scalar_callback!(cb_consul_get_secret, |_info, input, output| {
    let chunk = unsafe { DataChunk::from_raw(input) };
    let row_count = chunk.size();
    let secret_reader = unsafe { chunk.reader(0) };
    let url_reader = unsafe { chunk.reader(1) };
    let key_reader = unsafe { chunk.reader(2) };

    let mut sw = unsafe { StructWriter::new(output, 3) };

    for row in 0..row_count {
        let secret_name = unsafe { secret_reader.read_str(row) };
        let url = unsafe { url_reader.read_str(row) };
        let key = unsafe { key_reader.read_str(row) };

        let result = match crate::secrets_resolve::resolve_token(secret_name) {
            Ok(token) => crate::consul::consul_get(url, key, &token),
            Err(e) => crate::consul::KvResult {
                success: false,
                value: String::new(),
                message: e,
            },
        };

        unsafe { sw.write_bool(row, 0, result.success) };
        unsafe { sw.write_varchar(row, 1, &result.value) };
        unsafe { sw.write_varchar(row, 2, &result.message) };
    }
});

// ---------------------------------------------------------------------------
// Secrets-Aware InfluxDB Overload
// ---------------------------------------------------------------------------

fn influx_result_type() -> LogicalType {
    LogicalType::struct_type_from_logical(&[
        ("success", LogicalType::new(TypeId::Boolean)),
        ("body", LogicalType::new(TypeId::Varchar)),
        ("message", LogicalType::new(TypeId::Varchar)),
    ])
}

// influxdb_query_secret(secret_name, url, org, flux_query) -> STRUCT
quack_rs::scalar_callback!(cb_influxdb_query_secret, |_info, input, output| {
    let chunk = unsafe { DataChunk::from_raw(input) };
    let row_count = chunk.size();
    let secret_reader = unsafe { chunk.reader(0) };
    let url_reader = unsafe { chunk.reader(1) };
    let org_reader = unsafe { chunk.reader(2) };
    let query_reader = unsafe { chunk.reader(3) };

    let mut sw = unsafe { StructWriter::new(output, 3) };

    for row in 0..row_count {
        let secret_name = unsafe { secret_reader.read_str(row) };
        let url = unsafe { url_reader.read_str(row) };
        let org = unsafe { org_reader.read_str(row) };
        let flux_query = unsafe { query_reader.read_str(row) };

        let result = match crate::secrets_resolve::resolve_token(secret_name) {
            Ok(token) => crate::influxdb::query(url, org, &token, flux_query),
            Err(e) => crate::influxdb::InfluxResult {
                success: false,
                body: String::new(),
                message: e,
            },
        };

        unsafe { sw.write_bool(row, 0, result.success) };
        unsafe { sw.write_varchar(row, 1, &result.body) };
        unsafe { sw.write_varchar(row, 2, &result.message) };
    }
});

// ---------------------------------------------------------------------------
// Secrets-Aware HTTP Overload (for bearer token / basic auth from secrets)
// ---------------------------------------------------------------------------

// http_get_secret(secret_name, url) -> response STRUCT
quack_rs::scalar_callback!(cb_http_get_secret, |_info, input, output| {
    let chunk = unsafe { DataChunk::from_raw(input) };
    let row_count = chunk.size();
    let secret_reader = unsafe { chunk.reader(0) };
    let url_reader = unsafe { chunk.reader(1) };
    let mut map_offset: usize = 0;

    for row in 0..row_count {
        let secret_name = unsafe { secret_reader.read_str(row) };
        let url = unsafe { url_reader.read_str(row) };

        let resp = match crate::secrets_resolve::resolve_http(secret_name) {
            Ok(headers) => crate::http::execute(crate::http::Method::Get, url, &headers, None),
            Err(e) => crate::http::HttpResponse {
                status: 0,
                reason: e,
                headers: vec![],
                body: String::new(),
            },
        };
        unsafe { super::scalars::write_response(output, row, &resp, &mut map_offset) };
    }
});

// http_post_secret(secret_name, url, body) -> response STRUCT
quack_rs::scalar_callback!(cb_http_post_secret, |_info, input, output| {
    let chunk = unsafe { DataChunk::from_raw(input) };
    let row_count = chunk.size();
    let secret_reader = unsafe { chunk.reader(0) };
    let url_reader = unsafe { chunk.reader(1) };
    let body_reader = unsafe { chunk.reader(2) };
    let mut map_offset: usize = 0;

    for row in 0..row_count {
        let secret_name = unsafe { secret_reader.read_str(row) };
        let url = unsafe { url_reader.read_str(row) };
        let body = unsafe { body_reader.read_str(row) };

        let resp = match crate::secrets_resolve::resolve_http(secret_name) {
            Ok(headers) => {
                crate::http::execute(crate::http::Method::Post, url, &headers, Some(body))
            }
            Err(e) => crate::http::HttpResponse {
                status: 0,
                reason: e,
                headers: vec![],
                body: String::new(),
            },
        };
        unsafe { super::scalars::write_response(output, row, &resp, &mut map_offset) };
    }
});

// ---------------------------------------------------------------------------
// Secrets-Aware SNMP Overload
// ---------------------------------------------------------------------------

// snmp_get_secret(secret_name, host, oid) -> STRUCT(success, value)
quack_rs::scalar_callback!(cb_snmp_get_secret, |_info, input, output| {
    let chunk = unsafe { DataChunk::from_raw(input) };
    let row_count = chunk.size();
    let secret_reader = unsafe { chunk.reader(0) };
    let host_reader = unsafe { chunk.reader(1) };
    let oid_reader = unsafe { chunk.reader(2) };

    let mut sw = unsafe { StructWriter::new(output, 2) };

    for row in 0..row_count {
        let secret_name = unsafe { secret_reader.read_str(row) };
        let host = unsafe { host_reader.read_str(row) };
        let oid = unsafe { oid_reader.read_str(row) };

        let (success, value) = match crate::secrets_resolve::resolve_community(secret_name) {
            Ok(community) => match crate::snmp::get(host, oid, &community) {
                Ok(r) => (true, r.value),
                Err(e) => (false, e),
            },
            Err(e) => (false, e),
        };

        unsafe { sw.write_bool(row, 0, success) };
        unsafe { sw.write_varchar(row, 1, &value) };
    }
});

// radius_auth_secret(secret_name, host, username, password) -> STRUCT(success, message)
quack_rs::scalar_callback!(cb_radius_auth_secret, |_info, input, output| {
    let chunk = unsafe { DataChunk::from_raw(input) };
    let row_count = chunk.size();
    let secret_reader = unsafe { chunk.reader(0) };
    let host_reader = unsafe { chunk.reader(1) };
    let user_reader = unsafe { chunk.reader(2) };
    let pass_reader = unsafe { chunk.reader(3) };

    let mut sw = unsafe { StructWriter::new(output, 2) };

    for row in 0..row_count {
        let secret_name = unsafe { secret_reader.read_str(row) };
        let host = unsafe { host_reader.read_str(row) };
        let username = unsafe { user_reader.read_str(row) };
        let password = unsafe { pass_reader.read_str(row) };

        let (success, message) = match crate::secrets_resolve::resolve_shared_secret(secret_name) {
            Ok(shared_secret) => {
                let r = crate::radius::auth_default_port(host, &shared_secret, username, password);
                (r.success, r.message)
            }
            Err(e) => (false, e),
        };

        unsafe { sw.write_bool(row, 0, success) };
        unsafe { sw.write_varchar(row, 1, &message) };
    }
});

// imap_fetch_secret(secret_name, url, mailbox, uid) -> STRUCT(success, body, message)
quack_rs::scalar_callback!(cb_imap_fetch_secret, |_info, input, output| {
    let chunk = unsafe { DataChunk::from_raw(input) };
    let row_count = chunk.size();
    let secret_reader = unsafe { chunk.reader(0) };
    let url_reader = unsafe { chunk.reader(1) };
    let mailbox_reader = unsafe { chunk.reader(2) };
    let uid_reader = unsafe { chunk.reader(3) };

    let mut sw = unsafe { StructWriter::new(output, 3) };

    for row in 0..row_count {
        let secret_name = unsafe { secret_reader.read_str(row) };
        let url = unsafe { url_reader.read_str(row) };
        let mailbox = unsafe { mailbox_reader.read_str(row) };
        let uid = unsafe { uid_reader.read_i64(row) };

        let (success, body, message) =
            match crate::secrets_resolve::resolve_credentials(secret_name) {
                Ok((Some(user), Some(pass))) => {
                    let r = crate::imap::fetch_message(url, &user, &pass, mailbox, uid);
                    (r.success, r.body, r.message)
                }
                Ok(_) => (
                    false,
                    String::new(),
                    format!(
                        "Secret '{}' must have 'username' and 'password'",
                        secret_name
                    ),
                ),
                Err(e) => (false, String::new(), e),
            };

        unsafe { sw.write_bool(row, 0, success) };
        unsafe { sw.write_varchar(row, 1, &body) };
        unsafe { sw.write_varchar(row, 2, &message) };
    }
});

// ldap_search_secret(secret_name, url, base_dn, filter, attributes) -> VARCHAR
quack_rs::scalar_callback!(cb_ldap_search_secret, |_info, input, output| {
    let chunk = unsafe { DataChunk::from_raw(input) };
    let row_count = chunk.size();
    let secret_reader = unsafe { chunk.reader(0) };
    let url_reader = unsafe { chunk.reader(1) };
    let base_reader = unsafe { chunk.reader(2) };
    let filter_reader = unsafe { chunk.reader(3) };
    let attrs_reader = unsafe { chunk.reader(4) };

    for row in 0..row_count {
        let secret_name = unsafe { secret_reader.read_str(row) };
        let url = unsafe { url_reader.read_str(row) };
        let base_dn = unsafe { base_reader.read_str(row) };
        let filter = unsafe { filter_reader.read_str(row) };
        let attrs_str = unsafe { attrs_reader.read_str(row) };

        let msg = match crate::secrets_resolve::resolve_credentials(secret_name) {
            Ok((Some(user), Some(pass))) => {
                // First bind, then search
                let bind_result = crate::ldap::bind(url, &user, &pass);
                if !bind_result.success {
                    security::scrub_error(&bind_result.message)
                } else {
                    let attr_vec: Vec<&str> = attrs_str.split(',').map(|s| s.trim()).collect();
                    let result = crate::ldap::search(url, base_dn, filter, &attr_vec);
                    if result.success {
                        // Format entries as JSON
                        let entries_json: Vec<String> = result
                            .entries
                            .iter()
                            .map(|e| {
                                let attrs: Vec<String> = e
                                    .attributes
                                    .iter()
                                    .map(|(k, vals)| {
                                        let v_json = vals
                                            .iter()
                                            .map(|v| format!("\"{}\"", security::json_escape(v)))
                                            .collect::<Vec<_>>()
                                            .join(",");
                                        format!("\"{}\":[{}]", security::json_escape(k), v_json)
                                    })
                                    .collect();
                                format!(
                                    "{{\"dn\":\"{}\",{}}}",
                                    security::json_escape(&e.dn),
                                    attrs.join(",")
                                )
                            })
                            .collect();
                        format!("[{}]", entries_json.join(","))
                    } else {
                        security::scrub_error(&result.message)
                    }
                }
            }
            Ok(_) => format!(
                "Secret '{}' must have 'username' and 'password'",
                secret_name
            ),
            Err(e) => e,
        };

        unsafe { write_varchar(output, row, &msg) };
    }
});

// Registration

fn success_message_result_type() -> LogicalType {
    LogicalType::struct_type_from_logical(&[
        ("success", LogicalType::new(TypeId::Boolean)),
        ("message", LogicalType::new(TypeId::Varchar)),
    ])
}

pub unsafe fn register_all(con: duckdb_connection) -> Result<(), ExtensionError> {
    let v = TypeId::Varchar;

    // SSH
    ScalarFunctionBuilder::new("ssh_exec_secret")
        .param(v)
        .param(v)
        .param(v)
        .returns_logical(ssh_result_type())
        .function(cb_ssh_exec_secret)
        .null_handling(NullHandling::SpecialNullHandling)
        .register(con)?;
    // Consul
    ScalarFunctionBuilder::new("consul_get_secret")
        .param(v)
        .param(v)
        .param(v)
        .returns_logical(kv_result_type())
        .function(cb_consul_get_secret)
        .null_handling(NullHandling::SpecialNullHandling)
        .register(con)?;
    // InfluxDB
    ScalarFunctionBuilder::new("influxdb_query_secret")
        .param(v)
        .param(v)
        .param(v)
        .param(v)
        .returns_logical(influx_result_type())
        .function(cb_influxdb_query_secret)
        .null_handling(NullHandling::SpecialNullHandling)
        .register(con)?;
    // HTTP (bearer/basic auth from secret store)
    ScalarFunctionBuilder::new("http_get_secret")
        .param(v)
        .param(v)
        .returns_logical(super::scalars::response_type())
        .function(cb_http_get_secret)
        .null_handling(NullHandling::SpecialNullHandling)
        .register(con)?;
    ScalarFunctionBuilder::new("http_post_secret")
        .param(v)
        .param(v)
        .param(v)
        .returns_logical(super::scalars::response_type())
        .function(cb_http_post_secret)
        .null_handling(NullHandling::SpecialNullHandling)
        .register(con)?;
    // SNMP (community string from secret store)
    ScalarFunctionBuilder::new("snmp_get_secret")
        .param(v)
        .param(v)
        .param(v)
        .returns_logical(LogicalType::struct_type_from_logical(&[
            ("success", LogicalType::new(TypeId::Boolean)),
            ("value", LogicalType::new(TypeId::Varchar)),
        ]))
        .function(cb_snmp_get_secret)
        .null_handling(NullHandling::SpecialNullHandling)
        .register(con)?;
    // RADIUS (shared secret from secret store)
    ScalarFunctionBuilder::new("radius_auth_secret")
        .param(v)
        .param(v)
        .param(v)
        .param(v)
        .returns_logical(success_message_result_type())
        .function(cb_radius_auth_secret)
        .null_handling(NullHandling::SpecialNullHandling)
        .register(con)?;
    // IMAP (username/password from secret store)
    ScalarFunctionBuilder::new("imap_fetch_secret")
        .param(v)
        .param(v)
        .param(v)
        .param(TypeId::BigInt)
        .returns_logical(LogicalType::struct_type_from_logical(&[
            ("success", LogicalType::new(TypeId::Boolean)),
            ("body", LogicalType::new(TypeId::Varchar)),
            ("message", LogicalType::new(TypeId::Varchar)),
        ]))
        .function(cb_imap_fetch_secret)
        .null_handling(NullHandling::SpecialNullHandling)
        .register(con)?;
    // LDAP (bind credentials from secret store)
    ScalarFunctionBuilder::new("ldap_search_secret")
        .param(v)
        .param(v)
        .param(v)
        .param(v)
        .param(v)
        .returns(TypeId::Varchar)
        .function(cb_ldap_search_secret)
        .null_handling(NullHandling::SpecialNullHandling)
        .register(con)?;

    // Delegate Redis, S3, SMTP, Vault, and secrets-list to the ext module
    super::secrets_protocols_ext::register_all(con)?;

    Ok(())
}
