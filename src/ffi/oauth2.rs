// SPDX-License-Identifier: MIT
// Copyright 2026 Tom F. <tomf@tomtomtech.net> (https://github.com/tomtom215)

use quack_rs::prelude::*;

use crate::oauth2;

fn token_result_type() -> LogicalType {
    LogicalType::struct_type_from_logical(&[
        ("success", LogicalType::new(TypeId::Boolean)),
        ("access_token", LogicalType::new(TypeId::Varchar)),
        ("token_type", LogicalType::new(TypeId::Varchar)),
        ("expires_in", LogicalType::new(TypeId::BigInt)),
        ("scope", LogicalType::new(TypeId::Varchar)),
        ("message", LogicalType::new(TypeId::Varchar)),
    ])
}

// http_oauth2_token(token_url, client_id, client_secret) -> STRUCT
quack_rs::scalar_callback!(cb_oauth2_token, |_info, input, output| {
    let chunk = unsafe { DataChunk::from_raw(input) };
    let row_count = chunk.size();
    let url_reader = unsafe { chunk.reader(0) };
    let id_reader = unsafe { chunk.reader(1) };
    let secret_reader = unsafe { chunk.reader(2) };

    let mut sw = unsafe { StructWriter::new(output, 6) };

    for row in 0..row_count {
        let token_url = unsafe { url_reader.read_str(row) };
        let client_id = unsafe { id_reader.read_str(row) };
        let client_secret = unsafe { secret_reader.read_str(row) };

        let result = oauth2::client_credentials(token_url, client_id, client_secret, "");

        unsafe { sw.write_bool(row, 0, result.success) };
        unsafe { sw.write_varchar(row, 1, &result.access_token) };
        unsafe { sw.write_varchar(row, 2, &result.token_type) };
        unsafe { sw.write_i64(row, 3, result.expires_in) };
        unsafe { sw.write_varchar(row, 4, &result.scope) };
        unsafe { sw.write_varchar(row, 5, &result.message) };
    }
});

// http_oauth2_token(token_url, client_id, client_secret, scope) -> STRUCT
quack_rs::scalar_callback!(cb_oauth2_token_scoped, |_info, input, output| {
    let chunk = unsafe { DataChunk::from_raw(input) };
    let row_count = chunk.size();
    let url_reader = unsafe { chunk.reader(0) };
    let id_reader = unsafe { chunk.reader(1) };
    let secret_reader = unsafe { chunk.reader(2) };
    let scope_reader = unsafe { chunk.reader(3) };

    let mut sw = unsafe { StructWriter::new(output, 6) };

    for row in 0..row_count {
        let token_url = unsafe { url_reader.read_str(row) };
        let client_id = unsafe { id_reader.read_str(row) };
        let client_secret = unsafe { secret_reader.read_str(row) };
        let scope = unsafe { scope_reader.read_str(row) };

        let result = oauth2::client_credentials(token_url, client_id, client_secret, scope);

        unsafe { sw.write_bool(row, 0, result.success) };
        unsafe { sw.write_varchar(row, 1, &result.access_token) };
        unsafe { sw.write_varchar(row, 2, &result.token_type) };
        unsafe { sw.write_i64(row, 3, result.expires_in) };
        unsafe { sw.write_varchar(row, 4, &result.scope) };
        unsafe { sw.write_varchar(row, 5, &result.message) };
    }
});

pub unsafe fn register_all(con: &Connection) -> Result<(), ExtensionError> {
    let v = TypeId::Varchar;

    ScalarFunctionSetBuilder::new("http_oauth2_token")
        .overload(
            ScalarOverloadBuilder::new()
                .param(v) // token_url
                .param(v) // client_id
                .param(v) // client_secret
                .returns_logical(token_result_type())
                .function(cb_oauth2_token)
                .null_handling(NullHandling::SpecialNullHandling),
        )
        .overload(
            ScalarOverloadBuilder::new()
                .param(v) // token_url
                .param(v) // client_id
                .param(v) // client_secret
                .param(v) // scope
                .returns_logical(token_result_type())
                .function(cb_oauth2_token_scoped)
                .null_handling(NullHandling::SpecialNullHandling),
        )
        .register(con.as_raw_connection())?;

    Ok(())
}
