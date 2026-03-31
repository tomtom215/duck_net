// SPDX-License-Identifier: MIT
// Copyright 2026 Tom F. <tomf@tomtomtech.net> (https://github.com/tomtom215)

//! FFI bindings for the DuckDB secrets manager bridge.
//!
//! Exposes SQL functions that help users integrate duck_net with DuckDB's
//! native secrets manager.

use quack_rs::prelude::*;

use crate::duckdb_secrets_bridge;

// ---------------------------------------------------------------------------
// duck_net_import_aws_env(secret_name) -> VARCHAR
// Import AWS credentials from environment variables into duck_net's store.
// ---------------------------------------------------------------------------
quack_rs::scalar_callback!(cb_import_aws_env, |_info, input, output| {
    let chunk = unsafe { DataChunk::from_raw(input) };
    let row_count = chunk.size();
    let name_reader = unsafe { chunk.reader(0) };
    let mut writer = unsafe { VectorWriter::from_vector(output) };

    for row in 0..row_count {
        let name = unsafe { name_reader.read_str(row) };
        let msg = match duckdb_secrets_bridge::import_aws_env_credentials(name) {
            Ok(m) => m,
            Err(e) => format!("Error: {e}"),
        };
        unsafe { writer.write_varchar(row, &msg) };
    }
});

// ---------------------------------------------------------------------------
// duck_net_import_bearer_env(secret_name, env_var) -> VARCHAR
// Import HTTP bearer token from an environment variable.
// ---------------------------------------------------------------------------
quack_rs::scalar_callback!(cb_import_bearer_env, |_info, input, output| {
    let chunk = unsafe { DataChunk::from_raw(input) };
    let row_count = chunk.size();
    let name_reader = unsafe { chunk.reader(0) };
    let env_reader = unsafe { chunk.reader(1) };
    let mut writer = unsafe { VectorWriter::from_vector(output) };

    for row in 0..row_count {
        let name = unsafe { name_reader.read_str(row) };
        let env_var = unsafe { env_reader.read_str(row) };
        let msg = match duckdb_secrets_bridge::import_bearer_token_from_env(name, env_var) {
            Ok(m) => m,
            Err(e) => format!("Error: {e}"),
        };
        unsafe { writer.write_varchar(row, &msg) };
    }
});

// ---------------------------------------------------------------------------
// duck_net_duckdb_secrets_info() -> VARCHAR
// Return a human-readable summary of DuckDB secrets manager integration.
// ---------------------------------------------------------------------------
quack_rs::scalar_callback!(cb_duckdb_secrets_info, |_info, _input, output| {
    let info = duckdb_secrets_bridge::integration_info();
    let mut writer = unsafe { VectorWriter::from_vector(output) };
    unsafe { writer.write_varchar(0, info) };
});

// ---------------------------------------------------------------------------
// duck_net_to_duckdb_secret_sql(secret_name) -> VARCHAR
// Generate a DuckDB CREATE SECRET SQL statement from a duck_net secret.
// WARNING: Output contains plaintext credentials – handle with care.
// ---------------------------------------------------------------------------
quack_rs::scalar_callback!(cb_to_duckdb_secret_sql, |_info, input, output| {
    let chunk = unsafe { DataChunk::from_raw(input) };
    let row_count = chunk.size();
    let name_reader = unsafe { chunk.reader(0) };
    let mut writer = unsafe { VectorWriter::from_vector(output) };

    for row in 0..row_count {
        let name = unsafe { name_reader.read_str(row) };

        // Emit a warning since this exposes raw credentials as SQL
        crate::security_warnings::warn_secret_value_exposed(name);

        let msg = match duckdb_secrets_bridge::to_duckdb_create_secret_sql(name) {
            Some(sql) => sql,
            None => format!(
                "Secret '{}' not found or type not supported by DuckDB's native secrets manager \
                 (supported: s3, http, gcs, r2)",
                name
            ),
        };
        unsafe { writer.write_varchar(row, &msg) };
    }
});

// ---------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------

pub unsafe fn register_all(con: &Connection) -> Result<(), ExtensionError> {
    let v = TypeId::Varchar;

    // duck_net_import_aws_env(secret_name) -> VARCHAR
    ScalarFunctionBuilder::new("duck_net_import_aws_env")
        .param(v) // secret_name to create in duck_net's store
        .returns(TypeId::Varchar)
        .function(cb_import_aws_env)
        .register(con.as_raw_connection())?;

    // duck_net_import_bearer_env(secret_name, env_var) -> VARCHAR
    ScalarFunctionBuilder::new("duck_net_import_bearer_env")
        .param(v) // secret_name
        .param(v) // environment variable name holding the token
        .returns(TypeId::Varchar)
        .function(cb_import_bearer_env)
        .register(con.as_raw_connection())?;

    // duck_net_duckdb_secrets_info() -> VARCHAR
    ScalarFunctionBuilder::new("duck_net_duckdb_secrets_info")
        .returns(TypeId::Varchar)
        .function(cb_duckdb_secrets_info)
        .register(con.as_raw_connection())?;

    // duck_net_to_duckdb_secret_sql(secret_name) -> VARCHAR
    // WARNING: generates SQL containing plaintext credentials
    ScalarFunctionBuilder::new("duck_net_to_duckdb_secret_sql")
        .param(v) // secret_name
        .returns(TypeId::Varchar)
        .function(cb_to_duckdb_secret_sql)
        .register(con.as_raw_connection())?;

    Ok(())
}
