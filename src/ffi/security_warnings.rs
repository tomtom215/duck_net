// SPDX-License-Identifier: MIT
// Copyright 2026 Tom F. <tomf@tomtomtech.net> (https://github.com/tomtom215)

//! FFI bindings for the duck_net security warnings subsystem.

use libduckdb_sys::*;
use quack_rs::prelude::*;

use crate::security_warnings;

use super::scalars::write_varchar;

// ---------------------------------------------------------------------------
// Security Warnings Callbacks
// ---------------------------------------------------------------------------

/// duck_net_set_security_warnings(enabled BOOLEAN) -> VARCHAR
unsafe extern "C" fn cb_set_security_warnings(
    _info: duckdb_function_info,
    input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    let row_count = duckdb_data_chunk_get_size(input);
    let data = duckdb_vector_get_data(duckdb_data_chunk_get_vector(input, 0)) as *const bool;

    for row in 0..row_count {
        let enabled = *data.add(row as usize);
        security_warnings::set_warnings_enabled(enabled);
        let msg = if enabled {
            "Security warnings enabled"
        } else {
            "Security warnings suppressed (not recommended for production)"
        };
        write_varchar(output, row, msg);
    }
}

/// duck_net_clear_security_warnings() -> VARCHAR
unsafe extern "C" fn cb_clear_security_warnings(
    _info: duckdb_function_info,
    _input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    let count = security_warnings::clear_warnings();
    let msg = format!("Cleared {count} security warnings");
    write_varchar(output, 0, &msg);
}

// ---------------------------------------------------------------------------
// Security Warnings Table Function
// ---------------------------------------------------------------------------

struct WarningsBindData;
struct WarningsInitData {
    entries: Vec<security_warnings::SecurityWarning>,
    idx: usize,
}

unsafe extern "C" fn warnings_bind(info: duckdb_bind_info) {
    let bind = BindInfo::new(info);
    bind.add_result_column("code", TypeId::Varchar);
    bind.add_result_column("severity", TypeId::Varchar);
    bind.add_result_column("cwe", TypeId::Varchar);
    bind.add_result_column("protocol", TypeId::Varchar);
    bind.add_result_column("message", TypeId::Varchar);
    FfiBindData::<WarningsBindData>::set(info, WarningsBindData);
}

unsafe extern "C" fn warnings_init(info: duckdb_init_info) {
    FfiInitData::<WarningsInitData>::set(
        info,
        WarningsInitData {
            entries: vec![],
            idx: 0,
        },
    );
}

unsafe extern "C" fn warnings_scan(info: duckdb_function_info, output: duckdb_data_chunk) {
    let init_data = match FfiInitData::<WarningsInitData>::get_mut(info) {
        Some(d) => d,
        None => {
            duckdb_data_chunk_set_size(output, 0);
            return;
        }
    };

    if init_data.entries.is_empty() && init_data.idx == 0 {
        init_data.entries = security_warnings::list_warnings();
    }

    let code_vec = duckdb_data_chunk_get_vector(output, 0);
    let sev_vec = duckdb_data_chunk_get_vector(output, 1);
    let cwe_vec = duckdb_data_chunk_get_vector(output, 2);
    let proto_vec = duckdb_data_chunk_get_vector(output, 3);
    let msg_vec = duckdb_data_chunk_get_vector(output, 4);

    let mut count: idx_t = 0;
    let max_chunk = 2048;

    while init_data.idx < init_data.entries.len() && count < max_chunk {
        let w = &init_data.entries[init_data.idx];
        write_varchar(code_vec, count, w.code);
        write_varchar(sev_vec, count, w.severity.as_str());
        write_varchar(cwe_vec, count, w.cwe);
        write_varchar(proto_vec, count, w.protocol);
        write_varchar(msg_vec, count, &w.message);
        init_data.idx += 1;
        count += 1;
    }

    duckdb_data_chunk_set_size(output, count);
}

// ---------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------

pub unsafe fn register_all(con: duckdb_connection) -> Result<(), ExtensionError> {
    // Initialize warnings store
    security_warnings::init();

    // duck_net_set_security_warnings(enabled BOOLEAN) -> VARCHAR
    ScalarFunctionBuilder::new("duck_net_set_security_warnings")
        .param(TypeId::Boolean)
        .returns(TypeId::Varchar)
        .function(cb_set_security_warnings)
        .register(con)?;

    // duck_net_clear_security_warnings() -> VARCHAR
    ScalarFunctionBuilder::new("duck_net_clear_security_warnings")
        .returns(TypeId::Varchar)
        .function(cb_clear_security_warnings)
        .register(con)?;

    // duck_net_security_warnings() table function
    TableFunctionBuilder::new("duck_net_security_warnings")
        .bind(warnings_bind)
        .init(warnings_init)
        .scan(warnings_scan)
        .register(con)?;

    Ok(())
}
