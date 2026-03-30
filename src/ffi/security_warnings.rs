// SPDX-License-Identifier: MIT
// Copyright 2026 Tom F. <tomf@tomtomtech.net> (https://github.com/tomtom215)

//! FFI bindings for the duck_net security warnings subsystem.

use libduckdb_sys::*;
use quack_rs::prelude::*;

use crate::security_warnings;

// ---------------------------------------------------------------------------
// Security Warnings Callbacks
// ---------------------------------------------------------------------------

// duck_net_set_security_warnings(enabled BOOLEAN) -> VARCHAR
quack_rs::scalar_callback!(cb_set_security_warnings, |_info, input, output| {
    let chunk = unsafe { DataChunk::from_raw(input) };
    let row_count = chunk.size();
    let enabled_reader = unsafe { chunk.reader(0) };
    let mut out_w = unsafe { VectorWriter::from_vector(output) };

    for row in 0..row_count {
        let enabled = unsafe { enabled_reader.read_bool(row) };
        security_warnings::set_warnings_enabled(enabled);
        let msg = if enabled {
            "Security warnings enabled"
        } else {
            "Security warnings suppressed (not recommended for production)"
        };
        unsafe { out_w.write_varchar(row, msg) };
    }
});

// duck_net_clear_security_warnings() -> VARCHAR
quack_rs::scalar_callback!(cb_clear_security_warnings, |_info, _input, output| {
    let count = security_warnings::clear_warnings();
    let msg = format!("Cleared {count} security warnings");
    let mut out_w = unsafe { VectorWriter::from_vector(output) };
    unsafe { out_w.write_varchar(0, &msg) };
});

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

// warnings_scan table scan callback
quack_rs::table_scan_callback!(warnings_scan, |info, output| {
    let init_data = match unsafe { FfiInitData::<WarningsInitData>::get_mut(info) } {
        Some(d) => d,
        None => {
            unsafe { DataChunk::from_raw(output).set_size(0) };
            return;
        }
    };

    if init_data.entries.is_empty() && init_data.idx == 0 {
        init_data.entries = security_warnings::list_warnings();
    }

    let out_chunk = unsafe { DataChunk::from_raw(output) };
    let mut code_w = unsafe { out_chunk.writer(0) };
    let mut sev_w = unsafe { out_chunk.writer(1) };
    let mut cwe_w = unsafe { out_chunk.writer(2) };
    let mut proto_w = unsafe { out_chunk.writer(3) };
    let mut msg_w = unsafe { out_chunk.writer(4) };

    let mut count: usize = 0;
    let max_chunk = 2048;

    while init_data.idx < init_data.entries.len() && count < max_chunk {
        let w = &init_data.entries[init_data.idx];
        unsafe { code_w.write_varchar(count, w.code) };
        unsafe { sev_w.write_varchar(count, w.severity.as_str()) };
        unsafe { cwe_w.write_varchar(count, w.cwe) };
        unsafe { proto_w.write_varchar(count, w.protocol) };
        unsafe { msg_w.write_varchar(count, &w.message) };
        init_data.idx += 1;
        count += 1;
    }

    unsafe { out_chunk.set_size(count) };
});

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
