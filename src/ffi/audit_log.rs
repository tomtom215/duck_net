// SPDX-License-Identifier: MIT
// Copyright 2026 Tom F. <tomf@tomtomtech.net> (https://github.com/tomtom215)

//! FFI bindings for the duck_net audit logging subsystem.

use libduckdb_sys::*;
use quack_rs::prelude::*;

use crate::audit_log;

// ---------------------------------------------------------------------------
// Scalar callbacks
// ---------------------------------------------------------------------------

// duck_net_set_audit_logging(enabled BOOLEAN) -> VARCHAR
quack_rs::scalar_callback!(cb_set_audit_logging, |_info, input, output| {
    let chunk = unsafe { DataChunk::from_raw(input) };
    let row_count = chunk.size();
    let bool_reader = unsafe { chunk.reader(0) };
    let mut writer = unsafe { VectorWriter::from_vector(output) };

    for row in 0..row_count {
        let enabled = unsafe { bool_reader.read_bool(row) };
        audit_log::set_enabled(enabled);
        let msg = if enabled {
            format!(
                "Audit logging ENABLED. Network operations will be recorded (credentials scrubbed). \
                 Query with: SELECT * FROM duck_net_audit_log(); \
                 Current entries: {}",
                audit_log::len()
            )
        } else {
            format!(
                "Audit logging DISABLED. {} existing entries retained. \
                 Clear with: SELECT duck_net_clear_audit_log();",
                audit_log::len()
            )
        };
        unsafe { writer.write_varchar(row, &msg) };
    }
});

// duck_net_clear_audit_log() -> VARCHAR
quack_rs::scalar_callback!(cb_clear_audit_log, |_info, _input, output| {
    let count = audit_log::clear();
    let mut writer = unsafe { VectorWriter::from_vector(output) };
    unsafe { writer.write_varchar(0, &format!("Audit log cleared ({count} entries removed)")) };
});

// duck_net_audit_log_status() -> VARCHAR (JSON)
quack_rs::scalar_callback!(cb_audit_log_status, |_info, _input, output| {
    let enabled = audit_log::is_enabled();
    let count = audit_log::len();
    let status = format!(
        "{{\"audit_logging_enabled\":{enabled},\"entries\":{count},\"max_entries\":10000}}"
    );
    let mut writer = unsafe { VectorWriter::from_vector(output) };
    unsafe { writer.write_varchar(0, &status) };
});

// ---------------------------------------------------------------------------
// duck_net_audit_log() table function
// ---------------------------------------------------------------------------

struct AuditBindData;

struct AuditInitData {
    entries: Vec<audit_log::AuditEntry>,
    idx: usize,
}

unsafe extern "C" fn audit_bind(info: duckdb_bind_info) {
    let bind = BindInfo::new(info);
    bind.add_result_column("timestamp_iso", TypeId::Varchar);
    bind.add_result_column("timestamp_secs", TypeId::BigInt);
    bind.add_result_column("protocol", TypeId::Varchar);
    bind.add_result_column("operation", TypeId::Varchar);
    bind.add_result_column("host", TypeId::Varchar);
    bind.add_result_column("success", TypeId::Boolean);
    bind.add_result_column("status_code", TypeId::Integer);
    bind.add_result_column("message", TypeId::Varchar);
    FfiBindData::<AuditBindData>::set(info, AuditBindData);
}

unsafe extern "C" fn audit_init(info: duckdb_init_info) {
    FfiInitData::<AuditInitData>::set(
        info,
        AuditInitData {
            entries: vec![],
            idx: 0,
        },
    );
}

quack_rs::table_scan_callback!(audit_scan, |info, output| {
    let init_data = match unsafe { FfiInitData::<AuditInitData>::get_mut(info) } {
        Some(d) => d,
        None => {
            unsafe { DataChunk::from_raw(output).set_size(0) };
            return;
        }
    };

    // Snapshot entries on first scan batch.
    if init_data.entries.is_empty() && init_data.idx == 0 {
        init_data.entries = audit_log::entries();
    }

    let out_chunk = unsafe { DataChunk::from_raw(output) };
    let mut ts_iso_w = unsafe { out_chunk.writer(0) };
    let mut ts_secs_w = unsafe { out_chunk.writer(1) };
    let mut proto_w = unsafe { out_chunk.writer(2) };
    let mut op_w = unsafe { out_chunk.writer(3) };
    let mut host_w = unsafe { out_chunk.writer(4) };
    let mut ok_w = unsafe { out_chunk.writer(5) };
    let mut code_w = unsafe { out_chunk.writer(6) };
    let mut msg_w = unsafe { out_chunk.writer(7) };

    let mut count: usize = 0;
    let max_chunk = 2048;

    while init_data.idx < init_data.entries.len() && count < max_chunk {
        let e = &init_data.entries[init_data.idx];
        unsafe { ts_iso_w.write_varchar(count, &e.timestamp_iso) };
        unsafe { ts_secs_w.write_i64(count, e.timestamp_secs) };
        unsafe { proto_w.write_varchar(count, &e.protocol) };
        unsafe { op_w.write_varchar(count, &e.operation) };
        unsafe { host_w.write_varchar(count, &e.host) };
        unsafe { ok_w.write_bool(count, e.success) };
        unsafe { code_w.write_i32(count, e.status_code) };
        unsafe { msg_w.write_varchar(count, &e.message) };
        init_data.idx += 1;
        count += 1;
    }

    unsafe { out_chunk.set_size(count) };
});

// ---------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------

pub unsafe fn register_all(con: &Connection) -> Result<(), ExtensionError> {
    let raw = con.as_raw_connection();

    // Initialise the ring buffer.
    audit_log::init();

    // duck_net_set_audit_logging(enabled BOOLEAN) -> VARCHAR
    ScalarFunctionBuilder::new("duck_net_set_audit_logging")
        .param(TypeId::Boolean)
        .returns(TypeId::Varchar)
        .function(cb_set_audit_logging)
        .register(raw)?;

    // duck_net_clear_audit_log() -> VARCHAR
    ScalarFunctionBuilder::new("duck_net_clear_audit_log")
        .returns(TypeId::Varchar)
        .function(cb_clear_audit_log)
        .register(raw)?;

    // duck_net_audit_log_status() -> VARCHAR (JSON)
    ScalarFunctionBuilder::new("duck_net_audit_log_status")
        .returns(TypeId::Varchar)
        .function(cb_audit_log_status)
        .register(raw)?;

    // duck_net_audit_log() -> TABLE(...)
    TableFunctionBuilder::new("duck_net_audit_log")
        .bind(audit_bind)
        .init(audit_init)
        .scan(audit_scan)
        .register(raw)?;

    Ok(())
}
