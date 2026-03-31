// SPDX-License-Identifier: MIT
// Copyright 2026 Tom F. <tomf@tomtomtech.net> (https://github.com/tomtom215)

//! FFI bindings for the duck_net protocol feature-gate subsystem.
//!
//! SQL surface:
//!   SELECT * FROM duck_net_protocols();          -- all protocols + status
//!   SELECT duck_net_feature_status();            -- JSON summary
//!   SELECT duck_net_generate_config();           -- sample config file text

use libduckdb_sys::*;
use quack_rs::prelude::*;

use crate::features;

// ---------------------------------------------------------------------------
// duck_net_feature_status() -> VARCHAR  (JSON summary)
// ---------------------------------------------------------------------------

quack_rs::scalar_callback!(cb_feature_status, |_info, _input, output| {
    let snap = features::status_snapshot();
    let enabled: Vec<&str> = snap
        .iter()
        .filter(|(_, _, on)| *on)
        .map(|(n, _, _)| *n)
        .collect();
    let disabled_count = snap.len() - enabled.len();
    let enabled_list = enabled
        .iter()
        .map(|n| format!("\"{n}\""))
        .collect::<Vec<_>>()
        .join(",");

    let status = format!(
        "{{\"config_file\":\"{}\",\
          \"core_always_on\":{},\
          \"opt_in_enabled\":{},\
          \"opt_in_disabled\":{},\
          \"enabled_opt_in\":[{}]}}",
        features::config_path()
            .replace('\\', "\\\\")
            .replace('"', "\\\""),
        features::CORE_PROTOCOLS.len(),
        enabled.len(),
        disabled_count,
        enabled_list,
    );

    let mut w = unsafe { VectorWriter::from_vector(output) };
    unsafe { w.write_varchar(0, &status) };
});

// ---------------------------------------------------------------------------
// duck_net_generate_config() -> VARCHAR
// ---------------------------------------------------------------------------

quack_rs::scalar_callback!(cb_generate_config, |_info, _input, output| {
    let text = features::generate_sample_config();
    let mut w = unsafe { VectorWriter::from_vector(output) };
    unsafe { w.write_varchar(0, &text) };
});

// ---------------------------------------------------------------------------
// duck_net_protocols() table function
// ---------------------------------------------------------------------------

struct ProtoBindData;

struct ProtoInitData {
    /// Flattened snapshot: (name, group, description, enabled).
    rows: Vec<(&'static str, &'static str, &'static str, bool)>,
    idx: usize,
}

unsafe extern "C" fn proto_bind(info: duckdb_bind_info) {
    let bind = BindInfo::new(info);
    bind.add_result_column("protocol", TypeId::Varchar);
    bind.add_result_column("group", TypeId::Varchar);
    bind.add_result_column("enabled", TypeId::Boolean);
    bind.add_result_column("description", TypeId::Varchar);
    FfiBindData::<ProtoBindData>::set(info, ProtoBindData);
}

unsafe extern "C" fn proto_init(info: duckdb_init_info) {
    // Build the full row list: core first, then opt-in, alphabetically within
    // each group.
    let mut rows: Vec<(&'static str, &'static str, &'static str, bool)> = features::CORE_PROTOCOLS
        .iter()
        .map(|(name, desc)| (*name, "core", *desc, true))
        .collect();

    let mut opt: Vec<_> = features::OPT_IN_PROTOCOLS
        .iter()
        .map(|(name, desc)| (*name, "optional", *desc, features::is_enabled(name)))
        .collect();
    opt.sort_by_key(|(name, _, _, _)| *name);
    rows.extend(opt);

    FfiInitData::<ProtoInitData>::set(info, ProtoInitData { rows, idx: 0 });
}

quack_rs::table_scan_callback!(proto_scan, |info, output| {
    let init_data = match unsafe { FfiInitData::<ProtoInitData>::get_mut(info) } {
        Some(d) => d,
        None => {
            unsafe { DataChunk::from_raw(output).set_size(0) };
            return;
        }
    };

    let out_chunk = unsafe { DataChunk::from_raw(output) };
    let mut name_w = unsafe { out_chunk.writer(0) };
    let mut group_w = unsafe { out_chunk.writer(1) };
    let mut enabled_w = unsafe { out_chunk.writer(2) };
    let mut desc_w = unsafe { out_chunk.writer(3) };

    let mut count: usize = 0;
    let max_chunk = 2048;

    while init_data.idx < init_data.rows.len() && count < max_chunk {
        let (name, group, desc, enabled) = init_data.rows[init_data.idx];
        unsafe { name_w.write_varchar(count, name) };
        unsafe { group_w.write_varchar(count, group) };
        unsafe { enabled_w.write_bool(count, enabled) };
        unsafe { desc_w.write_varchar(count, desc) };
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

    // duck_net_feature_status() -> VARCHAR
    ScalarFunctionBuilder::new("duck_net_feature_status")
        .returns(TypeId::Varchar)
        .function(cb_feature_status)
        .register(raw)?;

    // duck_net_generate_config() -> VARCHAR
    ScalarFunctionBuilder::new("duck_net_generate_config")
        .returns(TypeId::Varchar)
        .function(cb_generate_config)
        .register(raw)?;

    // duck_net_protocols() -> TABLE(protocol, group, enabled, description)
    TableFunctionBuilder::new("duck_net_protocols")
        .bind(proto_bind)
        .init(proto_init)
        .scan(proto_scan)
        .register(raw)?;

    Ok(())
}
