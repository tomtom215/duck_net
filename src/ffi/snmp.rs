// SPDX-License-Identifier: MIT
// Copyright 2026 Tom F. <tomf@tomtomtech.net> (https://github.com/tomtom215)

use libduckdb_sys::*;
use quack_rs::prelude::*;

use crate::snmp;

// ===== snmp_get scalar =====

fn snmp_result_type() -> LogicalType {
    LogicalType::struct_type_from_logical(&[
        ("oid", LogicalType::new(TypeId::Varchar)),
        ("value", LogicalType::new(TypeId::Varchar)),
        ("value_type", LogicalType::new(TypeId::Varchar)),
    ])
}

// snmp_get(host, oid, community) -> STRUCT(oid, value, value_type)
quack_rs::scalar_callback!(cb_snmp_get, |_info, input, output| {
    let chunk = unsafe { DataChunk::from_raw(input) };
    let row_count = chunk.size();
    let host_reader = unsafe { chunk.reader(0) };
    let oid_reader = unsafe { chunk.reader(1) };
    let comm_reader = unsafe { chunk.reader(2) };

    let mut sw = unsafe { StructWriter::new(output, 3) };

    for row in 0..row_count {
        let host = unsafe { host_reader.read_str(row) };
        let oid = unsafe { oid_reader.read_str(row) };
        let community = unsafe { comm_reader.read_str(row) };

        match snmp::get(host, oid, community) {
            Ok(result) => {
                unsafe { sw.write_varchar(row, 0, &result.oid) };
                unsafe { sw.write_varchar(row, 1, &result.value) };
                unsafe { sw.write_varchar(row, 2, &result.value_type) };
            }
            Err(e) => {
                unsafe { sw.write_varchar(row, 0, oid) };
                unsafe { sw.write_varchar(row, 1, &format!("Error: {e}")) };
                unsafe { sw.write_varchar(row, 2, "ERROR") };
            }
        }
    }
});

// ===== snmp_walk table function =====

struct SnmpWalkBindData {
    host: String,
    oid: String,
    community: String,
    max_entries: usize,
}

struct SnmpWalkInitData {
    results: Vec<snmp::SnmpResult>,
    idx: usize,
    fetched: bool,
}

unsafe extern "C" fn snmp_walk_bind(info: duckdb_bind_info) {
    let bind = BindInfo::new(info);
    let host = bind.get_parameter_value(0).as_str().unwrap_or_default();
    let oid = bind.get_parameter_value(1).as_str().unwrap_or_default();
    let community = bind.get_parameter_value(2).as_str().unwrap_or_default();

    let max_val = bind.get_named_parameter_value("max_entries");
    let max_entries = if max_val.is_null() {
        1000
    } else {
        max_val.as_i64() as usize
    };

    bind.add_result_column("oid", TypeId::Varchar);
    bind.add_result_column("value", TypeId::Varchar);
    bind.add_result_column("value_type", TypeId::Varchar);

    FfiBindData::<SnmpWalkBindData>::set(
        info,
        SnmpWalkBindData {
            host,
            oid,
            community,
            max_entries,
        },
    );
}

unsafe extern "C" fn snmp_walk_init(info: duckdb_init_info) {
    FfiInitData::<SnmpWalkInitData>::set(
        info,
        SnmpWalkInitData {
            results: vec![],
            idx: 0,
            fetched: false,
        },
    );
}

// snmp_walk table scan callback
quack_rs::table_scan_callback!(snmp_walk_scan, |info, output| {
    let bind_data = match unsafe { FfiBindData::<SnmpWalkBindData>::get_from_function(info) } {
        Some(d) => d,
        None => {
            unsafe { DataChunk::from_raw(output).set_size(0) };
            return;
        }
    };
    let init_data = match unsafe { FfiInitData::<SnmpWalkInitData>::get_mut(info) } {
        Some(d) => d,
        None => {
            unsafe { DataChunk::from_raw(output).set_size(0) };
            return;
        }
    };

    if !init_data.fetched {
        init_data.fetched = true;
        match snmp::walk(
            &bind_data.host,
            &bind_data.oid,
            &bind_data.community,
            bind_data.max_entries,
        ) {
            Ok(results) => init_data.results = results,
            Err(e) => {
                let fi = FunctionInfo::new(info);
                fi.set_error(&e);
                unsafe { DataChunk::from_raw(output).set_size(0) };
                return;
            }
        }
    }

    let out_chunk = unsafe { DataChunk::from_raw(output) };
    let mut oid_w = unsafe { out_chunk.writer(0) };
    let mut value_w = unsafe { out_chunk.writer(1) };
    let mut type_w = unsafe { out_chunk.writer(2) };

    let mut count: idx_t = 0;
    let max_chunk = 2048;

    while init_data.idx < init_data.results.len() && count < max_chunk {
        let r = &init_data.results[init_data.idx];
        unsafe { oid_w.write_varchar(count as usize, &r.oid) };
        unsafe { value_w.write_varchar(count as usize, &r.value) };
        unsafe { type_w.write_varchar(count as usize, &r.value_type) };
        init_data.idx += 1;
        count += 1;
    }

    unsafe { out_chunk.set_size(count as usize) };
});

// ===== SNMPv3 helpers =====

fn hex_to_bytes(hex: &str) -> Result<Vec<u8>, String> {
    let hex = hex.trim();
    if hex.len() % 2 != 0 {
        return Err(format!(
            "Hex string must have even length, got {} chars",
            hex.len()
        ));
    }
    (0..hex.len() / 2)
        .map(|i| {
            u8::from_str_radix(&hex[2 * i..2 * i + 2], 16)
                .map_err(|_| format!("Invalid hex byte at position {}", i * 2))
        })
        .collect()
}

// snmp_v3_get(host, oid, username, auth_protocol, auth_password, engine_id_hex) -> STRUCT
quack_rs::scalar_callback!(cb_snmp_v3_get, |_info, input, output| {
    let chunk = unsafe { DataChunk::from_raw(input) };
    let row_count = chunk.size();
    let host_reader = unsafe { chunk.reader(0) };
    let oid_reader = unsafe { chunk.reader(1) };
    let user_reader = unsafe { chunk.reader(2) };
    let proto_reader = unsafe { chunk.reader(3) };
    let pass_reader = unsafe { chunk.reader(4) };
    let eid_reader = unsafe { chunk.reader(5) };

    let mut sw = unsafe { StructWriter::new(output, 3) };

    for row in 0..row_count {
        let host = unsafe { host_reader.read_str(row) };
        let oid = unsafe { oid_reader.read_str(row) };
        let username = unsafe { user_reader.read_str(row) };
        let auth_proto_str = unsafe { proto_reader.read_str(row) };
        let auth_password = unsafe { pass_reader.read_str(row) };
        let engine_id_hex = unsafe { eid_reader.read_str(row) };

        let result = snmp::SnmpV3AuthProtocol::from_str(auth_proto_str).and_then(|proto| {
            hex_to_bytes(engine_id_hex)
                .and_then(|eid| snmp::v3_get(host, oid, username, proto, auth_password, &eid))
        });

        match result {
            Ok(r) => {
                unsafe { sw.write_varchar(row, 0, &r.oid) };
                unsafe { sw.write_varchar(row, 1, &r.value) };
                unsafe { sw.write_varchar(row, 2, &r.value_type) };
            }
            Err(e) => {
                unsafe { sw.write_varchar(row, 0, oid) };
                unsafe { sw.write_varchar(row, 1, &format!("Error: {e}")) };
                unsafe { sw.write_varchar(row, 2, "ERROR") };
            }
        }
    }
});

// ===== snmp_v3_walk table function =====

struct SnmpV3WalkBindData {
    host: String,
    oid: String,
    username: String,
    auth_protocol: snmp::SnmpV3AuthProtocol,
    auth_password: String,
    engine_id: Vec<u8>,
    max_entries: usize,
}

struct SnmpV3WalkInitData {
    results: Vec<snmp::SnmpResult>,
    idx: usize,
    fetched: bool,
}

unsafe extern "C" fn snmp_v3_walk_bind(info: duckdb_bind_info) {
    let bind = BindInfo::new(info);
    let host = bind.get_parameter_value(0).as_str().unwrap_or_default();
    let oid = bind.get_parameter_value(1).as_str().unwrap_or_default();
    let username = bind.get_parameter_value(2).as_str().unwrap_or_default();
    let auth_proto_str = bind.get_parameter_value(3).as_str().unwrap_or_default();
    let auth_password = bind.get_parameter_value(4).as_str().unwrap_or_default();
    let engine_id_hex = bind.get_parameter_value(5).as_str().unwrap_or_default();

    let max_val = bind.get_named_parameter_value("max_entries");
    let max_entries = if max_val.is_null() {
        1000
    } else {
        max_val.as_i64() as usize
    };

    bind.add_result_column("oid", TypeId::Varchar);
    bind.add_result_column("value", TypeId::Varchar);
    bind.add_result_column("value_type", TypeId::Varchar);

    let auth_protocol = snmp::SnmpV3AuthProtocol::from_str(&auth_proto_str)
        .unwrap_or(snmp::SnmpV3AuthProtocol::None);
    let engine_id = hex_to_bytes(&engine_id_hex).unwrap_or_default();

    FfiBindData::<SnmpV3WalkBindData>::set(
        info,
        SnmpV3WalkBindData {
            host,
            oid,
            username,
            auth_protocol,
            auth_password,
            engine_id,
            max_entries,
        },
    );
}

unsafe extern "C" fn snmp_v3_walk_init(info: duckdb_init_info) {
    FfiInitData::<SnmpV3WalkInitData>::set(
        info,
        SnmpV3WalkInitData {
            results: vec![],
            idx: 0,
            fetched: false,
        },
    );
}

quack_rs::table_scan_callback!(snmp_v3_walk_scan, |info, output| {
    let bind_data =
        match unsafe { FfiBindData::<SnmpV3WalkBindData>::get_from_function(info) } {
            Some(d) => d,
            None => {
                unsafe { DataChunk::from_raw(output).set_size(0) };
                return;
            }
        };
    let init_data = match unsafe { FfiInitData::<SnmpV3WalkInitData>::get_mut(info) } {
        Some(d) => d,
        None => {
            unsafe { DataChunk::from_raw(output).set_size(0) };
            return;
        }
    };

    if !init_data.fetched {
        init_data.fetched = true;
        match snmp::v3_walk(
            &bind_data.host,
            &bind_data.oid,
            &bind_data.username,
            bind_data.auth_protocol,
            &bind_data.auth_password,
            &bind_data.engine_id,
            bind_data.max_entries,
        ) {
            Ok(results) => init_data.results = results,
            Err(e) => {
                let fi = FunctionInfo::new(info);
                fi.set_error(&e);
                unsafe { DataChunk::from_raw(output).set_size(0) };
                return;
            }
        }
    }

    let out_chunk = unsafe { DataChunk::from_raw(output) };
    let mut oid_w = unsafe { out_chunk.writer(0) };
    let mut value_w = unsafe { out_chunk.writer(1) };
    let mut type_w = unsafe { out_chunk.writer(2) };

    let mut count: idx_t = 0;
    let max_chunk = 2048;

    while init_data.idx < init_data.results.len() && count < max_chunk {
        let r = &init_data.results[init_data.idx];
        unsafe { oid_w.write_varchar(count as usize, &r.oid) };
        unsafe { value_w.write_varchar(count as usize, &r.value) };
        unsafe { type_w.write_varchar(count as usize, &r.value_type) };
        init_data.idx += 1;
        count += 1;
    }

    unsafe { out_chunk.set_size(count as usize) };
});

pub unsafe fn register_all(con: &Connection) -> Result<(), ExtensionError> {
    let v = TypeId::Varchar;

    ScalarFunctionBuilder::new("snmp_get")
        .param(v)
        .param(v)
        .param(v)
        .returns_logical(snmp_result_type())
        .function(cb_snmp_get)
        .null_handling(NullHandling::SpecialNullHandling)
        .register(con.as_raw_connection())?;

    TableFunctionBuilder::new("snmp_walk")
        .param(v)
        .param(v)
        .param(v)
        .named_param("max_entries", TypeId::BigInt)
        .bind(snmp_walk_bind)
        .init(snmp_walk_init)
        .scan(snmp_walk_scan)
        .register(con.as_raw_connection())?;

    // snmp_v3_get(host, oid, username, auth_protocol, auth_password, engine_id_hex)
    ScalarFunctionBuilder::new("snmp_v3_get")
        .param(v) // host
        .param(v) // oid
        .param(v) // username
        .param(v) // auth_protocol (MD5, SHA1, NONE)
        .param(v) // auth_password
        .param(v) // engine_id_hex
        .returns_logical(snmp_result_type())
        .function(cb_snmp_v3_get)
        .null_handling(NullHandling::SpecialNullHandling)
        .register(con.as_raw_connection())?;

    // snmp_v3_walk(host, oid, username, auth_protocol, auth_password, engine_id_hex, [max_entries])
    TableFunctionBuilder::new("snmp_v3_walk")
        .param(v) // host
        .param(v) // oid
        .param(v) // username
        .param(v) // auth_protocol
        .param(v) // auth_password
        .param(v) // engine_id_hex
        .named_param("max_entries", TypeId::BigInt)
        .bind(snmp_v3_walk_bind)
        .init(snmp_v3_walk_init)
        .scan(snmp_v3_walk_scan)
        .register(con.as_raw_connection())?;

    Ok(())
}
