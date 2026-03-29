// SPDX-License-Identifier: MIT
// Copyright 2026 Tom F. <tomf@tomtomtech.net> (https://github.com/tomtom215)

use std::ffi::CStr;

use libduckdb_sys::*;
use quack_rs::prelude::*;

use crate::snmp;

use super::scalars::write_varchar;

// ===== snmp_get scalar =====

fn snmp_result_type() -> LogicalType {
    LogicalType::struct_type_from_logical(&[
        ("oid", LogicalType::new(TypeId::Varchar)),
        ("value", LogicalType::new(TypeId::Varchar)),
        ("value_type", LogicalType::new(TypeId::Varchar)),
    ])
}

/// snmp_get(host, oid, community) -> STRUCT(oid, value, value_type)
unsafe extern "C" fn cb_snmp_get(
    _info: duckdb_function_info,
    input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    let row_count = duckdb_data_chunk_get_size(input);
    let host_reader = VectorReader::new(input, 0);
    let oid_reader = VectorReader::new(input, 1);
    let comm_reader = VectorReader::new(input, 2);

    let oid_vec = duckdb_struct_vector_get_child(output, 0);
    let value_vec = duckdb_struct_vector_get_child(output, 1);
    let type_vec = duckdb_struct_vector_get_child(output, 2);

    for row in 0..row_count {
        let host = host_reader.read_str(row as usize);
        let oid = oid_reader.read_str(row as usize);
        let community = comm_reader.read_str(row as usize);

        match snmp::get(host, oid, community) {
            Ok(result) => {
                write_varchar(oid_vec, row, &result.oid);
                write_varchar(value_vec, row, &result.value);
                write_varchar(type_vec, row, &result.value_type);
            }
            Err(e) => {
                write_varchar(oid_vec, row, oid);
                write_varchar(value_vec, row, &format!("Error: {e}"));
                write_varchar(type_vec, row, "ERROR");
            }
        }
    }
}

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
    let host = read_bind_str(&bind, 0);
    let oid = read_bind_str(&bind, 1);
    let community = read_bind_str(&bind, 2);

    let max_val = bind.get_named_parameter("max_entries");
    let max_entries = if max_val.is_null() {
        1000
    } else {
        let n = duckdb_get_int64(max_val) as usize;
        duckdb_destroy_value(&mut { max_val });
        n
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

unsafe fn read_bind_str(bind: &BindInfo, idx: u64) -> String {
    let val = bind.get_parameter(idx);
    let cstr = duckdb_get_varchar(val);
    let s = CStr::from_ptr(cstr).to_str().unwrap_or("").to_string();
    duckdb_free(cstr as *mut _);
    duckdb_destroy_value(&mut { val });
    s
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

unsafe extern "C" fn snmp_walk_scan(info: duckdb_function_info, output: duckdb_data_chunk) {
    let bind_data = match FfiBindData::<SnmpWalkBindData>::get_from_function(info) {
        Some(d) => d,
        None => {
            duckdb_data_chunk_set_size(output, 0);
            return;
        }
    };
    let init_data = match FfiInitData::<SnmpWalkInitData>::get_mut(info) {
        Some(d) => d,
        None => {
            duckdb_data_chunk_set_size(output, 0);
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
                duckdb_data_chunk_set_size(output, 0);
                return;
            }
        }
    }

    let oid_vec = duckdb_data_chunk_get_vector(output, 0);
    let value_vec = duckdb_data_chunk_get_vector(output, 1);
    let type_vec = duckdb_data_chunk_get_vector(output, 2);

    let mut count: idx_t = 0;
    let max_chunk = 2048;

    while init_data.idx < init_data.results.len() && count < max_chunk {
        let r = &init_data.results[init_data.idx];
        write_varchar(oid_vec, count, &r.oid);
        write_varchar(value_vec, count, &r.value);
        write_varchar(type_vec, count, &r.value_type);
        init_data.idx += 1;
        count += 1;
    }

    duckdb_data_chunk_set_size(output, count);
}

pub unsafe fn register_all(con: duckdb_connection) -> Result<(), ExtensionError> {
    let v = TypeId::Varchar;

    ScalarFunctionBuilder::new("snmp_get")
        .param(v)
        .param(v)
        .param(v)
        .returns_logical(snmp_result_type())
        .function(cb_snmp_get)
        .null_handling(NullHandling::SpecialNullHandling)
        .register(con)?;

    TableFunctionBuilder::new("snmp_walk")
        .param(v)
        .param(v)
        .param(v)
        .named_param("max_entries", TypeId::BigInt)
        .bind(snmp_walk_bind)
        .init(snmp_walk_init)
        .scan(snmp_walk_scan)
        .register(con)?;

    Ok(())
}
