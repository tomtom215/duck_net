// SPDX-License-Identifier: MIT
// Copyright 2026 Tom F. <tomf@tomtomtech.net> (https://github.com/tomtom215)

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
    let chunk = DataChunk::from_raw(input);
    let row_count = chunk.size();
    let host_reader = chunk.reader(0);
    let oid_reader = chunk.reader(1);
    let comm_reader = chunk.reader(2);

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

    let out_chunk = DataChunk::from_raw(output);
    let mut oid_w = out_chunk.writer(0);
    let mut value_w = out_chunk.writer(1);
    let mut type_w = out_chunk.writer(2);

    let mut count: idx_t = 0;
    let max_chunk = 2048;

    while init_data.idx < init_data.results.len() && count < max_chunk {
        let r = &init_data.results[init_data.idx];
        oid_w.write_varchar(count as usize, &r.oid);
        value_w.write_varchar(count as usize, &r.value);
        type_w.write_varchar(count as usize, &r.value_type);
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
