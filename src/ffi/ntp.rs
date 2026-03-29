// SPDX-License-Identifier: MIT
// Copyright 2026 Tom F. <tomf@tomtomtech.net> (https://github.com/tomtom215)

use libduckdb_sys::*;
use quack_rs::prelude::*;

use crate::ntp;

use super::scalars::write_varchar;

fn ntp_result_type() -> LogicalType {
    LogicalType::struct_type_from_logical(&[
        ("offset_ms", LogicalType::new(TypeId::Double)),
        ("delay_ms", LogicalType::new(TypeId::Double)),
        ("stratum", LogicalType::new(TypeId::Integer)),
        ("reference_id", LogicalType::new(TypeId::Varchar)),
        ("server_time_unix", LogicalType::new(TypeId::Double)),
    ])
}

/// ntp_query(server) -> STRUCT(offset_ms, delay_ms, stratum, reference_id, server_time_unix)
unsafe extern "C" fn cb_ntp_query(
    _info: duckdb_function_info,
    input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    let chunk = DataChunk::from_raw(input);
    let row_count = chunk.size();
    let server_reader = chunk.reader(0);

    let mut offset_w = StructVector::field_writer(output, 0);
    let mut delay_w = StructVector::field_writer(output, 1);
    let mut stratum_w = StructVector::field_writer(output, 2);
    let refid_vec = duckdb_struct_vector_get_child(output, 3);
    let mut time_w = StructVector::field_writer(output, 4);

    for row in 0..row_count {
        let server = server_reader.read_str(row as usize);
        match ntp::query(server) {
            Ok(result) => {
                offset_w.write_f64(row as usize, result.offset_ms);
                delay_w.write_f64(row as usize, result.delay_ms);
                stratum_w.write_i32(row as usize, result.stratum as i32);
                write_varchar(refid_vec, row, &result.reference_id);
                time_w.write_f64(row as usize, result.server_time_unix);
            }
            Err(e) => {
                offset_w.write_f64(row as usize, 0.0);
                delay_w.write_f64(row as usize, 0.0);
                stratum_w.write_i32(row as usize, -1);
                write_varchar(refid_vec, row, &format!("Error: {e}"));
                time_w.write_f64(row as usize, 0.0);
            }
        }
    }
}

pub unsafe fn register_all(con: duckdb_connection) -> Result<(), ExtensionError> {
    ScalarFunctionBuilder::new("ntp_query")
        .param(TypeId::Varchar)
        .returns_logical(ntp_result_type())
        .function(cb_ntp_query)
        .null_handling(NullHandling::SpecialNullHandling)
        .register(con)?;

    Ok(())
}
