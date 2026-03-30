// SPDX-License-Identifier: MIT
// Copyright 2026 Tom F. <tomf@tomtomtech.net> (https://github.com/tomtom215)

use libduckdb_sys::*;
use quack_rs::prelude::*;

use crate::ntp;

fn ntp_result_type() -> LogicalType {
    LogicalType::struct_type_from_logical(&[
        ("offset_ms", LogicalType::new(TypeId::Double)),
        ("delay_ms", LogicalType::new(TypeId::Double)),
        ("stratum", LogicalType::new(TypeId::Integer)),
        ("reference_id", LogicalType::new(TypeId::Varchar)),
        ("server_time_unix", LogicalType::new(TypeId::Double)),
    ])
}

// ntp_query(server) -> STRUCT(offset_ms, delay_ms, stratum, reference_id, server_time_unix)
quack_rs::scalar_callback!(cb_ntp_query, |_info, input, output| {
    let chunk = unsafe { DataChunk::from_raw(input) };
    let row_count = chunk.size();
    let server_reader = unsafe { chunk.reader(0) };

    let mut sw = unsafe { StructWriter::new(output, 5) };

    for row in 0..row_count {
        let server = unsafe { server_reader.read_str(row) };
        match ntp::query(server) {
            Ok(result) => {
                unsafe { sw.write_f64(row, 0, result.offset_ms) };
                unsafe { sw.write_f64(row, 1, result.delay_ms) };
                unsafe { sw.write_i32(row, 2, result.stratum as i32) };
                unsafe { sw.write_varchar(row, 3, &result.reference_id) };
                unsafe { sw.write_f64(row, 4, result.server_time_unix) };
            }
            Err(e) => {
                unsafe { sw.write_f64(row, 0, 0.0) };
                unsafe { sw.write_f64(row, 1, 0.0) };
                unsafe { sw.write_i32(row, 2, -1) };
                unsafe { sw.write_varchar(row, 3, &format!("Error: {e}")) };
                unsafe { sw.write_f64(row, 4, 0.0) };
            }
        }
    }
});

pub unsafe fn register_all(con: duckdb_connection) -> Result<(), ExtensionError> {
    ScalarFunctionBuilder::new("ntp_query")
        .param(TypeId::Varchar)
        .returns_logical(ntp_result_type())
        .function(cb_ntp_query)
        .null_handling(NullHandling::SpecialNullHandling)
        .register(con)?;

    Ok(())
}
