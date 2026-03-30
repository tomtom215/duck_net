// SPDX-License-Identifier: MIT
// Copyright 2026 Tom F. <tomf@tomtomtech.net> (https://github.com/tomtom215)

use libduckdb_sys::*;
use quack_rs::prelude::*;

use crate::ptp;


fn sntp_result_type() -> LogicalType {
    LogicalType::struct_type_from_logical(&[
        ("offset_ns", LogicalType::new(TypeId::Double)),
        ("delay_ns", LogicalType::new(TypeId::Double)),
        ("stratum", LogicalType::new(TypeId::Integer)),
        ("leap_indicator", LogicalType::new(TypeId::Integer)),
        ("version", LogicalType::new(TypeId::Integer)),
        ("poll_interval", LogicalType::new(TypeId::Integer)),
        ("precision", LogicalType::new(TypeId::Integer)),
        ("root_delay_us", LogicalType::new(TypeId::Double)),
        ("root_dispersion_us", LogicalType::new(TypeId::Double)),
        ("reference_id", LogicalType::new(TypeId::Varchar)),
        ("reference_time_unix", LogicalType::new(TypeId::Double)),
        ("receive_time_unix", LogicalType::new(TypeId::Double)),
        ("transmit_time_unix", LogicalType::new(TypeId::Double)),
        ("server_time_unix", LogicalType::new(TypeId::Double)),
    ])
}

fn ptp_probe_result_type() -> LogicalType {
    LogicalType::struct_type_from_logical(&[
        ("best_offset_ns", LogicalType::new(TypeId::Double)),
        ("best_delay_ns", LogicalType::new(TypeId::Double)),
        ("avg_offset_ns", LogicalType::new(TypeId::Double)),
        ("min_delay_ns", LogicalType::new(TypeId::Double)),
        ("max_delay_ns", LogicalType::new(TypeId::Double)),
        ("stddev_ns", LogicalType::new(TypeId::Double)),
        ("samples", LogicalType::new(TypeId::Integer)),
        ("stratum", LogicalType::new(TypeId::Integer)),
        ("reference_id", LogicalType::new(TypeId::Varchar)),
        ("server_time_unix", LogicalType::new(TypeId::Double)),
    ])
}

// sntp_query(server) -> STRUCT(offset_ns, delay_ns, stratum, leap_indicator, version,
//     poll_interval, precision, root_delay_us, root_dispersion_us, reference_id,
//     reference_time_unix, receive_time_unix, transmit_time_unix, server_time_unix)
quack_rs::scalar_callback!(cb_sntp_query, |_info, input, output| {
    let chunk = unsafe { DataChunk::from_raw(input) };
    let row_count = chunk.size();
    let server_reader = unsafe { chunk.reader(0) };

    let mut sw = unsafe { StructWriter::new(output, 14) };

    for row in 0..row_count {
        let server = unsafe { server_reader.read_str(row as usize) };
        match ptp::sntp_query(server) {
            Ok(result) => {
                unsafe { sw.write_f64(row as usize, 0, result.offset_ns) };
                unsafe { sw.write_f64(row as usize, 1, result.delay_ns) };
                unsafe { sw.write_i32(row as usize, 2, result.stratum as i32) };
                unsafe { sw.write_i32(row as usize, 3, result.leap_indicator as i32) };
                unsafe { sw.write_i32(row as usize, 4, result.version as i32) };
                unsafe { sw.write_i32(row as usize, 5, result.poll_interval as i32) };
                unsafe { sw.write_i32(row as usize, 6, result.precision as i32) };
                unsafe { sw.write_f64(row as usize, 7, result.root_delay_us) };
                unsafe { sw.write_f64(row as usize, 8, result.root_dispersion_us) };
                unsafe { sw.write_varchar(row as usize, 9, &result.reference_id) };
                unsafe { sw.write_f64(row as usize, 10, result.reference_time_unix) };
                unsafe { sw.write_f64(row as usize, 11, result.receive_time_unix) };
                unsafe { sw.write_f64(row as usize, 12, result.transmit_time_unix) };
                unsafe { sw.write_f64(row as usize, 13, result.server_time_unix) };
            }
            Err(e) => {
                unsafe { sw.write_f64(row as usize, 0, 0.0) };
                unsafe { sw.write_f64(row as usize, 1, 0.0) };
                unsafe { sw.write_i32(row as usize, 2, -1) };
                unsafe { sw.write_i32(row as usize, 3, 0) };
                unsafe { sw.write_i32(row as usize, 4, 0) };
                unsafe { sw.write_i32(row as usize, 5, 0) };
                unsafe { sw.write_i32(row as usize, 6, 0) };
                unsafe { sw.write_f64(row as usize, 7, 0.0) };
                unsafe { sw.write_f64(row as usize, 8, 0.0) };
                unsafe { sw.write_varchar(row as usize, 9, &format!("Error: {e}")) };
                unsafe { sw.write_f64(row as usize, 10, 0.0) };
                unsafe { sw.write_f64(row as usize, 11, 0.0) };
                unsafe { sw.write_f64(row as usize, 12, 0.0) };
                unsafe { sw.write_f64(row as usize, 13, 0.0) };
            }
        }
    }
});

/// Helper to write a PtpProbeResult (or error defaults) into the output vectors at a given row.
#[allow(clippy::too_many_arguments)]
unsafe fn write_ptp_probe_row(
    sw: &mut StructWriter,
    row: usize,
    best_offset_ns: f64,
    best_delay_ns: f64,
    avg_offset_ns: f64,
    min_delay_ns: f64,
    max_delay_ns: f64,
    stddev_ns: f64,
    samples: i32,
    stratum: i32,
    reference_id: &str,
    server_time_unix: f64,
) {
    sw.write_f64(row, 0, best_offset_ns);
    sw.write_f64(row, 1, best_delay_ns);
    sw.write_f64(row, 2, avg_offset_ns);
    sw.write_f64(row, 3, min_delay_ns);
    sw.write_f64(row, 4, max_delay_ns);
    sw.write_f64(row, 5, stddev_ns);
    sw.write_i32(row, 6, samples);
    sw.write_i32(row, 7, stratum);
    sw.write_varchar(row, 8, reference_id);
    sw.write_f64(row, 9, server_time_unix);
}

// ptp_probe(server, count) -> STRUCT(best_offset_ns, best_delay_ns, avg_offset_ns,
//     min_delay_ns, max_delay_ns, stddev_ns, samples, stratum, reference_id, server_time_unix)
quack_rs::scalar_callback!(cb_ptp_probe, |_info, input, output| {
    let chunk = unsafe { DataChunk::from_raw(input) };
    let row_count = chunk.size();
    let server_reader = unsafe { chunk.reader(0) };
    let count_reader = unsafe { chunk.reader(1) };

    let mut sw = unsafe { StructWriter::new(output, 10) };

    for row in 0..row_count {
        let server = unsafe { server_reader.read_str(row as usize) };
        let count = unsafe { count_reader.read_i32(row as usize) } as u8;
        match ptp::ptp_probe(server, count) {
            Ok(result) => {
                unsafe {
                    write_ptp_probe_row(
                        &mut sw,
                        row,
                        result.best_offset_ns,
                        result.best_delay_ns,
                        result.avg_offset_ns,
                        result.min_delay_ns,
                        result.max_delay_ns,
                        result.stddev_ns,
                        result.samples as i32,
                        result.stratum as i32,
                        &result.reference_id,
                        result.server_time_unix,
                    )
                };
            }
            Err(e) => {
                unsafe {
                    write_ptp_probe_row(
                        &mut sw,
                        row,
                        0.0,
                        0.0,
                        0.0,
                        0.0,
                        0.0,
                        0.0,
                        0,
                        -1,
                        &format!("Error: {e}"),
                        0.0,
                    )
                };
            }
        }
    }
});

// ptp_probe(server) -> same as above with default count=4
quack_rs::scalar_callback!(cb_ptp_probe_default, |_info, input, output| {
    let chunk = unsafe { DataChunk::from_raw(input) };
    let row_count = chunk.size();
    let server_reader = unsafe { chunk.reader(0) };

    let mut sw = unsafe { StructWriter::new(output, 10) };

    for row in 0..row_count {
        let server = unsafe { server_reader.read_str(row as usize) };
        match ptp::ptp_probe(server, 4) {
            Ok(result) => {
                unsafe {
                    write_ptp_probe_row(
                        &mut sw,
                        row,
                        result.best_offset_ns,
                        result.best_delay_ns,
                        result.avg_offset_ns,
                        result.min_delay_ns,
                        result.max_delay_ns,
                        result.stddev_ns,
                        result.samples as i32,
                        result.stratum as i32,
                        &result.reference_id,
                        result.server_time_unix,
                    )
                };
            }
            Err(e) => {
                unsafe {
                    write_ptp_probe_row(
                        &mut sw,
                        row,
                        0.0,
                        0.0,
                        0.0,
                        0.0,
                        0.0,
                        0.0,
                        0,
                        -1,
                        &format!("Error: {e}"),
                        0.0,
                    )
                };
            }
        }
    }
});

pub unsafe fn register_all(con: duckdb_connection) -> Result<(), ExtensionError> {
    ScalarFunctionBuilder::new("sntp_query")
        .param(TypeId::Varchar)
        .returns_logical(sntp_result_type())
        .function(cb_sntp_query)
        .null_handling(NullHandling::SpecialNullHandling)
        .register(con)?;

    ScalarFunctionSetBuilder::new("ptp_probe")
        .overload(
            ScalarOverloadBuilder::new()
                .param(TypeId::Varchar)
                .returns_logical(ptp_probe_result_type())
                .function(cb_ptp_probe_default)
                .null_handling(NullHandling::SpecialNullHandling),
        )
        .overload(
            ScalarOverloadBuilder::new()
                .param(TypeId::Varchar)
                .param(TypeId::Integer)
                .returns_logical(ptp_probe_result_type())
                .function(cb_ptp_probe)
                .null_handling(NullHandling::SpecialNullHandling),
        )
        .register(con)?;

    Ok(())
}
