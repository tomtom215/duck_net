// SPDX-License-Identifier: MIT
// Copyright 2026 Tom F. <tomf@tomtomtech.net> (https://github.com/tomtom215)

use libduckdb_sys::*;
use quack_rs::prelude::*;

use crate::ptp;

use super::scalars::write_varchar;

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

/// sntp_query(server) -> STRUCT(offset_ns, delay_ns, stratum, leap_indicator, version,
///     poll_interval, precision, root_delay_us, root_dispersion_us, reference_id,
///     reference_time_unix, receive_time_unix, transmit_time_unix, server_time_unix)
unsafe extern "C" fn cb_sntp_query(
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
    let mut leap_w = StructVector::field_writer(output, 3);
    let mut version_w = StructVector::field_writer(output, 4);
    let mut poll_w = StructVector::field_writer(output, 5);
    let mut precision_w = StructVector::field_writer(output, 6);
    let mut root_delay_w = StructVector::field_writer(output, 7);
    let mut root_disp_w = StructVector::field_writer(output, 8);
    let refid_vec = StructVector::get_child(output, 9);
    let mut ref_time_w = StructVector::field_writer(output, 10);
    let mut rx_time_w = StructVector::field_writer(output, 11);
    let mut tx_time_w = StructVector::field_writer(output, 12);
    let mut srv_time_w = StructVector::field_writer(output, 13);

    for row in 0..row_count {
        let server = server_reader.read_str(row as usize);
        match ptp::sntp_query(server) {
            Ok(result) => {
                offset_w.write_f64(row as usize, result.offset_ns);
                delay_w.write_f64(row as usize, result.delay_ns);
                stratum_w.write_i32(row as usize, result.stratum as i32);
                leap_w.write_i32(row as usize, result.leap_indicator as i32);
                version_w.write_i32(row as usize, result.version as i32);
                poll_w.write_i32(row as usize, result.poll_interval as i32);
                precision_w.write_i32(row as usize, result.precision as i32);
                root_delay_w.write_f64(row as usize, result.root_delay_us);
                root_disp_w.write_f64(row as usize, result.root_dispersion_us);
                write_varchar(refid_vec, row as usize, &result.reference_id);
                ref_time_w.write_f64(row as usize, result.reference_time_unix);
                rx_time_w.write_f64(row as usize, result.receive_time_unix);
                tx_time_w.write_f64(row as usize, result.transmit_time_unix);
                srv_time_w.write_f64(row as usize, result.server_time_unix);
            }
            Err(e) => {
                offset_w.write_f64(row as usize, 0.0);
                delay_w.write_f64(row as usize, 0.0);
                stratum_w.write_i32(row as usize, -1);
                leap_w.write_i32(row as usize, 0);
                version_w.write_i32(row as usize, 0);
                poll_w.write_i32(row as usize, 0);
                precision_w.write_i32(row as usize, 0);
                root_delay_w.write_f64(row as usize, 0.0);
                root_disp_w.write_f64(row as usize, 0.0);
                write_varchar(refid_vec, row as usize, &format!("Error: {e}"));
                ref_time_w.write_f64(row as usize, 0.0);
                rx_time_w.write_f64(row as usize, 0.0);
                tx_time_w.write_f64(row as usize, 0.0);
                srv_time_w.write_f64(row as usize, 0.0);
            }
        }
    }
}

/// Helper to write a PtpProbeResult (or error defaults) into the output vectors at a given row.
#[allow(clippy::too_many_arguments)]
unsafe fn write_ptp_probe_row(
    output: duckdb_vector,
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
    let mut best_offset_w = StructVector::field_writer(output, 0);
    let mut best_delay_w = StructVector::field_writer(output, 1);
    let mut avg_offset_w = StructVector::field_writer(output, 2);
    let mut min_delay_w = StructVector::field_writer(output, 3);
    let mut max_delay_w = StructVector::field_writer(output, 4);
    let mut stddev_w = StructVector::field_writer(output, 5);
    let mut samples_w = StructVector::field_writer(output, 6);
    let mut stratum_w = StructVector::field_writer(output, 7);
    let refid_vec = StructVector::get_child(output, 8);
    let mut srv_time_w = StructVector::field_writer(output, 9);

    best_offset_w.write_f64(row as usize, best_offset_ns);
    best_delay_w.write_f64(row as usize, best_delay_ns);
    avg_offset_w.write_f64(row as usize, avg_offset_ns);
    min_delay_w.write_f64(row as usize, min_delay_ns);
    max_delay_w.write_f64(row as usize, max_delay_ns);
    stddev_w.write_f64(row as usize, stddev_ns);
    samples_w.write_i32(row as usize, samples);
    stratum_w.write_i32(row as usize, stratum);
    write_varchar(refid_vec, row as usize, reference_id);
    srv_time_w.write_f64(row as usize, server_time_unix);
}

/// ptp_probe(server, count) -> STRUCT(best_offset_ns, best_delay_ns, avg_offset_ns,
///     min_delay_ns, max_delay_ns, stddev_ns, samples, stratum, reference_id, server_time_unix)
unsafe extern "C" fn cb_ptp_probe(
    _info: duckdb_function_info,
    input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    let chunk = DataChunk::from_raw(input);
    let row_count = chunk.size();
    let server_reader = chunk.reader(0);
    let count_reader = chunk.reader(1);

    for row in 0..row_count {
        let server = server_reader.read_str(row as usize);
        let count = count_reader.read_i32(row as usize) as u8;
        match ptp::ptp_probe(server, count) {
            Ok(result) => {
                write_ptp_probe_row(
                    output,
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
                );
            }
            Err(e) => {
                write_ptp_probe_row(
                    output,
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
                );
            }
        }
    }
}

/// ptp_probe(server) -> same as above with default count=4
unsafe extern "C" fn cb_ptp_probe_default(
    _info: duckdb_function_info,
    input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    let chunk = DataChunk::from_raw(input);
    let row_count = chunk.size();
    let server_reader = chunk.reader(0);

    for row in 0..row_count {
        let server = server_reader.read_str(row as usize);
        match ptp::ptp_probe(server, 4) {
            Ok(result) => {
                write_ptp_probe_row(
                    output,
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
                );
            }
            Err(e) => {
                write_ptp_probe_row(
                    output,
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
                );
            }
        }
    }
}

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
