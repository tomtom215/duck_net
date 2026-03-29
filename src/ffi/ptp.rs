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
    let row_count = duckdb_data_chunk_get_size(input);
    let server_reader = VectorReader::new(input, 0);

    let offset_vec = duckdb_struct_vector_get_child(output, 0);
    let delay_vec = duckdb_struct_vector_get_child(output, 1);
    let stratum_vec = duckdb_struct_vector_get_child(output, 2);
    let leap_vec = duckdb_struct_vector_get_child(output, 3);
    let version_vec = duckdb_struct_vector_get_child(output, 4);
    let poll_vec = duckdb_struct_vector_get_child(output, 5);
    let precision_vec = duckdb_struct_vector_get_child(output, 6);
    let root_delay_vec = duckdb_struct_vector_get_child(output, 7);
    let root_disp_vec = duckdb_struct_vector_get_child(output, 8);
    let refid_vec = duckdb_struct_vector_get_child(output, 9);
    let ref_time_vec = duckdb_struct_vector_get_child(output, 10);
    let rx_time_vec = duckdb_struct_vector_get_child(output, 11);
    let tx_time_vec = duckdb_struct_vector_get_child(output, 12);
    let srv_time_vec = duckdb_struct_vector_get_child(output, 13);

    for row in 0..row_count {
        let server = server_reader.read_str(row as usize);
        match ptp::sntp_query(server) {
            Ok(result) => {
                let p = duckdb_vector_get_data(offset_vec) as *mut f64;
                *p.add(row as usize) = result.offset_ns;
                let p = duckdb_vector_get_data(delay_vec) as *mut f64;
                *p.add(row as usize) = result.delay_ns;
                let p = duckdb_vector_get_data(stratum_vec) as *mut i32;
                *p.add(row as usize) = result.stratum as i32;
                let p = duckdb_vector_get_data(leap_vec) as *mut i32;
                *p.add(row as usize) = result.leap_indicator as i32;
                let p = duckdb_vector_get_data(version_vec) as *mut i32;
                *p.add(row as usize) = result.version as i32;
                let p = duckdb_vector_get_data(poll_vec) as *mut i32;
                *p.add(row as usize) = result.poll_interval as i32;
                let p = duckdb_vector_get_data(precision_vec) as *mut i32;
                *p.add(row as usize) = result.precision as i32;
                let p = duckdb_vector_get_data(root_delay_vec) as *mut f64;
                *p.add(row as usize) = result.root_delay_us;
                let p = duckdb_vector_get_data(root_disp_vec) as *mut f64;
                *p.add(row as usize) = result.root_dispersion_us;
                write_varchar(refid_vec, row, &result.reference_id);
                let p = duckdb_vector_get_data(ref_time_vec) as *mut f64;
                *p.add(row as usize) = result.reference_time_unix;
                let p = duckdb_vector_get_data(rx_time_vec) as *mut f64;
                *p.add(row as usize) = result.receive_time_unix;
                let p = duckdb_vector_get_data(tx_time_vec) as *mut f64;
                *p.add(row as usize) = result.transmit_time_unix;
                let p = duckdb_vector_get_data(srv_time_vec) as *mut f64;
                *p.add(row as usize) = result.server_time_unix;
            }
            Err(e) => {
                let p = duckdb_vector_get_data(offset_vec) as *mut f64;
                *p.add(row as usize) = 0.0;
                let p = duckdb_vector_get_data(delay_vec) as *mut f64;
                *p.add(row as usize) = 0.0;
                let p = duckdb_vector_get_data(stratum_vec) as *mut i32;
                *p.add(row as usize) = -1;
                let p = duckdb_vector_get_data(leap_vec) as *mut i32;
                *p.add(row as usize) = 0;
                let p = duckdb_vector_get_data(version_vec) as *mut i32;
                *p.add(row as usize) = 0;
                let p = duckdb_vector_get_data(poll_vec) as *mut i32;
                *p.add(row as usize) = 0;
                let p = duckdb_vector_get_data(precision_vec) as *mut i32;
                *p.add(row as usize) = 0;
                let p = duckdb_vector_get_data(root_delay_vec) as *mut f64;
                *p.add(row as usize) = 0.0;
                let p = duckdb_vector_get_data(root_disp_vec) as *mut f64;
                *p.add(row as usize) = 0.0;
                write_varchar(refid_vec, row, &format!("Error: {e}"));
                let p = duckdb_vector_get_data(ref_time_vec) as *mut f64;
                *p.add(row as usize) = 0.0;
                let p = duckdb_vector_get_data(rx_time_vec) as *mut f64;
                *p.add(row as usize) = 0.0;
                let p = duckdb_vector_get_data(tx_time_vec) as *mut f64;
                *p.add(row as usize) = 0.0;
                let p = duckdb_vector_get_data(srv_time_vec) as *mut f64;
                *p.add(row as usize) = 0.0;
            }
        }
    }
}

/// Helper to write a PtpProbeResult (or error defaults) into the output vectors at a given row.
unsafe fn write_ptp_probe_row(
    output: duckdb_vector,
    row: idx_t,
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
    let best_offset_vec = duckdb_struct_vector_get_child(output, 0);
    let best_delay_vec = duckdb_struct_vector_get_child(output, 1);
    let avg_offset_vec = duckdb_struct_vector_get_child(output, 2);
    let min_delay_vec = duckdb_struct_vector_get_child(output, 3);
    let max_delay_vec = duckdb_struct_vector_get_child(output, 4);
    let stddev_vec = duckdb_struct_vector_get_child(output, 5);
    let samples_vec = duckdb_struct_vector_get_child(output, 6);
    let stratum_vec = duckdb_struct_vector_get_child(output, 7);
    let refid_vec = duckdb_struct_vector_get_child(output, 8);
    let srv_time_vec = duckdb_struct_vector_get_child(output, 9);

    let p = duckdb_vector_get_data(best_offset_vec) as *mut f64;
    *p.add(row as usize) = best_offset_ns;
    let p = duckdb_vector_get_data(best_delay_vec) as *mut f64;
    *p.add(row as usize) = best_delay_ns;
    let p = duckdb_vector_get_data(avg_offset_vec) as *mut f64;
    *p.add(row as usize) = avg_offset_ns;
    let p = duckdb_vector_get_data(min_delay_vec) as *mut f64;
    *p.add(row as usize) = min_delay_ns;
    let p = duckdb_vector_get_data(max_delay_vec) as *mut f64;
    *p.add(row as usize) = max_delay_ns;
    let p = duckdb_vector_get_data(stddev_vec) as *mut f64;
    *p.add(row as usize) = stddev_ns;
    let p = duckdb_vector_get_data(samples_vec) as *mut i32;
    *p.add(row as usize) = samples;
    let p = duckdb_vector_get_data(stratum_vec) as *mut i32;
    *p.add(row as usize) = stratum;
    write_varchar(refid_vec, row, reference_id);
    let p = duckdb_vector_get_data(srv_time_vec) as *mut f64;
    *p.add(row as usize) = server_time_unix;
}

/// ptp_probe(server, count) -> STRUCT(best_offset_ns, best_delay_ns, avg_offset_ns,
///     min_delay_ns, max_delay_ns, stddev_ns, samples, stratum, reference_id, server_time_unix)
unsafe extern "C" fn cb_ptp_probe(
    _info: duckdb_function_info,
    input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    let row_count = duckdb_data_chunk_get_size(input);
    let server_reader = VectorReader::new(input, 0);
    let count_reader = VectorReader::new(input, 1);

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
    let row_count = duckdb_data_chunk_get_size(input);
    let server_reader = VectorReader::new(input, 0);

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
