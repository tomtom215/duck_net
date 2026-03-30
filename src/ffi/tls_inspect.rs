// SPDX-License-Identifier: MIT
// Copyright 2026 Tom F. <tomf@tomtomtech.net> (https://github.com/tomtom215)

use libduckdb_sys::*;
use quack_rs::prelude::*;

use crate::tls_inspect;

use super::dns::write_string_list;
use super::scalars::StructWriter;

fn tls_cert_type() -> LogicalType {
    LogicalType::struct_type_from_logical(&[
        ("subject", LogicalType::new(TypeId::Varchar)),
        ("issuer", LogicalType::new(TypeId::Varchar)),
        ("not_before", LogicalType::new(TypeId::Varchar)),
        ("not_after", LogicalType::new(TypeId::Varchar)),
        ("serial", LogicalType::new(TypeId::Varchar)),
        (
            "san_names",
            LogicalType::list_from_logical(&LogicalType::new(TypeId::Varchar)),
        ),
        ("key_algorithm", LogicalType::new(TypeId::Varchar)),
        ("signature_algorithm", LogicalType::new(TypeId::Varchar)),
        ("is_expired", LogicalType::new(TypeId::Boolean)),
        ("days_until_expiry", LogicalType::new(TypeId::BigInt)),
        ("version", LogicalType::new(TypeId::Varchar)),
    ])
}

// tls_inspect(host) -> STRUCT
quack_rs::scalar_callback!(cb_tls_inspect, |_info, input, output| {
    let chunk = unsafe { DataChunk::from_raw(input) };
    let row_count = chunk.size();
    let host_reader = unsafe { chunk.reader(0) };

    let mut sw = unsafe { StructWriter::new(output, 11) };
    let san_names_vec = unsafe { duckdb_struct_vector_get_child(output, 5) };

    let mut san_list_offset: usize = 0;

    for row in 0..row_count {
        let host = unsafe { host_reader.read_str(row as usize) };
        match tls_inspect::inspect(host, 443) {
            Ok(info) => {
                unsafe { sw.write_varchar(row as usize, 0, &info.subject) };
                unsafe { sw.write_varchar(row as usize, 1, &info.issuer) };
                unsafe { sw.write_varchar(row as usize, 2, &info.not_before) };
                unsafe { sw.write_varchar(row as usize, 3, &info.not_after) };
                unsafe { sw.write_varchar(row as usize, 4, &info.serial) };
                unsafe { write_string_list(san_names_vec, row, &info.san_names, &mut san_list_offset) };
                unsafe { sw.write_varchar(row as usize, 6, &info.key_algorithm) };
                unsafe { sw.write_varchar(row as usize, 7, &info.signature_algorithm) };
                unsafe { sw.write_bool(row as usize, 8, info.is_expired) };
                unsafe { sw.write_i64(row as usize, 9, info.days_until_expiry) };
                unsafe { sw.write_varchar(row as usize, 10, &info.version) };
            }
            Err(e) => {
                unsafe { sw.write_varchar(row as usize, 0, &format!("Error: {e}")) };
                unsafe { sw.write_varchar(row as usize, 1, "") };
                unsafe { sw.write_varchar(row as usize, 2, "") };
                unsafe { sw.write_varchar(row as usize, 3, "") };
                unsafe { sw.write_varchar(row as usize, 4, "") };
                unsafe { write_string_list(san_names_vec, row, &[], &mut san_list_offset) };
                unsafe { sw.write_varchar(row as usize, 6, "") };
                unsafe { sw.write_varchar(row as usize, 7, "") };
                unsafe { sw.write_bool(row as usize, 8, false) };
                unsafe { sw.write_i64(row as usize, 9, -1) };
                unsafe { sw.write_varchar(row as usize, 10, "") };
            }
        }
    }
});

// tls_inspect(host, port) -> STRUCT
quack_rs::scalar_callback!(cb_tls_inspect_port, |_info, input, output| {
    let chunk = unsafe { DataChunk::from_raw(input) };
    let row_count = chunk.size();
    let host_reader = unsafe { chunk.reader(0) };
    let port_reader = unsafe { chunk.reader(1) };

    let mut sw = unsafe { StructWriter::new(output, 11) };
    let san_names_vec = unsafe { duckdb_struct_vector_get_child(output, 5) };

    let mut san_list_offset: usize = 0;

    for row in 0..row_count {
        let host = unsafe { host_reader.read_str(row as usize) };
        let port = unsafe { port_reader.read_i32(row as usize) } as u16;
        match tls_inspect::inspect(host, port) {
            Ok(info) => {
                unsafe { sw.write_varchar(row as usize, 0, &info.subject) };
                unsafe { sw.write_varchar(row as usize, 1, &info.issuer) };
                unsafe { sw.write_varchar(row as usize, 2, &info.not_before) };
                unsafe { sw.write_varchar(row as usize, 3, &info.not_after) };
                unsafe { sw.write_varchar(row as usize, 4, &info.serial) };
                unsafe { write_string_list(san_names_vec, row, &info.san_names, &mut san_list_offset) };
                unsafe { sw.write_varchar(row as usize, 6, &info.key_algorithm) };
                unsafe { sw.write_varchar(row as usize, 7, &info.signature_algorithm) };
                unsafe { sw.write_bool(row as usize, 8, info.is_expired) };
                unsafe { sw.write_i64(row as usize, 9, info.days_until_expiry) };
                unsafe { sw.write_varchar(row as usize, 10, &info.version) };
            }
            Err(e) => {
                unsafe { sw.write_varchar(row as usize, 0, &format!("Error: {e}")) };
                unsafe { sw.write_varchar(row as usize, 1, "") };
                unsafe { sw.write_varchar(row as usize, 2, "") };
                unsafe { sw.write_varchar(row as usize, 3, "") };
                unsafe { sw.write_varchar(row as usize, 4, "") };
                unsafe { write_string_list(san_names_vec, row, &[], &mut san_list_offset) };
                unsafe { sw.write_varchar(row as usize, 6, "") };
                unsafe { sw.write_varchar(row as usize, 7, "") };
                unsafe { sw.write_bool(row as usize, 8, false) };
                unsafe { sw.write_i64(row as usize, 9, -1) };
                unsafe { sw.write_varchar(row as usize, 10, "") };
            }
        }
    }
});

pub unsafe fn register_all(con: duckdb_connection) -> Result<(), ExtensionError> {
    ScalarFunctionSetBuilder::new("tls_inspect")
        .overload(
            ScalarOverloadBuilder::new()
                .param(TypeId::Varchar)
                .returns_logical(tls_cert_type())
                .function(cb_tls_inspect)
                .null_handling(NullHandling::SpecialNullHandling),
        )
        .overload(
            ScalarOverloadBuilder::new()
                .param(TypeId::Varchar)
                .param(TypeId::Integer)
                .returns_logical(tls_cert_type())
                .function(cb_tls_inspect_port)
                .null_handling(NullHandling::SpecialNullHandling),
        )
        .register(con)?;

    Ok(())
}
