// SPDX-License-Identifier: MIT
// Copyright 2026 Tom F. <tomf@tomtomtech.net> (https://github.com/tomtom215)

use quack_rs::prelude::*;

use crate::ocsp;

fn ocsp_result_type() -> LogicalType {
    LogicalType::struct_type_from_logical(&[
        ("success", LogicalType::new(TypeId::Boolean)),
        ("status", LogicalType::new(TypeId::Varchar)),
        ("revocation_time", LogicalType::new(TypeId::Varchar)),
        ("this_update", LogicalType::new(TypeId::Varchar)),
        ("next_update", LogicalType::new(TypeId::Varchar)),
        ("responder", LogicalType::new(TypeId::Varchar)),
        ("message", LogicalType::new(TypeId::Varchar)),
    ])
}

// ocsp_check(host, port) -> STRUCT
quack_rs::scalar_callback!(cb_ocsp_check, |_info, input, output| {
    let chunk = unsafe { DataChunk::from_raw(input) };
    let row_count = chunk.size();
    let host_reader = unsafe { chunk.reader(0) };
    let port_reader = unsafe { chunk.reader(1) };

    let mut sw = unsafe { StructWriter::new(output, 7) };

    for row in 0..row_count {
        let host = unsafe { host_reader.read_str(row) };
        let port = unsafe { port_reader.read_i32(row) } as u16;

        let result = ocsp::check(host, port);

        unsafe { sw.write_bool(row, 0, result.success) };
        unsafe { sw.write_varchar(row, 1, &result.status) };
        unsafe { sw.write_varchar(row, 2, &result.revocation_time) };
        unsafe { sw.write_varchar(row, 3, &result.this_update) };
        unsafe { sw.write_varchar(row, 4, &result.next_update) };
        unsafe { sw.write_varchar(row, 5, &result.responder) };
        unsafe { sw.write_varchar(row, 6, &result.message) };
    }
});

// ocsp_check(host) -> STRUCT (default port 443)
quack_rs::scalar_callback!(cb_ocsp_check_default, |_info, input, output| {
    let chunk = unsafe { DataChunk::from_raw(input) };
    let row_count = chunk.size();
    let host_reader = unsafe { chunk.reader(0) };

    let mut sw = unsafe { StructWriter::new(output, 7) };

    for row in 0..row_count {
        let host = unsafe { host_reader.read_str(row) };

        let result = ocsp::check(host, 443);

        unsafe { sw.write_bool(row, 0, result.success) };
        unsafe { sw.write_varchar(row, 1, &result.status) };
        unsafe { sw.write_varchar(row, 2, &result.revocation_time) };
        unsafe { sw.write_varchar(row, 3, &result.this_update) };
        unsafe { sw.write_varchar(row, 4, &result.next_update) };
        unsafe { sw.write_varchar(row, 5, &result.responder) };
        unsafe { sw.write_varchar(row, 6, &result.message) };
    }
});

pub unsafe fn register_all(con: &Connection) -> Result<(), ExtensionError> {
    let v = TypeId::Varchar;

    ScalarFunctionSetBuilder::new("ocsp_check")
        .overload(
            ScalarOverloadBuilder::new()
                .param(v) // host
                .returns_logical(ocsp_result_type())
                .function(cb_ocsp_check_default)
                .null_handling(NullHandling::SpecialNullHandling),
        )
        .overload(
            ScalarOverloadBuilder::new()
                .param(v) // host
                .param(TypeId::Integer) // port
                .returns_logical(ocsp_result_type())
                .function(cb_ocsp_check)
                .null_handling(NullHandling::SpecialNullHandling),
        )
        .register(con.as_raw_connection())?;

    Ok(())
}
