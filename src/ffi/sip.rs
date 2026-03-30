// SPDX-License-Identifier: MIT
// Copyright 2026 Tom F. <tomf@tomtomtech.net> (https://github.com/tomtom215)

use libduckdb_sys::*;
use quack_rs::prelude::*;

use crate::sip;


fn sip_result_type() -> LogicalType {
    LogicalType::struct_type_from_logical(&[
        ("alive", LogicalType::new(TypeId::Boolean)),
        ("status_code", LogicalType::new(TypeId::Integer)),
        ("status_text", LogicalType::new(TypeId::Varchar)),
        ("user_agent", LogicalType::new(TypeId::Varchar)),
        ("allow_methods", LogicalType::new(TypeId::Varchar)),
    ])
}

// sip_options(host) -> STRUCT
quack_rs::scalar_callback!(cb_sip_options, |_info, input, output| {
    let chunk = unsafe { DataChunk::from_raw(input) };
    let row_count = chunk.size();
    let host_reader = unsafe { chunk.reader(0) };

    let mut sw = unsafe { StructWriter::new(output, 5) };

    for row in 0..row_count {
        let host = unsafe { host_reader.read_str(row as usize) };
        let result = sip::options_ping(host, 0);

        unsafe { sw.write_bool(row as usize, 0, result.alive) };
        unsafe { sw.write_i32(row as usize, 1, result.status_code) };
        unsafe { sw.write_varchar(row as usize, 2, &result.status_text) };
        unsafe { sw.write_varchar(row as usize, 3, &result.user_agent) };
        unsafe { sw.write_varchar(row as usize, 4, &result.allow_methods) };
    }
});

// sip_options(host, port) -> STRUCT
quack_rs::scalar_callback!(cb_sip_options_port, |_info, input, output| {
    let chunk = unsafe { DataChunk::from_raw(input) };
    let row_count = chunk.size();
    let host_reader = unsafe { chunk.reader(0) };
    let port_reader = unsafe { chunk.reader(1) };

    let mut sw = unsafe { StructWriter::new(output, 5) };

    for row in 0..row_count {
        let host = unsafe { host_reader.read_str(row as usize) };
        let port = unsafe { port_reader.read_i32(row as usize) } as u16;
        let result = sip::options_ping(host, port);

        unsafe { sw.write_bool(row as usize, 0, result.alive) };
        unsafe { sw.write_i32(row as usize, 1, result.status_code) };
        unsafe { sw.write_varchar(row as usize, 2, &result.status_text) };
        unsafe { sw.write_varchar(row as usize, 3, &result.user_agent) };
        unsafe { sw.write_varchar(row as usize, 4, &result.allow_methods) };
    }
});

pub unsafe fn register_all(con: duckdb_connection) -> Result<(), ExtensionError> {
    let v = TypeId::Varchar;

    ScalarFunctionSetBuilder::new("sip_options")
        .overload(
            ScalarOverloadBuilder::new()
                .param(v)
                .returns_logical(sip_result_type())
                .function(cb_sip_options)
                .null_handling(NullHandling::SpecialNullHandling),
        )
        .overload(
            ScalarOverloadBuilder::new()
                .param(v)
                .param(TypeId::Integer)
                .returns_logical(sip_result_type())
                .function(cb_sip_options_port)
                .null_handling(NullHandling::SpecialNullHandling),
        )
        .register(con)?;

    Ok(())
}
