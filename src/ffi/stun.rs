// SPDX-License-Identifier: MIT
// Copyright 2026 Tom F. <tomf@tomtomtech.net> (https://github.com/tomtom215)

use libduckdb_sys::*;
use quack_rs::prelude::*;

use crate::stun;

use super::scalars::StructWriter;

fn stun_result_type() -> LogicalType {
    LogicalType::struct_type_from_logical(&[
        ("success", LogicalType::new(TypeId::Boolean)),
        ("public_ip", LogicalType::new(TypeId::Varchar)),
        ("public_port", LogicalType::new(TypeId::Integer)),
        ("message", LogicalType::new(TypeId::Varchar)),
    ])
}

// stun_lookup(server) -> STRUCT(success, public_ip, public_port, message)
quack_rs::scalar_callback!(cb_stun_lookup, |_info, input, output| {
    let chunk = unsafe { DataChunk::from_raw(input) };
    let row_count = chunk.size();
    let server_reader = unsafe { chunk.reader(0) };

    let mut sw = unsafe { StructWriter::new(output, 4) };

    for row in 0..row_count {
        let server = unsafe { server_reader.read_str(row) };

        let result = stun::lookup(server);

        unsafe { sw.write_bool(row, 0, result.success) };
        unsafe { sw.write_varchar(row, 1, &result.public_ip) };
        unsafe { sw.write_i32(row, 2, result.public_port as i32) };
        unsafe { sw.write_varchar(row, 3, &result.message) };
    }
});

pub unsafe fn register_all(con: duckdb_connection) -> Result<(), ExtensionError> {
    ScalarFunctionBuilder::new("stun_lookup")
        .param(TypeId::Varchar) // server
        .returns_logical(stun_result_type())
        .function(cb_stun_lookup)
        .null_handling(NullHandling::SpecialNullHandling)
        .register(con)?;

    Ok(())
}
