// SPDX-License-Identifier: MIT
// Copyright 2026 Tom F. <tomf@tomtomtech.net> (https://github.com/tomtom215)

use quack_rs::prelude::*;

use crate::bgp;

fn bgp_result_type() -> LogicalType {
    LogicalType::struct_type_from_logical(&[
        ("success", LogicalType::new(TypeId::Boolean)),
        ("body", LogicalType::new(TypeId::Varchar)),
        ("message", LogicalType::new(TypeId::Varchar)),
    ])
}

// bgp_route(prefix) -> STRUCT(success, body, message)
quack_rs::scalar_callback!(cb_bgp_route, |_info, input, output| {
    let chunk = unsafe { DataChunk::from_raw(input) };
    let row_count = chunk.size();
    let prefix_reader = unsafe { chunk.reader(0) };

    let mut sw = unsafe { StructWriter::new(output, 3) };

    for row in 0..row_count {
        let prefix = unsafe { prefix_reader.read_str(row) };

        let result = bgp::route(prefix);

        unsafe { sw.write_bool(row, 0, result.success) };
        unsafe { sw.write_varchar(row, 1, &result.body) };
        unsafe { sw.write_varchar(row, 2, &result.message) };
    }
});

// bgp_prefix_overview(prefix) -> STRUCT
quack_rs::scalar_callback!(cb_bgp_prefix_overview, |_info, input, output| {
    let chunk = unsafe { DataChunk::from_raw(input) };
    let row_count = chunk.size();
    let prefix_reader = unsafe { chunk.reader(0) };

    let mut sw = unsafe { StructWriter::new(output, 3) };

    for row in 0..row_count {
        let prefix = unsafe { prefix_reader.read_str(row) };

        let result = bgp::prefix_overview(prefix);

        unsafe { sw.write_bool(row, 0, result.success) };
        unsafe { sw.write_varchar(row, 1, &result.body) };
        unsafe { sw.write_varchar(row, 2, &result.message) };
    }
});

// bgp_asn_info(asn) -> STRUCT
quack_rs::scalar_callback!(cb_bgp_asn_info, |_info, input, output| {
    let chunk = unsafe { DataChunk::from_raw(input) };
    let row_count = chunk.size();
    let asn_reader = unsafe { chunk.reader(0) };

    let mut sw = unsafe { StructWriter::new(output, 3) };

    for row in 0..row_count {
        let asn = unsafe { asn_reader.read_str(row) };

        let result = bgp::asn_info(asn);

        unsafe { sw.write_bool(row, 0, result.success) };
        unsafe { sw.write_varchar(row, 1, &result.body) };
        unsafe { sw.write_varchar(row, 2, &result.message) };
    }
});

pub unsafe fn register_all(con: &Connection) -> Result<(), ExtensionError> {
    let v = TypeId::Varchar;

    // bgp_route(prefix)
    ScalarFunctionBuilder::new("bgp_route")
        .param(v)
        .returns_logical(bgp_result_type())
        .function(cb_bgp_route)
        .null_handling(NullHandling::SpecialNullHandling)
        .register(con.as_raw_connection())?;

    // bgp_prefix_overview(prefix)
    ScalarFunctionBuilder::new("bgp_prefix_overview")
        .param(v)
        .returns_logical(bgp_result_type())
        .function(cb_bgp_prefix_overview)
        .null_handling(NullHandling::SpecialNullHandling)
        .register(con.as_raw_connection())?;

    // bgp_asn_info(asn)
    ScalarFunctionBuilder::new("bgp_asn_info")
        .param(v)
        .returns_logical(bgp_result_type())
        .function(cb_bgp_asn_info)
        .null_handling(NullHandling::SpecialNullHandling)
        .register(con.as_raw_connection())?;

    Ok(())
}
