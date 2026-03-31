// SPDX-License-Identifier: MIT
// Copyright 2026 Tom F. <tomf@tomtomtech.net> (https://github.com/tomtom215)

use quack_rs::prelude::*;

use crate::influxdb;

fn influx_result_type() -> LogicalType {
    LogicalType::struct_type_from_logical(&[
        ("success", LogicalType::new(TypeId::Boolean)),
        ("body", LogicalType::new(TypeId::Varchar)),
        ("message", LogicalType::new(TypeId::Varchar)),
    ])
}

// influx_query(url, org, token, flux_query) -> STRUCT(success, body, message)
quack_rs::scalar_callback!(cb_influx_query, |_info, input, output| {
    let chunk = unsafe { DataChunk::from_raw(input) };
    let row_count = chunk.size();
    let url_reader = unsafe { chunk.reader(0) };
    let org_reader = unsafe { chunk.reader(1) };
    let token_reader = unsafe { chunk.reader(2) };
    let flux_query_reader = unsafe { chunk.reader(3) };

    let mut sw = unsafe { StructWriter::new(output, 3) };

    for row in 0..row_count {
        let url = unsafe { url_reader.read_str(row) };
        let org = unsafe { org_reader.read_str(row) };
        let token = unsafe { token_reader.read_str(row) };
        let flux_query = unsafe { flux_query_reader.read_str(row) };

        let result = influxdb::query(url, org, token, flux_query);

        unsafe { sw.write_bool(row, 0, result.success) };
        unsafe { sw.write_varchar(row, 1, &result.body) };
        unsafe { sw.write_varchar(row, 2, &result.message) };
    }
});

// influx_write(url, org, bucket, token, line_protocol) -> STRUCT(success, body, message)
quack_rs::scalar_callback!(cb_influx_write, |_info, input, output| {
    let chunk = unsafe { DataChunk::from_raw(input) };
    let row_count = chunk.size();
    let url_reader = unsafe { chunk.reader(0) };
    let org_reader = unsafe { chunk.reader(1) };
    let bucket_reader = unsafe { chunk.reader(2) };
    let token_reader = unsafe { chunk.reader(3) };
    let line_protocol_reader = unsafe { chunk.reader(4) };

    let mut sw = unsafe { StructWriter::new(output, 3) };

    for row in 0..row_count {
        let url = unsafe { url_reader.read_str(row) };
        let org = unsafe { org_reader.read_str(row) };
        let bucket = unsafe { bucket_reader.read_str(row) };
        let token = unsafe { token_reader.read_str(row) };
        let line_protocol = unsafe { line_protocol_reader.read_str(row) };

        let result = influxdb::write(url, org, bucket, token, line_protocol);

        unsafe { sw.write_bool(row, 0, result.success) };
        unsafe { sw.write_varchar(row, 1, &result.body) };
        unsafe { sw.write_varchar(row, 2, &result.message) };
    }
});

// influx_health(url) -> STRUCT(success, body, message)
quack_rs::scalar_callback!(cb_influx_health, |_info, input, output| {
    let chunk = unsafe { DataChunk::from_raw(input) };
    let row_count = chunk.size();
    let url_reader = unsafe { chunk.reader(0) };

    let mut sw = unsafe { StructWriter::new(output, 3) };

    for row in 0..row_count {
        let url = unsafe { url_reader.read_str(row) };

        let result = influxdb::health(url);

        unsafe { sw.write_bool(row, 0, result.success) };
        unsafe { sw.write_varchar(row, 1, &result.body) };
        unsafe { sw.write_varchar(row, 2, &result.message) };
    }
});

pub unsafe fn register_all(con: &Connection) -> Result<(), ExtensionError> {
    let v = TypeId::Varchar;

    // influx_query(url, org, token, flux_query)
    ScalarFunctionBuilder::new("influx_query")
        .param(v) // url
        .param(v) // org
        .param(v) // token
        .param(v) // flux_query
        .returns_logical(influx_result_type())
        .function(cb_influx_query)
        .null_handling(NullHandling::SpecialNullHandling)
        .register(con.as_raw_connection())?;

    // influx_write(url, org, bucket, token, line_protocol)
    ScalarFunctionBuilder::new("influx_write")
        .param(v) // url
        .param(v) // org
        .param(v) // bucket
        .param(v) // token
        .param(v) // line_protocol
        .returns_logical(influx_result_type())
        .function(cb_influx_write)
        .null_handling(NullHandling::SpecialNullHandling)
        .register(con.as_raw_connection())?;

    // influx_health(url)
    ScalarFunctionBuilder::new("influx_health")
        .param(v) // url
        .returns_logical(influx_result_type())
        .function(cb_influx_health)
        .null_handling(NullHandling::SpecialNullHandling)
        .register(con.as_raw_connection())?;

    Ok(())
}
