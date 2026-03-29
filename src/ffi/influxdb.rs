// SPDX-License-Identifier: MIT
// Copyright 2026 Tom F. <tomf@tomtomtech.net> (https://github.com/tomtom215)

use libduckdb_sys::*;
use quack_rs::prelude::*;

use crate::influxdb;

use super::scalars::write_varchar;

fn influx_result_type() -> LogicalType {
    LogicalType::struct_type_from_logical(&[
        ("success", LogicalType::new(TypeId::Boolean)),
        ("body", LogicalType::new(TypeId::Varchar)),
        ("message", LogicalType::new(TypeId::Varchar)),
    ])
}

/// influx_query(url, org, token, flux_query) -> STRUCT(success, body, message)
unsafe extern "C" fn cb_influx_query(
    _info: duckdb_function_info,
    input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    let chunk = DataChunk::from_raw(input);
    let row_count = chunk.size();
    let url_reader = chunk.reader(0);
    let org_reader = chunk.reader(1);
    let token_reader = chunk.reader(2);
    let flux_query_reader = chunk.reader(3);

    let mut success_w = StructVector::field_writer(output, 0);
    let body_vec = duckdb_struct_vector_get_child(output, 1);
    let message_vec = duckdb_struct_vector_get_child(output, 2);

    for row in 0..row_count {
        let url = url_reader.read_str(row as usize);
        let org = org_reader.read_str(row as usize);
        let token = token_reader.read_str(row as usize);
        let flux_query = flux_query_reader.read_str(row as usize);

        let result = influxdb::query(url, org, token, flux_query);

        success_w.write_bool(row as usize, result.success);
        write_varchar(body_vec, row, &result.body);
        write_varchar(message_vec, row, &result.message);
    }
}

/// influx_write(url, org, bucket, token, line_protocol) -> STRUCT(success, body, message)
unsafe extern "C" fn cb_influx_write(
    _info: duckdb_function_info,
    input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    let chunk = DataChunk::from_raw(input);
    let row_count = chunk.size();
    let url_reader = chunk.reader(0);
    let org_reader = chunk.reader(1);
    let bucket_reader = chunk.reader(2);
    let token_reader = chunk.reader(3);
    let line_protocol_reader = chunk.reader(4);

    let mut success_w = StructVector::field_writer(output, 0);
    let body_vec = duckdb_struct_vector_get_child(output, 1);
    let message_vec = duckdb_struct_vector_get_child(output, 2);

    for row in 0..row_count {
        let url = url_reader.read_str(row as usize);
        let org = org_reader.read_str(row as usize);
        let bucket = bucket_reader.read_str(row as usize);
        let token = token_reader.read_str(row as usize);
        let line_protocol = line_protocol_reader.read_str(row as usize);

        let result = influxdb::write(url, org, bucket, token, line_protocol);

        success_w.write_bool(row as usize, result.success);
        write_varchar(body_vec, row, &result.body);
        write_varchar(message_vec, row, &result.message);
    }
}

/// influx_health(url) -> STRUCT(success, body, message)
unsafe extern "C" fn cb_influx_health(
    _info: duckdb_function_info,
    input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    let chunk = DataChunk::from_raw(input);
    let row_count = chunk.size();
    let url_reader = chunk.reader(0);

    let mut success_w = StructVector::field_writer(output, 0);
    let body_vec = duckdb_struct_vector_get_child(output, 1);
    let message_vec = duckdb_struct_vector_get_child(output, 2);

    for row in 0..row_count {
        let url = url_reader.read_str(row as usize);

        let result = influxdb::health(url);

        success_w.write_bool(row as usize, result.success);
        write_varchar(body_vec, row, &result.body);
        write_varchar(message_vec, row, &result.message);
    }
}

pub unsafe fn register_all(con: duckdb_connection) -> Result<(), ExtensionError> {
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
        .register(con)?;

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
        .register(con)?;

    // influx_health(url)
    ScalarFunctionBuilder::new("influx_health")
        .param(v) // url
        .returns_logical(influx_result_type())
        .function(cb_influx_health)
        .null_handling(NullHandling::SpecialNullHandling)
        .register(con)?;

    Ok(())
}
