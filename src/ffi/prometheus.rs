// SPDX-License-Identifier: MIT
// Copyright 2026 Tom F. <tomf@tomtomtech.net> (https://github.com/tomtom215)

use quack_rs::prelude::*;

use crate::prometheus;

fn prometheus_result_type() -> LogicalType {
    LogicalType::struct_type_from_logical(&[
        ("success", LogicalType::new(TypeId::Boolean)),
        ("result_type", LogicalType::new(TypeId::Varchar)),
        ("body", LogicalType::new(TypeId::Varchar)),
        ("message", LogicalType::new(TypeId::Varchar)),
    ])
}

// prometheus_query(url, promql) -> STRUCT(success, result_type, body, message)
quack_rs::scalar_callback!(cb_prometheus_query, |_info, input, output| {
    let chunk = unsafe { DataChunk::from_raw(input) };
    let row_count = chunk.size();
    let url_reader = unsafe { chunk.reader(0) };
    let promql_reader = unsafe { chunk.reader(1) };

    let mut sw = unsafe { StructWriter::new(output, 4) };

    for row in 0..row_count {
        let url = unsafe { url_reader.read_str(row) };
        let promql = unsafe { promql_reader.read_str(row) };

        let result = prometheus::query(url, promql);

        unsafe { sw.write_bool(row, 0, result.success) };
        unsafe { sw.write_varchar(row, 1, &result.result_type) };
        unsafe { sw.write_varchar(row, 2, &result.body) };
        unsafe { sw.write_varchar(row, 3, &result.message) };
    }
});

// prometheus_query_range(url, promql, start, end, step) -> STRUCT
quack_rs::scalar_callback!(cb_prometheus_query_range, |_info, input, output| {
    let chunk = unsafe { DataChunk::from_raw(input) };
    let row_count = chunk.size();
    let url_reader = unsafe { chunk.reader(0) };
    let promql_reader = unsafe { chunk.reader(1) };
    let start_reader = unsafe { chunk.reader(2) };
    let end_reader = unsafe { chunk.reader(3) };
    let step_reader = unsafe { chunk.reader(4) };

    let mut sw = unsafe { StructWriter::new(output, 4) };

    for row in 0..row_count {
        let url = unsafe { url_reader.read_str(row) };
        let promql = unsafe { promql_reader.read_str(row) };
        let start = unsafe { start_reader.read_str(row) };
        let end = unsafe { end_reader.read_str(row) };
        let step = unsafe { step_reader.read_str(row) };

        let result = prometheus::query_range(url, promql, start, end, step);

        unsafe { sw.write_bool(row, 0, result.success) };
        unsafe { sw.write_varchar(row, 1, &result.result_type) };
        unsafe { sw.write_varchar(row, 2, &result.body) };
        unsafe { sw.write_varchar(row, 3, &result.message) };
    }
});

pub unsafe fn register_all(con: &Connection) -> Result<(), ExtensionError> {
    let v = TypeId::Varchar;

    // prometheus_query(url, promql)
    ScalarFunctionBuilder::new("prometheus_query")
        .param(v) // url
        .param(v) // promql
        .returns_logical(prometheus_result_type())
        .function(cb_prometheus_query)
        .null_handling(NullHandling::SpecialNullHandling)
        .register(con.as_raw_connection())?;

    // prometheus_query_range(url, promql, start, end, step)
    ScalarFunctionBuilder::new("prometheus_query_range")
        .param(v) // url
        .param(v) // promql
        .param(v) // start
        .param(v) // end
        .param(v) // step
        .returns_logical(prometheus_result_type())
        .function(cb_prometheus_query_range)
        .null_handling(NullHandling::SpecialNullHandling)
        .register(con.as_raw_connection())?;

    Ok(())
}
