// SPDX-License-Identifier: MIT
// Copyright 2026 Tom F. <tomf@tomtomtech.net> (https://github.com/tomtom215)

use quack_rs::prelude::*;

use crate::elasticsearch;

fn es_result_type() -> LogicalType {
    LogicalType::struct_type_from_logical(&[
        ("success", LogicalType::new(TypeId::Boolean)),
        ("body", LogicalType::new(TypeId::Varchar)),
        ("message", LogicalType::new(TypeId::Varchar)),
    ])
}

// es_search(url, index, query_json) -> STRUCT(success, body, message)
quack_rs::scalar_callback!(cb_es_search, |_info, input, output| {
    let chunk = unsafe { DataChunk::from_raw(input) };
    let row_count = chunk.size();
    let url_reader = unsafe { chunk.reader(0) };
    let index_reader = unsafe { chunk.reader(1) };
    let query_reader = unsafe { chunk.reader(2) };

    let mut sw = unsafe { StructWriter::new(output, 3) };

    for row in 0..row_count {
        let url = unsafe { url_reader.read_str(row) };
        let index = unsafe { index_reader.read_str(row) };
        let query = unsafe { query_reader.read_str(row) };

        let result = elasticsearch::search(url, index, query);

        unsafe { sw.write_bool(row, 0, result.success) };
        unsafe { sw.write_varchar(row, 1, &result.body) };
        unsafe { sw.write_varchar(row, 2, &result.message) };
    }
});

// es_count(url, index, query_json) -> STRUCT
quack_rs::scalar_callback!(cb_es_count, |_info, input, output| {
    let chunk = unsafe { DataChunk::from_raw(input) };
    let row_count = chunk.size();
    let url_reader = unsafe { chunk.reader(0) };
    let index_reader = unsafe { chunk.reader(1) };
    let query_reader = unsafe { chunk.reader(2) };

    let mut sw = unsafe { StructWriter::new(output, 3) };

    for row in 0..row_count {
        let url = unsafe { url_reader.read_str(row) };
        let index = unsafe { index_reader.read_str(row) };
        let query = unsafe { query_reader.read_str(row) };

        let result = elasticsearch::count(url, index, query);

        unsafe { sw.write_bool(row, 0, result.success) };
        unsafe { sw.write_varchar(row, 1, &result.body) };
        unsafe { sw.write_varchar(row, 2, &result.message) };
    }
});

// es_cat(url, endpoint) -> STRUCT
quack_rs::scalar_callback!(cb_es_cat, |_info, input, output| {
    let chunk = unsafe { DataChunk::from_raw(input) };
    let row_count = chunk.size();
    let url_reader = unsafe { chunk.reader(0) };
    let endpoint_reader = unsafe { chunk.reader(1) };

    let mut sw = unsafe { StructWriter::new(output, 3) };

    for row in 0..row_count {
        let url = unsafe { url_reader.read_str(row) };
        let endpoint = unsafe { endpoint_reader.read_str(row) };

        let result = elasticsearch::cat(url, endpoint);

        unsafe { sw.write_bool(row, 0, result.success) };
        unsafe { sw.write_varchar(row, 1, &result.body) };
        unsafe { sw.write_varchar(row, 2, &result.message) };
    }
});

pub unsafe fn register_all(con: &Connection) -> Result<(), ExtensionError> {
    let v = TypeId::Varchar;

    // es_search(url, index, query_json)
    ScalarFunctionBuilder::new("es_search")
        .param(v) // url
        .param(v) // index
        .param(v) // query_json
        .returns_logical(es_result_type())
        .function(cb_es_search)
        .null_handling(NullHandling::SpecialNullHandling)
        .register(con.as_raw_connection())?;

    // es_count(url, index, query_json)
    ScalarFunctionBuilder::new("es_count")
        .param(v) // url
        .param(v) // index
        .param(v) // query_json
        .returns_logical(es_result_type())
        .function(cb_es_count)
        .null_handling(NullHandling::SpecialNullHandling)
        .register(con.as_raw_connection())?;

    // es_cat(url, endpoint)
    ScalarFunctionBuilder::new("es_cat")
        .param(v) // url
        .param(v) // endpoint
        .returns_logical(es_result_type())
        .function(cb_es_cat)
        .null_handling(NullHandling::SpecialNullHandling)
        .register(con.as_raw_connection())?;

    Ok(())
}
