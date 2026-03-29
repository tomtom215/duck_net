// SPDX-License-Identifier: MIT
// Copyright 2026 Tom F. <tomf@tomtomtech.net> (https://github.com/tomtom215)

use libduckdb_sys::*;
use quack_rs::prelude::*;

use crate::whois;

/// whois_lookup(domain) -> VARCHAR (raw WHOIS text)
unsafe extern "C" fn cb_whois_lookup(
    _info: duckdb_function_info,
    input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    let chunk = DataChunk::from_raw(input);
    let row_count = chunk.size();
    let domain_reader = chunk.reader(0);
    let mut writer = VectorWriter::from_vector(output);

    for row in 0..row_count {
        let domain = domain_reader.read_str(row);
        let result = whois::lookup(domain).unwrap_or_else(|e| format!("WHOIS error: {e}"));
        writer.write_varchar(row, &result);
    }
}

/// whois_query(domain) -> STRUCT(registrar, creation_date, expiration_date, updated_date, raw)
unsafe extern "C" fn cb_whois_query(
    _info: duckdb_function_info,
    input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    let chunk = DataChunk::from_raw(input);
    let row_count = chunk.size();
    let domain_reader = chunk.reader(0);

    let mut registrar_w = StructVector::field_writer(output, 0);
    let mut creation_w = StructVector::field_writer(output, 1);
    let mut expiration_w = StructVector::field_writer(output, 2);
    let mut updated_w = StructVector::field_writer(output, 3);
    let mut raw_w = StructVector::field_writer(output, 4);

    for row in 0..row_count {
        let domain = domain_reader.read_str(row);
        let raw = whois::lookup(domain).unwrap_or_else(|e| format!("WHOIS error: {e}"));
        let info = whois::parse_info(&raw);

        registrar_w.write_varchar(row, &info.registrar);
        creation_w.write_varchar(row, &info.creation_date);
        expiration_w.write_varchar(row, &info.expiration_date);
        updated_w.write_varchar(row, &info.updated_date);
        raw_w.write_varchar(row, &info.raw);
    }
}

fn whois_query_type() -> LogicalType {
    LogicalType::struct_type_from_logical(&[
        ("registrar", LogicalType::new(TypeId::Varchar)),
        ("creation_date", LogicalType::new(TypeId::Varchar)),
        ("expiration_date", LogicalType::new(TypeId::Varchar)),
        ("updated_date", LogicalType::new(TypeId::Varchar)),
        ("raw", LogicalType::new(TypeId::Varchar)),
    ])
}

pub unsafe fn register_all(con: duckdb_connection) -> Result<(), ExtensionError> {
    let v = TypeId::Varchar;

    ScalarFunctionBuilder::new("whois_lookup")
        .param(v)
        .returns(v)
        .function(cb_whois_lookup)
        .register(con)?;

    ScalarFunctionBuilder::new("whois_query")
        .param(v)
        .returns_logical(whois_query_type())
        .function(cb_whois_query)
        .register(con)?;

    Ok(())
}
