// SPDX-License-Identifier: MIT
// Copyright 2026 Tom F. <tomf@tomtomtech.net> (https://github.com/tomtom215)

use quack_rs::prelude::*;

use crate::whois;

// whois_lookup(domain) -> VARCHAR (raw WHOIS text)
quack_rs::scalar_callback!(cb_whois_lookup, |_info, input, output| {
    let chunk = unsafe { DataChunk::from_raw(input) };
    let row_count = chunk.size();
    let domain_reader = unsafe { chunk.reader(0) };
    let mut writer = unsafe { VectorWriter::from_vector(output) };

    for row in 0..row_count {
        let domain = unsafe { domain_reader.read_str(row) };
        let result = whois::lookup(domain).unwrap_or_else(|e| format!("WHOIS error: {e}"));
        unsafe { writer.write_varchar(row, &result) };
    }
});

// whois_query(domain) -> STRUCT(registrar, creation_date, expiration_date, updated_date, raw)
quack_rs::scalar_callback!(cb_whois_query, |_info, input, output| {
    let chunk = unsafe { DataChunk::from_raw(input) };
    let row_count = chunk.size();
    let domain_reader = unsafe { chunk.reader(0) };

    let mut registrar_w = unsafe { StructVector::field_writer(output, 0) };
    let mut creation_w = unsafe { StructVector::field_writer(output, 1) };
    let mut expiration_w = unsafe { StructVector::field_writer(output, 2) };
    let mut updated_w = unsafe { StructVector::field_writer(output, 3) };
    let mut raw_w = unsafe { StructVector::field_writer(output, 4) };

    for row in 0..row_count {
        let domain = unsafe { domain_reader.read_str(row) };
        let raw = whois::lookup(domain).unwrap_or_else(|e| format!("WHOIS error: {e}"));
        let info = whois::parse_info(&raw);

        unsafe { registrar_w.write_varchar(row, &info.registrar) };
        unsafe { creation_w.write_varchar(row, &info.creation_date) };
        unsafe { expiration_w.write_varchar(row, &info.expiration_date) };
        unsafe { updated_w.write_varchar(row, &info.updated_date) };
        unsafe { raw_w.write_varchar(row, &info.raw) };
    }
});

fn whois_query_type() -> LogicalType {
    LogicalType::struct_type_from_logical(&[
        ("registrar", LogicalType::new(TypeId::Varchar)),
        ("creation_date", LogicalType::new(TypeId::Varchar)),
        ("expiration_date", LogicalType::new(TypeId::Varchar)),
        ("updated_date", LogicalType::new(TypeId::Varchar)),
        ("raw", LogicalType::new(TypeId::Varchar)),
    ])
}

pub unsafe fn register_all(con: &Connection) -> Result<(), ExtensionError> {
    let v = TypeId::Varchar;

    ScalarFunctionBuilder::new("whois_lookup")
        .param(v)
        .returns(v)
        .function(cb_whois_lookup)
        .register(con.as_raw_connection())?;

    ScalarFunctionBuilder::new("whois_query")
        .param(v)
        .returns_logical(whois_query_type())
        .function(cb_whois_query)
        .register(con.as_raw_connection())?;

    Ok(())
}
