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

    let mut sw = unsafe { StructWriter::new(output, 5) };

    for row in 0..row_count {
        let domain = unsafe { domain_reader.read_str(row) };
        let raw = whois::lookup(domain).unwrap_or_else(|e| format!("WHOIS error: {e}"));
        let info = whois::parse_info(&raw);

        unsafe { sw.write_varchar(row, 0, &info.registrar) };
        unsafe { sw.write_varchar(row, 1, &info.creation_date) };
        unsafe { sw.write_varchar(row, 2, &info.expiration_date) };
        unsafe { sw.write_varchar(row, 3, &info.updated_date) };
        unsafe { sw.write_varchar(row, 4, &info.raw) };
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
