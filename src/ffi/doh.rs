// SPDX-License-Identifier: MIT
// Copyright 2026 Tom F. <tomf@tomtomtech.net> (https://github.com/tomtom215)

use quack_rs::prelude::*;

use crate::doh;

use super::dns::write_string_list;

fn doh_result_type() -> LogicalType {
    LogicalType::struct_type_from_logical(&[
        ("success", LogicalType::new(TypeId::Boolean)),
        (
            "records",
            LogicalType::list_from_logical(&LogicalType::new(TypeId::Varchar)),
        ),
        ("message", LogicalType::new(TypeId::Varchar)),
    ])
}

// doh_lookup(resolver_url, domain, type) -> STRUCT(success, records, message)
quack_rs::scalar_callback!(cb_doh_lookup, |_info, input, output| {
    let chunk = unsafe { DataChunk::from_raw(input) };
    let row_count = chunk.size();
    let url_reader = unsafe { chunk.reader(0) };
    let domain_reader = unsafe { chunk.reader(1) };
    let type_reader = unsafe { chunk.reader(2) };

    let mut sw = unsafe { StructWriter::new(output, 3) };
    let records_vec = sw.child_vector(1);
    let mut list_offset: usize = 0;

    for row in 0..row_count {
        let url = unsafe { url_reader.read_str(row) };
        let domain = unsafe { domain_reader.read_str(row) };
        let rtype = unsafe { type_reader.read_str(row) };

        let result = doh::lookup(url, domain, rtype);

        unsafe { sw.write_bool(row, 0, result.success) };
        unsafe { write_string_list(records_vec, row, &result.records, &mut list_offset) };
        unsafe { sw.write_varchar(row, 2, &result.message) };
    }
});

// doh_lookup(domain, type) -> STRUCT (uses default Cloudflare resolver)
quack_rs::scalar_callback!(cb_doh_lookup_default, |_info, input, output| {
    let chunk = unsafe { DataChunk::from_raw(input) };
    let row_count = chunk.size();
    let domain_reader = unsafe { chunk.reader(0) };
    let type_reader = unsafe { chunk.reader(1) };

    let mut sw = unsafe { StructWriter::new(output, 3) };
    let records_vec = sw.child_vector(1);
    let mut list_offset: usize = 0;

    for row in 0..row_count {
        let domain = unsafe { domain_reader.read_str(row) };
        let rtype = unsafe { type_reader.read_str(row) };

        let result = doh::lookup_default(domain, rtype);

        unsafe { sw.write_bool(row, 0, result.success) };
        unsafe { write_string_list(records_vec, row, &result.records, &mut list_offset) };
        unsafe { sw.write_varchar(row, 2, &result.message) };
    }
});

pub unsafe fn register_all(con: &Connection) -> Result<(), ExtensionError> {
    let v = TypeId::Varchar;

    ScalarFunctionSetBuilder::new("doh_lookup")
        .overload(
            ScalarOverloadBuilder::new()
                .param(v) // domain
                .param(v) // type
                .returns_logical(doh_result_type())
                .function(cb_doh_lookup_default)
                .null_handling(NullHandling::SpecialNullHandling),
        )
        .overload(
            ScalarOverloadBuilder::new()
                .param(v) // resolver_url
                .param(v) // domain
                .param(v) // type
                .returns_logical(doh_result_type())
                .function(cb_doh_lookup)
                .null_handling(NullHandling::SpecialNullHandling),
        )
        .register(con.as_raw_connection())?;

    Ok(())
}
