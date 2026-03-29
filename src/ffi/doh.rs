// SPDX-License-Identifier: MIT
// Copyright 2026 Tom F. <tomf@tomtomtech.net> (https://github.com/tomtom215)

use libduckdb_sys::*;
use quack_rs::prelude::*;

use crate::doh;

use super::dns::write_string_list;
use super::scalars::write_varchar;

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

/// doh_lookup(resolver_url, domain, type) -> STRUCT(success, records, message)
unsafe extern "C" fn cb_doh_lookup(
    _info: duckdb_function_info,
    input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    let chunk = DataChunk::from_raw(input);
    let row_count = chunk.size();
    let url_reader = chunk.reader(0);
    let domain_reader = chunk.reader(1);
    let type_reader = chunk.reader(2);

    let mut success_w = StructVector::field_writer(output, 0);
    let records_vec = duckdb_struct_vector_get_child(output, 1);
    let message_vec = duckdb_struct_vector_get_child(output, 2);
    let mut list_offset: usize = 0;

    for row in 0..row_count {
        let url = url_reader.read_str(row);
        let domain = domain_reader.read_str(row);
        let rtype = type_reader.read_str(row);

        let result = doh::lookup(url, domain, rtype);

        success_w.write_bool(row, result.success);
        write_string_list(records_vec, row, &result.records, &mut list_offset);
        write_varchar(message_vec, row, &result.message);
    }
}

/// doh_lookup(domain, type) -> STRUCT (uses default Cloudflare resolver)
unsafe extern "C" fn cb_doh_lookup_default(
    _info: duckdb_function_info,
    input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    let chunk = DataChunk::from_raw(input);
    let row_count = chunk.size();
    let domain_reader = chunk.reader(0);
    let type_reader = chunk.reader(1);

    let mut success_w = StructVector::field_writer(output, 0);
    let records_vec = duckdb_struct_vector_get_child(output, 1);
    let message_vec = duckdb_struct_vector_get_child(output, 2);
    let mut list_offset: usize = 0;

    for row in 0..row_count {
        let domain = domain_reader.read_str(row);
        let rtype = type_reader.read_str(row);

        let result = doh::lookup_default(domain, rtype);

        success_w.write_bool(row, result.success);
        write_string_list(records_vec, row, &result.records, &mut list_offset);
        write_varchar(message_vec, row, &result.message);
    }
}

pub unsafe fn register_all(con: duckdb_connection) -> Result<(), ExtensionError> {
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
        .register(con)?;

    Ok(())
}
