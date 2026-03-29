// SPDX-License-Identifier: MIT
// Copyright 2026 Tom F. <tomf@tomtomtech.net> (https://github.com/tomtom215)

use libduckdb_sys::*;
use quack_rs::prelude::*;

use crate::dns;

use super::scalars::write_varchar;

// ===== Helper: write a Vec<String> to a LIST(VARCHAR) vector =====

pub(crate) unsafe fn write_string_list(
    output: duckdb_vector,
    row: idx_t,
    items: &[String],
    list_offset: &mut idx_t,
) {
    let n = items.len() as idx_t;
    let new_total = *list_offset + n;

    ListVector::reserve(output, new_total as usize);
    let child = ListVector::get_child(output);

    for (i, s) in items.iter().enumerate() {
        write_varchar(child, *list_offset + i as idx_t, s);
    }

    ListVector::set_entry(output, row as usize, *list_offset, n);
    *list_offset = new_total;
    ListVector::set_size(output, new_total as usize);
}

// ===== DNS Callbacks =====

/// dns_lookup(hostname) -> VARCHAR[]
unsafe extern "C" fn cb_dns_lookup(
    _info: duckdb_function_info,
    input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    let row_count = duckdb_data_chunk_get_size(input);
    let host_reader = VectorReader::new(input, 0);
    let mut list_offset: idx_t = 0;

    for row in 0..row_count {
        let hostname = host_reader.read_str(row as usize);
        let ips = dns::lookup(hostname).unwrap_or_default();
        write_string_list(output, row, &ips, &mut list_offset);
    }
}

/// dns_lookup_a(hostname) -> VARCHAR[]
unsafe extern "C" fn cb_dns_lookup_a(
    _info: duckdb_function_info,
    input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    let row_count = duckdb_data_chunk_get_size(input);
    let host_reader = VectorReader::new(input, 0);
    let mut list_offset: idx_t = 0;

    for row in 0..row_count {
        let hostname = host_reader.read_str(row as usize);
        let ips = dns::lookup_a(hostname).unwrap_or_default();
        write_string_list(output, row, &ips, &mut list_offset);
    }
}

/// dns_lookup_aaaa(hostname) -> VARCHAR[]
unsafe extern "C" fn cb_dns_lookup_aaaa(
    _info: duckdb_function_info,
    input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    let row_count = duckdb_data_chunk_get_size(input);
    let host_reader = VectorReader::new(input, 0);
    let mut list_offset: idx_t = 0;

    for row in 0..row_count {
        let hostname = host_reader.read_str(row as usize);
        let ips = dns::lookup_aaaa(hostname).unwrap_or_default();
        write_string_list(output, row, &ips, &mut list_offset);
    }
}

/// dns_reverse(ip) -> VARCHAR (nullable)
unsafe extern "C" fn cb_dns_reverse(
    _info: duckdb_function_info,
    input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    let row_count = duckdb_data_chunk_get_size(input);
    let ip_reader = VectorReader::new(input, 0);
    duckdb_vector_ensure_validity_writable(output);
    let validity = duckdb_vector_get_validity(output);

    for row in 0..row_count {
        let ip = ip_reader.read_str(row as usize);
        match dns::reverse(ip) {
            Ok(Some(hostname)) => write_varchar(output, row, &hostname),
            _ => duckdb_validity_set_row_invalid(validity, row),
        }
    }
}

/// dns_txt(hostname) -> VARCHAR[]
unsafe extern "C" fn cb_dns_txt(
    _info: duckdb_function_info,
    input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    let row_count = duckdb_data_chunk_get_size(input);
    let host_reader = VectorReader::new(input, 0);
    let mut list_offset: idx_t = 0;

    for row in 0..row_count {
        let hostname = host_reader.read_str(row as usize);
        let txts = dns::lookup_txt(hostname).unwrap_or_default();
        write_string_list(output, row, &txts, &mut list_offset);
    }
}

/// dns_mx(hostname) -> VARCHAR[] (formatted as "priority host")
/// Using VARCHAR[] instead of LIST(STRUCT) for simplicity. Each entry is "priority\thost".
unsafe extern "C" fn cb_dns_mx(
    _info: duckdb_function_info,
    input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    let row_count = duckdb_data_chunk_get_size(input);
    let host_reader = VectorReader::new(input, 0);
    let mut list_offset: idx_t = 0;

    for row in 0..row_count {
        let hostname = host_reader.read_str(row as usize);
        let records = dns::lookup_mx(hostname).unwrap_or_default();
        let formatted: Vec<String> = records
            .iter()
            .map(|r| format!("{}\t{}", r.priority, r.host))
            .collect();
        write_string_list(output, row, &formatted, &mut list_offset);
    }
}

// ===== Registration =====

pub unsafe fn register_all(con: duckdb_connection) -> Result<(), ExtensionError> {
    // dns_lookup(hostname) -> VARCHAR[]
    ScalarFunctionBuilder::new("dns_lookup")
        .param(TypeId::Varchar)
        .returns_logical(LogicalType::list_from_logical(&LogicalType::new(
            TypeId::Varchar,
        )))
        .function(cb_dns_lookup)
        .register(con)?;

    // dns_lookup_a(hostname) -> VARCHAR[]
    ScalarFunctionBuilder::new("dns_lookup_a")
        .param(TypeId::Varchar)
        .returns_logical(LogicalType::list_from_logical(&LogicalType::new(
            TypeId::Varchar,
        )))
        .function(cb_dns_lookup_a)
        .register(con)?;

    // dns_lookup_aaaa(hostname) -> VARCHAR[]
    ScalarFunctionBuilder::new("dns_lookup_aaaa")
        .param(TypeId::Varchar)
        .returns_logical(LogicalType::list_from_logical(&LogicalType::new(
            TypeId::Varchar,
        )))
        .function(cb_dns_lookup_aaaa)
        .register(con)?;

    // dns_reverse(ip) -> VARCHAR
    ScalarFunctionBuilder::new("dns_reverse")
        .param(TypeId::Varchar)
        .returns(TypeId::Varchar)
        .function(cb_dns_reverse)
        .null_handling(NullHandling::SpecialNullHandling)
        .register(con)?;

    // dns_txt(hostname) -> VARCHAR[]
    ScalarFunctionBuilder::new("dns_txt")
        .param(TypeId::Varchar)
        .returns_logical(LogicalType::list_from_logical(&LogicalType::new(
            TypeId::Varchar,
        )))
        .function(cb_dns_txt)
        .register(con)?;

    // dns_mx(hostname) -> VARCHAR[] (each entry: "priority\thost")
    ScalarFunctionBuilder::new("dns_mx")
        .param(TypeId::Varchar)
        .returns_logical(LogicalType::list_from_logical(&LogicalType::new(
            TypeId::Varchar,
        )))
        .function(cb_dns_mx)
        .register(con)?;

    Ok(())
}
