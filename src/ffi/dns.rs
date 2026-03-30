// SPDX-License-Identifier: MIT
// Copyright 2026 Tom F. <tomf@tomtomtech.net> (https://github.com/tomtom215)

use libduckdb_sys::*;
use quack_rs::prelude::*;

use crate::dns;

// ===== Helper: write a Vec<String> to a LIST(VARCHAR) vector =====

pub(crate) unsafe fn write_string_list(
    output: duckdb_vector,
    row: usize,
    items: &[String],
    list_offset: &mut usize,
) {
    let n = items.len();
    let new_total = *list_offset + n;

    ListVector::reserve(output, new_total);
    let mut child_w = ListVector::child_writer(output);

    for (i, s) in items.iter().enumerate() {
        child_w.write_varchar(*list_offset + i, s);
    }

    ListVector::set_entry(output, row, *list_offset as u64, n as u64);
    *list_offset = new_total;
    ListVector::set_size(output, new_total);
}

// ===== DNS Callbacks =====

// dns_lookup(hostname) -> VARCHAR[]
quack_rs::scalar_callback!(cb_dns_lookup, |_info, input, output| {
    let chunk = unsafe { DataChunk::from_raw(input) };
    let row_count = chunk.size();
    let host_reader = unsafe { chunk.reader(0) };
    let mut list_offset: usize = 0;

    for row in 0..row_count {
        let hostname = unsafe { host_reader.read_str(row) };
        let ips = dns::lookup(hostname).unwrap_or_default();
        unsafe { write_string_list(output, row, &ips, &mut list_offset) };
    }
});

// dns_lookup_a(hostname) -> VARCHAR[]
quack_rs::scalar_callback!(cb_dns_lookup_a, |_info, input, output| {
    let chunk = unsafe { DataChunk::from_raw(input) };
    let row_count = chunk.size();
    let host_reader = unsafe { chunk.reader(0) };
    let mut list_offset: usize = 0;

    for row in 0..row_count {
        let hostname = unsafe { host_reader.read_str(row) };
        let ips = dns::lookup_a(hostname).unwrap_or_default();
        unsafe { write_string_list(output, row, &ips, &mut list_offset) };
    }
});

// dns_lookup_aaaa(hostname) -> VARCHAR[]
quack_rs::scalar_callback!(cb_dns_lookup_aaaa, |_info, input, output| {
    let chunk = unsafe { DataChunk::from_raw(input) };
    let row_count = chunk.size();
    let host_reader = unsafe { chunk.reader(0) };
    let mut list_offset: usize = 0;

    for row in 0..row_count {
        let hostname = unsafe { host_reader.read_str(row) };
        let ips = dns::lookup_aaaa(hostname).unwrap_or_default();
        unsafe { write_string_list(output, row, &ips, &mut list_offset) };
    }
});

// dns_reverse(ip) -> VARCHAR (nullable)
quack_rs::scalar_callback!(cb_dns_reverse, |_info, input, output| {
    let chunk = unsafe { DataChunk::from_raw(input) };
    let row_count = chunk.size();
    let ip_reader = unsafe { chunk.reader(0) };
    let mut writer = unsafe { VectorWriter::from_vector(output) };

    for row in 0..row_count {
        let ip = unsafe { ip_reader.read_str(row) };
        match dns::reverse(ip) {
            Ok(Some(hostname)) => unsafe { writer.write_varchar(row, &hostname) },
            _ => unsafe { writer.set_null(row) },
        }
    }
});

// dns_txt(hostname) -> VARCHAR[]
quack_rs::scalar_callback!(cb_dns_txt, |_info, input, output| {
    let chunk = unsafe { DataChunk::from_raw(input) };
    let row_count = chunk.size();
    let host_reader = unsafe { chunk.reader(0) };
    let mut list_offset: usize = 0;

    for row in 0..row_count {
        let hostname = unsafe { host_reader.read_str(row) };
        let txts = dns::lookup_txt(hostname).unwrap_or_default();
        unsafe { write_string_list(output, row, &txts, &mut list_offset) };
    }
});

// dns_mx(hostname) -> VARCHAR[] (each entry: "priority\thost")
quack_rs::scalar_callback!(cb_dns_mx, |_info, input, output| {
    let chunk = unsafe { DataChunk::from_raw(input) };
    let row_count = chunk.size();
    let host_reader = unsafe { chunk.reader(0) };
    let mut list_offset: usize = 0;

    for row in 0..row_count {
        let hostname = unsafe { host_reader.read_str(row) };
        let records = dns::lookup_mx(hostname).unwrap_or_default();
        let formatted: Vec<String> = records
            .iter()
            .map(|r| format!("{}\t{}", r.priority, r.host))
            .collect();
        unsafe { write_string_list(output, row, &formatted, &mut list_offset) };
    }
});

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
