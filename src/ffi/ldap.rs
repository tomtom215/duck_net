// SPDX-License-Identifier: MIT
// Copyright 2026 Tom F. <tomf@tomtomtech.net> (https://github.com/tomtom215)

use libduckdb_sys::*;
use quack_rs::prelude::*;

use crate::ldap;
use crate::ldap_write;

// ===== ldap_search table function =====

struct LdapSearchBindData {
    url: String,
    base_dn: String,
    filter: String,
    attributes: Vec<String>,
}

struct LdapSearchInitData {
    entries: Vec<ldap::LdapEntry>,
    idx: usize,
    fetched: bool,
}

unsafe extern "C" fn ldap_search_bind(info: duckdb_bind_info) {
    let bind = BindInfo::new(info);

    let url = bind.get_parameter_value(0).as_str().unwrap_or_default();
    let base_dn = bind.get_parameter_value(1).as_str().unwrap_or_default();
    let filter = bind.get_parameter_value(2).as_str().unwrap_or_default();
    let attrs_str = bind.get_parameter_value(3).as_str().unwrap_or_default();

    let attributes: Vec<String> = attrs_str
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();

    bind.add_result_column("dn", TypeId::Varchar);
    bind.add_result_column("attribute", TypeId::Varchar);
    bind.add_result_column("value", TypeId::Varchar);

    FfiBindData::<LdapSearchBindData>::set(
        info,
        LdapSearchBindData {
            url,
            base_dn,
            filter,
            attributes,
        },
    );
}

unsafe extern "C" fn ldap_search_init(info: duckdb_init_info) {
    FfiInitData::<LdapSearchInitData>::set(
        info,
        LdapSearchInitData {
            entries: vec![],
            idx: 0,
            fetched: false,
        },
    );
}

// ldap_search scan callback
quack_rs::table_scan_callback!(ldap_search_scan, |info, output| {
    let bind_data = match unsafe { FfiBindData::<LdapSearchBindData>::get_from_function(info) } {
        Some(d) => d,
        None => {
            unsafe { DataChunk::from_raw(output).set_size(0) };
            return;
        }
    };
    let init_data = match unsafe { FfiInitData::<LdapSearchInitData>::get_mut(info) } {
        Some(d) => d,
        None => {
            unsafe { DataChunk::from_raw(output).set_size(0) };
            return;
        }
    };

    if !init_data.fetched {
        init_data.fetched = true;
        let attrs: Vec<&str> = bind_data.attributes.iter().map(|s| s.as_str()).collect();
        let result = ldap::search(
            &bind_data.url,
            &bind_data.base_dn,
            &bind_data.filter,
            &attrs,
        );
        if !result.success {
            let fi = FunctionInfo::new(info);
            fi.set_error(&result.message);
            unsafe { DataChunk::from_raw(output).set_size(0) };
            return;
        }
        init_data.entries = result.entries;
    }

    // Flatten entries into rows
    let out_chunk = unsafe { DataChunk::from_raw(output) };
    let mut dn_w = unsafe { out_chunk.writer(0) };
    let mut attr_w = unsafe { out_chunk.writer(1) };
    let mut val_w = unsafe { out_chunk.writer(2) };

    let mut count: idx_t = 0;
    let max_chunk = 2048;

    while init_data.idx < init_data.entries.len() && count < max_chunk {
        let entry = &init_data.entries[init_data.idx];
        // Output one row per attribute value
        let mut emitted = false;
        for (attr_name, values) in &entry.attributes {
            for val in values {
                if count >= max_chunk {
                    // We need to come back for more rows from this entry
                    // For simplicity, we output all attributes of one entry at once
                    break;
                }
                unsafe { dn_w.write_varchar(count as usize, &entry.dn) };
                unsafe { attr_w.write_varchar(count as usize, attr_name) };
                unsafe { val_w.write_varchar(count as usize, val) };
                count += 1;
                emitted = true;
            }
        }
        if !emitted {
            // Entry with no attributes
            unsafe { dn_w.write_varchar(count as usize, &entry.dn) };
            unsafe { attr_w.write_varchar(count as usize, "") };
            unsafe { val_w.write_varchar(count as usize, "") };
            count += 1;
        }
        init_data.idx += 1;
    }

    unsafe { out_chunk.set_size(count as usize) };
});

// ===== ldap_bind scalar =====

fn ldap_bind_result_type() -> LogicalType {
    LogicalType::struct_type_from_logical(&[
        ("success", LogicalType::new(TypeId::Boolean)),
        ("message", LogicalType::new(TypeId::Varchar)),
    ])
}

// ldap_bind(url, bind_dn, password) -> STRUCT(success, message)
quack_rs::scalar_callback!(cb_ldap_bind, |_info, input, output| {
    let chunk = unsafe { DataChunk::from_raw(input) };
    let row_count = chunk.size();
    let url_reader = unsafe { chunk.reader(0) };
    let dn_reader = unsafe { chunk.reader(1) };
    let pass_reader = unsafe { chunk.reader(2) };

    let mut sw = unsafe { StructWriter::new(output, 2) };

    for row in 0..row_count {
        let url = unsafe { url_reader.read_str(row) };
        let dn = unsafe { dn_reader.read_str(row) };
        let pass = unsafe { pass_reader.read_str(row) };
        let result = ldap::bind(url, dn, pass);

        unsafe { sw.write_bool(row, 0, result.success) };
        unsafe { sw.write_varchar(row, 1, &result.message) };
    }
});

// ldap_add(url, bind_dn, password, entry_dn, attributes) -> STRUCT(success, message)
quack_rs::scalar_callback!(cb_ldap_add, |_info, input, output| {
    let chunk = unsafe { DataChunk::from_raw(input) };
    let row_count = chunk.size();
    let url_reader = unsafe { chunk.reader(0) };
    let dn_reader = unsafe { chunk.reader(1) };
    let pass_reader = unsafe { chunk.reader(2) };
    let entry_dn_reader = unsafe { chunk.reader(3) };
    let attrs_reader = unsafe { chunk.reader(4) };

    let mut sw = unsafe { StructWriter::new(output, 2) };

    for row in 0..row_count {
        let url = unsafe { url_reader.read_str(row) };
        let dn = unsafe { dn_reader.read_str(row) };
        let pass = unsafe { pass_reader.read_str(row) };
        let entry_dn = unsafe { entry_dn_reader.read_str(row) };
        let attrs = unsafe { attrs_reader.read_str(row) };
        let result = ldap_write::add(url, dn, pass, entry_dn, attrs);

        unsafe { sw.write_bool(row, 0, result.success) };
        unsafe { sw.write_varchar(row, 1, &result.message) };
    }
});

// ldap_modify(url, bind_dn, password, entry_dn, modifications) -> STRUCT(success, message)
quack_rs::scalar_callback!(cb_ldap_modify, |_info, input, output| {
    let chunk = unsafe { DataChunk::from_raw(input) };
    let row_count = chunk.size();
    let url_reader = unsafe { chunk.reader(0) };
    let dn_reader = unsafe { chunk.reader(1) };
    let pass_reader = unsafe { chunk.reader(2) };
    let entry_dn_reader = unsafe { chunk.reader(3) };
    let mods_reader = unsafe { chunk.reader(4) };

    let mut sw = unsafe { StructWriter::new(output, 2) };

    for row in 0..row_count {
        let url = unsafe { url_reader.read_str(row) };
        let dn = unsafe { dn_reader.read_str(row) };
        let pass = unsafe { pass_reader.read_str(row) };
        let entry_dn = unsafe { entry_dn_reader.read_str(row) };
        let mods = unsafe { mods_reader.read_str(row) };
        let result = ldap_write::modify(url, dn, pass, entry_dn, mods);

        unsafe { sw.write_bool(row, 0, result.success) };
        unsafe { sw.write_varchar(row, 1, &result.message) };
    }
});

// ldap_delete(url, bind_dn, password, entry_dn) -> STRUCT(success, message)
quack_rs::scalar_callback!(cb_ldap_delete, |_info, input, output| {
    let chunk = unsafe { DataChunk::from_raw(input) };
    let row_count = chunk.size();
    let url_reader = unsafe { chunk.reader(0) };
    let dn_reader = unsafe { chunk.reader(1) };
    let pass_reader = unsafe { chunk.reader(2) };
    let entry_dn_reader = unsafe { chunk.reader(3) };

    let mut sw = unsafe { StructWriter::new(output, 2) };

    for row in 0..row_count {
        let url = unsafe { url_reader.read_str(row) };
        let dn = unsafe { dn_reader.read_str(row) };
        let pass = unsafe { pass_reader.read_str(row) };
        let entry_dn = unsafe { entry_dn_reader.read_str(row) };
        let result = ldap_write::delete(url, dn, pass, entry_dn);

        unsafe { sw.write_bool(row, 0, result.success) };
        unsafe { sw.write_varchar(row, 1, &result.message) };
    }
});

pub unsafe fn register_all(con: duckdb_connection) -> Result<(), ExtensionError> {
    let v = TypeId::Varchar;

    // ldap_search(url, base_dn, filter, attributes) -> table(dn, attribute, value)
    TableFunctionBuilder::new("ldap_search")
        .param(v)
        .param(v)
        .param(v)
        .param(v)
        .bind(ldap_search_bind)
        .init(ldap_search_init)
        .scan(ldap_search_scan)
        .register(con)?;

    // ldap_bind(url, bind_dn, password) -> STRUCT(success, message)
    ScalarFunctionBuilder::new("ldap_bind")
        .param(v)
        .param(v)
        .param(v)
        .returns_logical(ldap_bind_result_type())
        .function(cb_ldap_bind)
        .null_handling(NullHandling::SpecialNullHandling)
        .register(con)?;

    // ldap_add(url, bind_dn, password, entry_dn, attributes) -> STRUCT(success, message)
    ScalarFunctionBuilder::new("ldap_add")
        .param(v)
        .param(v)
        .param(v)
        .param(v)
        .param(v)
        .returns_logical(ldap_bind_result_type())
        .function(cb_ldap_add)
        .null_handling(NullHandling::SpecialNullHandling)
        .register(con)?;

    // ldap_modify(url, bind_dn, password, entry_dn, modifications) -> STRUCT(success, message)
    ScalarFunctionBuilder::new("ldap_modify")
        .param(v)
        .param(v)
        .param(v)
        .param(v)
        .param(v)
        .returns_logical(ldap_bind_result_type())
        .function(cb_ldap_modify)
        .null_handling(NullHandling::SpecialNullHandling)
        .register(con)?;

    // ldap_delete(url, bind_dn, password, entry_dn) -> STRUCT(success, message)
    ScalarFunctionBuilder::new("ldap_delete")
        .param(v)
        .param(v)
        .param(v)
        .param(v)
        .returns_logical(ldap_bind_result_type())
        .function(cb_ldap_delete)
        .null_handling(NullHandling::SpecialNullHandling)
        .register(con)?;

    Ok(())
}
