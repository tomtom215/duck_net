// SPDX-License-Identifier: MIT
// Copyright 2026 Tom F. <tomf@tomtomtech.net> (https://github.com/tomtom215)

use libduckdb_sys::*;
use quack_rs::prelude::*;

use crate::ldap;
use crate::ldap_write;

use super::scalars::write_varchar;

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

unsafe extern "C" fn ldap_search_scan(info: duckdb_function_info, output: duckdb_data_chunk) {
    let bind_data = match FfiBindData::<LdapSearchBindData>::get_from_function(info) {
        Some(d) => d,
        None => {
            duckdb_data_chunk_set_size(output, 0);
            return;
        }
    };
    let init_data = match FfiInitData::<LdapSearchInitData>::get_mut(info) {
        Some(d) => d,
        None => {
            duckdb_data_chunk_set_size(output, 0);
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
            duckdb_data_chunk_set_size(output, 0);
            return;
        }
        init_data.entries = result.entries;
    }

    // Flatten entries into rows
    let out_chunk = DataChunk::from_raw(output);
    let mut dn_w = out_chunk.writer(0);
    let mut attr_w = out_chunk.writer(1);
    let mut val_w = out_chunk.writer(2);

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
                dn_w.write_varchar(count as usize, &entry.dn);
                attr_w.write_varchar(count as usize, attr_name);
                val_w.write_varchar(count as usize, val);
                count += 1;
                emitted = true;
            }
        }
        if !emitted {
            // Entry with no attributes
            dn_w.write_varchar(count as usize, &entry.dn);
            attr_w.write_varchar(count as usize, "");
            val_w.write_varchar(count as usize, "");
            count += 1;
        }
        init_data.idx += 1;
    }

    duckdb_data_chunk_set_size(output, count);
}

// ===== ldap_bind scalar =====

fn ldap_bind_result_type() -> LogicalType {
    LogicalType::struct_type_from_logical(&[
        ("success", LogicalType::new(TypeId::Boolean)),
        ("message", LogicalType::new(TypeId::Varchar)),
    ])
}

unsafe extern "C" fn cb_ldap_bind(
    _info: duckdb_function_info,
    input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    let chunk = DataChunk::from_raw(input);
    let row_count = chunk.size();
    let url_reader = chunk.reader(0);
    let dn_reader = chunk.reader(1);
    let pass_reader = chunk.reader(2);

    for row in 0..row_count {
        let url = url_reader.read_str(row as usize);
        let dn = dn_reader.read_str(row as usize);
        let pass = pass_reader.read_str(row as usize);
        let result = ldap::bind(url, dn, pass);

        let mut success_w = StructVector::field_writer(output, 0);
        let message_vec = duckdb_struct_vector_get_child(output, 1);
        success_w.write_bool(row as usize, result.success);
        write_varchar(message_vec, row, &result.message);
    }
}

/// ldap_add(url, bind_dn, password, entry_dn, attributes) -> STRUCT(success, message)
unsafe extern "C" fn cb_ldap_add(
    _info: duckdb_function_info,
    input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    let chunk = DataChunk::from_raw(input);
    let row_count = chunk.size();
    let url_reader = chunk.reader(0);
    let dn_reader = chunk.reader(1);
    let pass_reader = chunk.reader(2);
    let entry_dn_reader = chunk.reader(3);
    let attrs_reader = chunk.reader(4);

    for row in 0..row_count {
        let url = url_reader.read_str(row as usize);
        let dn = dn_reader.read_str(row as usize);
        let pass = pass_reader.read_str(row as usize);
        let entry_dn = entry_dn_reader.read_str(row as usize);
        let attrs = attrs_reader.read_str(row as usize);
        let result = ldap_write::add(url, dn, pass, entry_dn, attrs);

        let mut success_w = StructVector::field_writer(output, 0);
        let message_vec = duckdb_struct_vector_get_child(output, 1);
        success_w.write_bool(row as usize, result.success);
        write_varchar(message_vec, row, &result.message);
    }
}

/// ldap_modify(url, bind_dn, password, entry_dn, modifications) -> STRUCT(success, message)
unsafe extern "C" fn cb_ldap_modify(
    _info: duckdb_function_info,
    input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    let chunk = DataChunk::from_raw(input);
    let row_count = chunk.size();
    let url_reader = chunk.reader(0);
    let dn_reader = chunk.reader(1);
    let pass_reader = chunk.reader(2);
    let entry_dn_reader = chunk.reader(3);
    let mods_reader = chunk.reader(4);

    for row in 0..row_count {
        let url = url_reader.read_str(row as usize);
        let dn = dn_reader.read_str(row as usize);
        let pass = pass_reader.read_str(row as usize);
        let entry_dn = entry_dn_reader.read_str(row as usize);
        let mods = mods_reader.read_str(row as usize);
        let result = ldap_write::modify(url, dn, pass, entry_dn, mods);

        let mut success_w = StructVector::field_writer(output, 0);
        let message_vec = duckdb_struct_vector_get_child(output, 1);
        success_w.write_bool(row as usize, result.success);
        write_varchar(message_vec, row, &result.message);
    }
}

/// ldap_delete(url, bind_dn, password, entry_dn) -> STRUCT(success, message)
unsafe extern "C" fn cb_ldap_delete(
    _info: duckdb_function_info,
    input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    let chunk = DataChunk::from_raw(input);
    let row_count = chunk.size();
    let url_reader = chunk.reader(0);
    let dn_reader = chunk.reader(1);
    let pass_reader = chunk.reader(2);
    let entry_dn_reader = chunk.reader(3);

    for row in 0..row_count {
        let url = url_reader.read_str(row as usize);
        let dn = dn_reader.read_str(row as usize);
        let pass = pass_reader.read_str(row as usize);
        let entry_dn = entry_dn_reader.read_str(row as usize);
        let result = ldap_write::delete(url, dn, pass, entry_dn);

        let mut success_w = StructVector::field_writer(output, 0);
        let message_vec = duckdb_struct_vector_get_child(output, 1);
        success_w.write_bool(row as usize, result.success);
        write_varchar(message_vec, row, &result.message);
    }
}

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
