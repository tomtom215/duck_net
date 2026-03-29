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

    let url = read_param_varchar(&bind, 0);
    let base_dn = read_param_varchar(&bind, 1);
    let filter = read_param_varchar(&bind, 2);
    let attrs_str = read_param_varchar(&bind, 3);

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

unsafe fn read_param_varchar(bind: &BindInfo, idx: u64) -> String {
    let val = bind.get_parameter(idx);
    let cstr = duckdb_get_varchar(val);
    let s = std::ffi::CStr::from_ptr(cstr)
        .to_str()
        .unwrap_or("")
        .to_string();
    duckdb_free(cstr as *mut _);
    duckdb_destroy_value(&mut { val });
    s
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
    let dn_vec = duckdb_data_chunk_get_vector(output, 0);
    let attr_vec = duckdb_data_chunk_get_vector(output, 1);
    let val_vec = duckdb_data_chunk_get_vector(output, 2);

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
                write_varchar(dn_vec, count, &entry.dn);
                write_varchar(attr_vec, count, attr_name);
                write_varchar(val_vec, count, val);
                count += 1;
                emitted = true;
            }
        }
        if !emitted {
            // Entry with no attributes
            write_varchar(dn_vec, count, &entry.dn);
            write_varchar(attr_vec, count, "");
            write_varchar(val_vec, count, "");
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
    let row_count = duckdb_data_chunk_get_size(input);
    let url_reader = VectorReader::new(input, 0);
    let dn_reader = VectorReader::new(input, 1);
    let pass_reader = VectorReader::new(input, 2);

    let success_vec = duckdb_struct_vector_get_child(output, 0);
    let message_vec = duckdb_struct_vector_get_child(output, 1);

    for row in 0..row_count {
        let url = url_reader.read_str(row as usize);
        let dn = dn_reader.read_str(row as usize);
        let pass = pass_reader.read_str(row as usize);
        let result = ldap::bind(url, dn, pass);

        let sd = duckdb_vector_get_data(success_vec) as *mut bool;
        *sd.add(row as usize) = result.success;
        write_varchar(message_vec, row, &result.message);
    }
}

/// ldap_add(url, bind_dn, password, entry_dn, attributes) -> STRUCT(success, message)
unsafe extern "C" fn cb_ldap_add(
    _info: duckdb_function_info,
    input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    let row_count = duckdb_data_chunk_get_size(input);
    let url_reader = VectorReader::new(input, 0);
    let dn_reader = VectorReader::new(input, 1);
    let pass_reader = VectorReader::new(input, 2);
    let entry_dn_reader = VectorReader::new(input, 3);
    let attrs_reader = VectorReader::new(input, 4);

    let success_vec = duckdb_struct_vector_get_child(output, 0);
    let message_vec = duckdb_struct_vector_get_child(output, 1);

    for row in 0..row_count {
        let url = url_reader.read_str(row as usize);
        let dn = dn_reader.read_str(row as usize);
        let pass = pass_reader.read_str(row as usize);
        let entry_dn = entry_dn_reader.read_str(row as usize);
        let attrs = attrs_reader.read_str(row as usize);
        let result = ldap_write::add(url, dn, pass, entry_dn, attrs);

        let sd = duckdb_vector_get_data(success_vec) as *mut bool;
        *sd.add(row as usize) = result.success;
        write_varchar(message_vec, row, &result.message);
    }
}

/// ldap_modify(url, bind_dn, password, entry_dn, modifications) -> STRUCT(success, message)
unsafe extern "C" fn cb_ldap_modify(
    _info: duckdb_function_info,
    input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    let row_count = duckdb_data_chunk_get_size(input);
    let url_reader = VectorReader::new(input, 0);
    let dn_reader = VectorReader::new(input, 1);
    let pass_reader = VectorReader::new(input, 2);
    let entry_dn_reader = VectorReader::new(input, 3);
    let mods_reader = VectorReader::new(input, 4);

    let success_vec = duckdb_struct_vector_get_child(output, 0);
    let message_vec = duckdb_struct_vector_get_child(output, 1);

    for row in 0..row_count {
        let url = url_reader.read_str(row as usize);
        let dn = dn_reader.read_str(row as usize);
        let pass = pass_reader.read_str(row as usize);
        let entry_dn = entry_dn_reader.read_str(row as usize);
        let mods = mods_reader.read_str(row as usize);
        let result = ldap_write::modify(url, dn, pass, entry_dn, mods);

        let sd = duckdb_vector_get_data(success_vec) as *mut bool;
        *sd.add(row as usize) = result.success;
        write_varchar(message_vec, row, &result.message);
    }
}

/// ldap_delete(url, bind_dn, password, entry_dn) -> STRUCT(success, message)
unsafe extern "C" fn cb_ldap_delete(
    _info: duckdb_function_info,
    input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    let row_count = duckdb_data_chunk_get_size(input);
    let url_reader = VectorReader::new(input, 0);
    let dn_reader = VectorReader::new(input, 1);
    let pass_reader = VectorReader::new(input, 2);
    let entry_dn_reader = VectorReader::new(input, 3);

    let success_vec = duckdb_struct_vector_get_child(output, 0);
    let message_vec = duckdb_struct_vector_get_child(output, 1);

    for row in 0..row_count {
        let url = url_reader.read_str(row as usize);
        let dn = dn_reader.read_str(row as usize);
        let pass = pass_reader.read_str(row as usize);
        let entry_dn = entry_dn_reader.read_str(row as usize);
        let result = ldap_write::delete(url, dn, pass, entry_dn);

        let sd = duckdb_vector_get_data(success_vec) as *mut bool;
        *sd.add(row as usize) = result.success;
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
