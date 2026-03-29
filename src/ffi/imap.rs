// SPDX-License-Identifier: MIT
// Copyright 2026 Tom F. <tomf@tomtomtech.net> (https://github.com/tomtom215)

use std::ffi::CStr;

use libduckdb_sys::*;
use quack_rs::prelude::*;

use crate::imap;

use super::scalars::write_varchar;

// ===== imap_list table function =====

struct ImapListBindData {
    url: String,
    username: String,
    password: String,
    mailbox: String,
    search: String,
    limit: i64,
}

struct ImapListInitData {
    messages: Vec<imap::ImapMessage>,
    idx: usize,
    fetched: bool,
}

unsafe extern "C" fn imap_list_bind(info: duckdb_bind_info) {
    let bind = BindInfo::new(info);

    let url = read_bind_varchar(&bind, 0);
    let username = read_bind_varchar(&bind, 1);
    let password = read_bind_varchar(&bind, 2);

    let mailbox_val = bind.get_named_parameter("mailbox");
    let mailbox = if mailbox_val.is_null() {
        "INBOX".to_string()
    } else {
        let cstr = duckdb_get_varchar(mailbox_val);
        let s = CStr::from_ptr(cstr).to_str().unwrap_or("INBOX").to_string();
        duckdb_free(cstr as *mut _);
        duckdb_destroy_value(&mut { mailbox_val });
        s
    };

    let search = read_named_varchar_imap(info, "search").unwrap_or_default();
    let limit = read_named_bigint_imap(info, "limit").unwrap_or(50);

    bind.add_result_column("uid", TypeId::BigInt);
    bind.add_result_column("from_addr", TypeId::Varchar);
    bind.add_result_column("to_addr", TypeId::Varchar);
    bind.add_result_column("subject", TypeId::Varchar);
    bind.add_result_column("date", TypeId::Varchar);
    bind.add_result_column("size", TypeId::BigInt);

    FfiBindData::<ImapListBindData>::set(
        info,
        ImapListBindData {
            url,
            username,
            password,
            mailbox,
            search,
            limit,
        },
    );
}

unsafe fn read_bind_varchar(bind: &BindInfo, idx: u64) -> String {
    let val = bind.get_parameter(idx);
    let cstr = duckdb_get_varchar(val);
    let s = CStr::from_ptr(cstr).to_str().unwrap_or("").to_string();
    duckdb_free(cstr as *mut _);
    duckdb_destroy_value(&mut { val });
    s
}

unsafe fn read_named_varchar_imap(info: duckdb_bind_info, name: &str) -> Option<String> {
    let bind = BindInfo::new(info);
    let val = bind.get_named_parameter(name);
    if val.is_null() {
        return None;
    }
    let cstr = duckdb_get_varchar(val);
    if cstr.is_null() {
        duckdb_destroy_value(&mut { val });
        return None;
    }
    let s = CStr::from_ptr(cstr).to_str().ok().map(|s| s.to_string());
    duckdb_free(cstr as *mut _);
    duckdb_destroy_value(&mut { val });
    s
}

unsafe fn read_named_bigint_imap(info: duckdb_bind_info, name: &str) -> Option<i64> {
    let bind = BindInfo::new(info);
    let val = bind.get_named_parameter(name);
    if val.is_null() {
        return None;
    }
    let n = duckdb_get_int64(val);
    duckdb_destroy_value(&mut { val });
    Some(n)
}

unsafe extern "C" fn imap_list_init(info: duckdb_init_info) {
    FfiInitData::<ImapListInitData>::set(
        info,
        ImapListInitData {
            messages: vec![],
            idx: 0,
            fetched: false,
        },
    );
}

unsafe extern "C" fn imap_list_scan(info: duckdb_function_info, output: duckdb_data_chunk) {
    let bind_data = match FfiBindData::<ImapListBindData>::get_from_function(info) {
        Some(d) => d,
        None => {
            duckdb_data_chunk_set_size(output, 0);
            return;
        }
    };
    let init_data = match FfiInitData::<ImapListInitData>::get_mut(info) {
        Some(d) => d,
        None => {
            duckdb_data_chunk_set_size(output, 0);
            return;
        }
    };

    if !init_data.fetched {
        init_data.fetched = true;
        let result = imap::list_messages(
            &bind_data.url,
            &bind_data.username,
            &bind_data.password,
            &bind_data.mailbox,
            &bind_data.search,
            bind_data.limit,
        );
        if !result.success {
            let fi = FunctionInfo::new(info);
            fi.set_error(&result.message);
            duckdb_data_chunk_set_size(output, 0);
            return;
        }
        init_data.messages = result.messages;
    }

    let uid_vec = duckdb_data_chunk_get_vector(output, 0);
    let from_vec = duckdb_data_chunk_get_vector(output, 1);
    let to_vec = duckdb_data_chunk_get_vector(output, 2);
    let subject_vec = duckdb_data_chunk_get_vector(output, 3);
    let date_vec = duckdb_data_chunk_get_vector(output, 4);
    let size_vec = duckdb_data_chunk_get_vector(output, 5);

    let mut count: idx_t = 0;
    let max_chunk = 2048;

    while init_data.idx < init_data.messages.len() && count < max_chunk {
        let msg = &init_data.messages[init_data.idx];
        let uid_data = duckdb_vector_get_data(uid_vec) as *mut i64;
        *uid_data.add(count as usize) = msg.uid;
        write_varchar(from_vec, count, &msg.from);
        write_varchar(to_vec, count, &msg.to);
        write_varchar(subject_vec, count, &msg.subject);
        write_varchar(date_vec, count, &msg.date);
        let size_data = duckdb_vector_get_data(size_vec) as *mut i64;
        *size_data.add(count as usize) = msg.size;
        init_data.idx += 1;
        count += 1;
    }

    duckdb_data_chunk_set_size(output, count);
}

// ===== imap_fetch scalar =====

fn imap_fetch_result_type() -> LogicalType {
    LogicalType::struct_type_from_logical(&[
        ("success", LogicalType::new(TypeId::Boolean)),
        ("body", LogicalType::new(TypeId::Varchar)),
        ("message", LogicalType::new(TypeId::Varchar)),
    ])
}

unsafe extern "C" fn cb_imap_fetch(
    _info: duckdb_function_info,
    input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    let row_count = duckdb_data_chunk_get_size(input);
    let url_reader = VectorReader::new(input, 0);
    let user_reader = VectorReader::new(input, 1);
    let pass_reader = VectorReader::new(input, 2);
    let uid_data = duckdb_vector_get_data(duckdb_data_chunk_get_vector(input, 3)) as *const i64;

    let success_vec = duckdb_struct_vector_get_child(output, 0);
    let body_vec = duckdb_struct_vector_get_child(output, 1);
    let message_vec = duckdb_struct_vector_get_child(output, 2);

    for row in 0..row_count {
        let url = url_reader.read_str(row as usize);
        let user = user_reader.read_str(row as usize);
        let pass = pass_reader.read_str(row as usize);
        let uid = *uid_data.add(row as usize);

        let result = imap::fetch_message(url, user, pass, "INBOX", uid);
        let sd = duckdb_vector_get_data(success_vec) as *mut bool;
        *sd.add(row as usize) = result.success;
        write_varchar(body_vec, row, &result.body);
        write_varchar(message_vec, row, &result.message);
    }
}

fn imap_write_result_type() -> LogicalType {
    LogicalType::struct_type_from_logical(&[
        ("success", LogicalType::new(TypeId::Boolean)),
        ("message", LogicalType::new(TypeId::Varchar)),
    ])
}

/// imap_move(url, username, password, mailbox, uid, dest_mailbox) -> STRUCT(success, message)
unsafe extern "C" fn cb_imap_move(
    _info: duckdb_function_info,
    input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    let row_count = duckdb_data_chunk_get_size(input);
    let url_reader = VectorReader::new(input, 0);
    let user_reader = VectorReader::new(input, 1);
    let pass_reader = VectorReader::new(input, 2);
    let mailbox_reader = VectorReader::new(input, 3);
    let uid_data = duckdb_vector_get_data(duckdb_data_chunk_get_vector(input, 4)) as *const i64;
    let dest_reader = VectorReader::new(input, 5);

    let success_vec = duckdb_struct_vector_get_child(output, 0);
    let message_vec = duckdb_struct_vector_get_child(output, 1);

    for row in 0..row_count {
        let url = url_reader.read_str(row as usize);
        let user = user_reader.read_str(row as usize);
        let pass = pass_reader.read_str(row as usize);
        let mailbox = mailbox_reader.read_str(row as usize);
        let uid = *uid_data.add(row as usize);
        let dest = dest_reader.read_str(row as usize);

        let result = imap::move_message(url, user, pass, mailbox, uid, dest);

        let sd = duckdb_vector_get_data(success_vec) as *mut bool;
        *sd.add(row as usize) = result.success;
        write_varchar(message_vec, row, &result.message);
    }
}

/// imap_delete(url, username, password, mailbox, uid) -> STRUCT(success, message)
unsafe extern "C" fn cb_imap_delete(
    _info: duckdb_function_info,
    input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    let row_count = duckdb_data_chunk_get_size(input);
    let url_reader = VectorReader::new(input, 0);
    let user_reader = VectorReader::new(input, 1);
    let pass_reader = VectorReader::new(input, 2);
    let mailbox_reader = VectorReader::new(input, 3);
    let uid_data = duckdb_vector_get_data(duckdb_data_chunk_get_vector(input, 4)) as *const i64;

    let success_vec = duckdb_struct_vector_get_child(output, 0);
    let message_vec = duckdb_struct_vector_get_child(output, 1);

    for row in 0..row_count {
        let url = url_reader.read_str(row as usize);
        let user = user_reader.read_str(row as usize);
        let pass = pass_reader.read_str(row as usize);
        let mailbox = mailbox_reader.read_str(row as usize);
        let uid = *uid_data.add(row as usize);

        let result = imap::delete_message(url, user, pass, mailbox, uid);

        let sd = duckdb_vector_get_data(success_vec) as *mut bool;
        *sd.add(row as usize) = result.success;
        write_varchar(message_vec, row, &result.message);
    }
}

/// imap_flag(url, username, password, mailbox, uid, flags) -> STRUCT(success, message)
unsafe extern "C" fn cb_imap_flag(
    _info: duckdb_function_info,
    input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    let row_count = duckdb_data_chunk_get_size(input);
    let url_reader = VectorReader::new(input, 0);
    let user_reader = VectorReader::new(input, 1);
    let pass_reader = VectorReader::new(input, 2);
    let mailbox_reader = VectorReader::new(input, 3);
    let uid_data = duckdb_vector_get_data(duckdb_data_chunk_get_vector(input, 4)) as *const i64;
    let flags_reader = VectorReader::new(input, 5);

    let success_vec = duckdb_struct_vector_get_child(output, 0);
    let message_vec = duckdb_struct_vector_get_child(output, 1);

    for row in 0..row_count {
        let url = url_reader.read_str(row as usize);
        let user = user_reader.read_str(row as usize);
        let pass = pass_reader.read_str(row as usize);
        let mailbox = mailbox_reader.read_str(row as usize);
        let uid = *uid_data.add(row as usize);
        let flags = flags_reader.read_str(row as usize);

        let result = imap::flag_message(url, user, pass, mailbox, uid, flags);

        let sd = duckdb_vector_get_data(success_vec) as *mut bool;
        *sd.add(row as usize) = result.success;
        write_varchar(message_vec, row, &result.message);
    }
}

pub unsafe fn register_all(con: duckdb_connection) -> Result<(), ExtensionError> {
    let v = TypeId::Varchar;

    // imap_list(url, username, password) table function
    TableFunctionBuilder::new("imap_list")
        .param(v)
        .param(v)
        .param(v)
        .named_param("mailbox", v)
        .named_param("search", v)
        .named_param("limit", TypeId::BigInt)
        .bind(imap_list_bind)
        .init(imap_list_init)
        .scan(imap_list_scan)
        .register(con)?;

    // imap_fetch(url, username, password, uid) -> STRUCT(success, body, message)
    ScalarFunctionBuilder::new("imap_fetch")
        .param(v)
        .param(v)
        .param(v)
        .param(TypeId::BigInt)
        .returns_logical(imap_fetch_result_type())
        .function(cb_imap_fetch)
        .null_handling(NullHandling::SpecialNullHandling)
        .register(con)?;

    // imap_move(url, username, password, mailbox, uid, dest_mailbox) -> STRUCT(success, message)
    ScalarFunctionBuilder::new("imap_move")
        .param(v)
        .param(v)
        .param(v)
        .param(v)
        .param(TypeId::BigInt)
        .param(v)
        .returns_logical(imap_write_result_type())
        .function(cb_imap_move)
        .null_handling(NullHandling::SpecialNullHandling)
        .register(con)?;

    // imap_delete(url, username, password, mailbox, uid) -> STRUCT(success, message)
    ScalarFunctionBuilder::new("imap_delete")
        .param(v)
        .param(v)
        .param(v)
        .param(v)
        .param(TypeId::BigInt)
        .returns_logical(imap_write_result_type())
        .function(cb_imap_delete)
        .null_handling(NullHandling::SpecialNullHandling)
        .register(con)?;

    // imap_flag(url, username, password, mailbox, uid, flags) -> STRUCT(success, message)
    ScalarFunctionBuilder::new("imap_flag")
        .param(v)
        .param(v)
        .param(v)
        .param(v)
        .param(TypeId::BigInt)
        .param(v)
        .returns_logical(imap_write_result_type())
        .function(cb_imap_flag)
        .null_handling(NullHandling::SpecialNullHandling)
        .register(con)?;

    Ok(())
}
