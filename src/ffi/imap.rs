// SPDX-License-Identifier: MIT
// Copyright 2026 Tom F. <tomf@tomtomtech.net> (https://github.com/tomtom215)

use libduckdb_sys::*;
use quack_rs::prelude::*;

use crate::imap;
use crate::imap_write;


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

    let url = bind.get_parameter_value(0).as_str().unwrap_or_default();
    let username = bind.get_parameter_value(1).as_str().unwrap_or_default();
    let password = bind.get_parameter_value(2).as_str().unwrap_or_default();

    let mailbox_val = bind.get_named_parameter_value("mailbox");
    let mailbox = if mailbox_val.is_null() {
        "INBOX".to_string()
    } else {
        mailbox_val.as_str().unwrap_or("INBOX".to_string())
    };

    let search_val = bind.get_named_parameter_value("search");
    let search = if search_val.is_null() {
        String::new()
    } else {
        search_val.as_str().unwrap_or_default()
    };

    let limit_val = bind.get_named_parameter_value("limit");
    let limit = if limit_val.is_null() {
        50
    } else {
        limit_val.as_i64()
    };

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

// imap_list_scan table scan callback
quack_rs::table_scan_callback!(imap_list_scan, |info, output| {
    let bind_data = match unsafe { FfiBindData::<ImapListBindData>::get_from_function(info) } {
        Some(d) => d,
        None => {
            unsafe { duckdb_data_chunk_set_size(output, 0) };
            return;
        }
    };
    let init_data = match unsafe { FfiInitData::<ImapListInitData>::get_mut(info) } {
        Some(d) => d,
        None => {
            unsafe { duckdb_data_chunk_set_size(output, 0) };
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
            let fi = unsafe { FunctionInfo::new(info) };
            fi.set_error(&result.message);
            unsafe { duckdb_data_chunk_set_size(output, 0) };
            return;
        }
        init_data.messages = result.messages;
    }

    let out_chunk = unsafe { DataChunk::from_raw(output) };
    let mut uid_w = unsafe { out_chunk.writer(0) };
    let mut from_w = unsafe { out_chunk.writer(1) };
    let mut to_w = unsafe { out_chunk.writer(2) };
    let mut subject_w = unsafe { out_chunk.writer(3) };
    let mut date_w = unsafe { out_chunk.writer(4) };
    let mut size_w = unsafe { out_chunk.writer(5) };

    let mut count: idx_t = 0;
    let max_chunk = 2048;

    while init_data.idx < init_data.messages.len() && count < max_chunk {
        let msg = &init_data.messages[init_data.idx];
        unsafe { uid_w.write_i64(count as usize, msg.uid) };
        unsafe { from_w.write_varchar(count as usize, &msg.from) };
        unsafe { to_w.write_varchar(count as usize, &msg.to) };
        unsafe { subject_w.write_varchar(count as usize, &msg.subject) };
        unsafe { date_w.write_varchar(count as usize, &msg.date) };
        unsafe { size_w.write_i64(count as usize, msg.size) };
        init_data.idx += 1;
        count += 1;
    }

    unsafe { duckdb_data_chunk_set_size(output, count) };
});

// ===== imap_fetch scalar =====

fn imap_fetch_result_type() -> LogicalType {
    LogicalType::struct_type_from_logical(&[
        ("success", LogicalType::new(TypeId::Boolean)),
        ("body", LogicalType::new(TypeId::Varchar)),
        ("message", LogicalType::new(TypeId::Varchar)),
    ])
}

// imap_fetch(url, username, password, uid) -> STRUCT(success, body, message)
quack_rs::scalar_callback!(cb_imap_fetch, |_info, input, output| {
    let chunk = unsafe { DataChunk::from_raw(input) };
    let row_count = chunk.size();
    let url_reader = unsafe { chunk.reader(0) };
    let user_reader = unsafe { chunk.reader(1) };
    let pass_reader = unsafe { chunk.reader(2) };
    let uid_reader = unsafe { chunk.reader(3) };

    let mut sw = unsafe { StructWriter::new(output, 3) };

    for row in 0..row_count {
        let url = unsafe { url_reader.read_str(row as usize) };
        let user = unsafe { user_reader.read_str(row as usize) };
        let pass = unsafe { pass_reader.read_str(row as usize) };
        let uid = unsafe { uid_reader.read_i64(row as usize) };

        let result = imap::fetch_message(url, user, pass, "INBOX", uid);
        unsafe { sw.write_bool(row as usize, 0, result.success) };
        unsafe { sw.write_varchar(row as usize, 1, &result.body) };
        unsafe { sw.write_varchar(row as usize, 2, &result.message) };
    }
});

fn imap_write_result_type() -> LogicalType {
    LogicalType::struct_type_from_logical(&[
        ("success", LogicalType::new(TypeId::Boolean)),
        ("message", LogicalType::new(TypeId::Varchar)),
    ])
}

// imap_move(url, username, password, mailbox, uid, dest_mailbox) -> STRUCT(success, message)
quack_rs::scalar_callback!(cb_imap_move, |_info, input, output| {
    let chunk = unsafe { DataChunk::from_raw(input) };
    let row_count = chunk.size();
    let url_reader = unsafe { chunk.reader(0) };
    let user_reader = unsafe { chunk.reader(1) };
    let pass_reader = unsafe { chunk.reader(2) };
    let mailbox_reader = unsafe { chunk.reader(3) };
    let uid_reader = unsafe { chunk.reader(4) };
    let dest_reader = unsafe { chunk.reader(5) };

    let mut sw = unsafe { StructWriter::new(output, 2) };

    for row in 0..row_count {
        let url = unsafe { url_reader.read_str(row as usize) };
        let user = unsafe { user_reader.read_str(row as usize) };
        let pass = unsafe { pass_reader.read_str(row as usize) };
        let mailbox = unsafe { mailbox_reader.read_str(row as usize) };
        let uid = unsafe { uid_reader.read_i64(row as usize) };
        let dest = unsafe { dest_reader.read_str(row as usize) };

        let result = imap_write::move_message(url, user, pass, mailbox, uid, dest);

        unsafe { sw.write_bool(row as usize, 0, result.success) };
        unsafe { sw.write_varchar(row as usize, 1, &result.message) };
    }
});

// imap_delete(url, username, password, mailbox, uid) -> STRUCT(success, message)
quack_rs::scalar_callback!(cb_imap_delete, |_info, input, output| {
    let chunk = unsafe { DataChunk::from_raw(input) };
    let row_count = chunk.size();
    let url_reader = unsafe { chunk.reader(0) };
    let user_reader = unsafe { chunk.reader(1) };
    let pass_reader = unsafe { chunk.reader(2) };
    let mailbox_reader = unsafe { chunk.reader(3) };
    let uid_reader = unsafe { chunk.reader(4) };

    let mut sw = unsafe { StructWriter::new(output, 2) };

    for row in 0..row_count {
        let url = unsafe { url_reader.read_str(row as usize) };
        let user = unsafe { user_reader.read_str(row as usize) };
        let pass = unsafe { pass_reader.read_str(row as usize) };
        let mailbox = unsafe { mailbox_reader.read_str(row as usize) };
        let uid = unsafe { uid_reader.read_i64(row as usize) };

        let result = imap_write::delete_message(url, user, pass, mailbox, uid);

        unsafe { sw.write_bool(row as usize, 0, result.success) };
        unsafe { sw.write_varchar(row as usize, 1, &result.message) };
    }
});

// imap_flag(url, username, password, mailbox, uid, flags) -> STRUCT(success, message)
quack_rs::scalar_callback!(cb_imap_flag, |_info, input, output| {
    let chunk = unsafe { DataChunk::from_raw(input) };
    let row_count = chunk.size();
    let url_reader = unsafe { chunk.reader(0) };
    let user_reader = unsafe { chunk.reader(1) };
    let pass_reader = unsafe { chunk.reader(2) };
    let mailbox_reader = unsafe { chunk.reader(3) };
    let uid_reader = unsafe { chunk.reader(4) };
    let flags_reader = unsafe { chunk.reader(5) };

    let mut sw = unsafe { StructWriter::new(output, 2) };

    for row in 0..row_count {
        let url = unsafe { url_reader.read_str(row as usize) };
        let user = unsafe { user_reader.read_str(row as usize) };
        let pass = unsafe { pass_reader.read_str(row as usize) };
        let mailbox = unsafe { mailbox_reader.read_str(row as usize) };
        let uid = unsafe { uid_reader.read_i64(row as usize) };
        let flags = unsafe { flags_reader.read_str(row as usize) };

        let result = imap_write::flag_message(url, user, pass, mailbox, uid, flags);

        unsafe { sw.write_bool(row as usize, 0, result.success) };
        unsafe { sw.write_varchar(row as usize, 1, &result.message) };
    }
});

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
