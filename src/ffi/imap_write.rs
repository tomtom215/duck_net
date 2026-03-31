// SPDX-License-Identifier: MIT
// Copyright 2026 Tom F. <tomf@tomtomtech.net> (https://github.com/tomtom215)

use quack_rs::prelude::*;

use crate::imap_write;

fn write_result_type() -> LogicalType {
    LogicalType::struct_type_from_logical(&[
        ("success", LogicalType::new(TypeId::Boolean)),
        ("message", LogicalType::new(TypeId::Varchar)),
    ])
}

// imap_move(url, username, password, mailbox, uid, dest_mailbox) -> STRUCT
quack_rs::scalar_callback!(cb_imap_move, |_info, input, output| {
    let chunk = unsafe { DataChunk::from_raw(input) };
    let row_count = chunk.size();
    let url_reader = unsafe { chunk.reader(0) };
    let user_reader = unsafe { chunk.reader(1) };
    let pass_reader = unsafe { chunk.reader(2) };
    let mbox_reader = unsafe { chunk.reader(3) };
    let uid_reader = unsafe { chunk.reader(4) };
    let dest_reader = unsafe { chunk.reader(5) };

    let mut sw = unsafe { StructWriter::new(output, 2) };

    for row in 0..row_count {
        let url = unsafe { url_reader.read_str(row) };
        let username = unsafe { user_reader.read_str(row) };
        let password = unsafe { pass_reader.read_str(row) };
        let mailbox = unsafe { mbox_reader.read_str(row) };
        let uid = unsafe { uid_reader.read_i64(row) };
        let dest_mailbox = unsafe { dest_reader.read_str(row) };

        let result =
            imap_write::move_message(url, username, password, mailbox, uid, dest_mailbox);

        unsafe { sw.write_bool(row, 0, result.success) };
        unsafe { sw.write_varchar(row, 1, &result.message) };
    }
});

// imap_delete(url, username, password, mailbox, uid) -> STRUCT
quack_rs::scalar_callback!(cb_imap_delete, |_info, input, output| {
    let chunk = unsafe { DataChunk::from_raw(input) };
    let row_count = chunk.size();
    let url_reader = unsafe { chunk.reader(0) };
    let user_reader = unsafe { chunk.reader(1) };
    let pass_reader = unsafe { chunk.reader(2) };
    let mbox_reader = unsafe { chunk.reader(3) };
    let uid_reader = unsafe { chunk.reader(4) };

    let mut sw = unsafe { StructWriter::new(output, 2) };

    for row in 0..row_count {
        let url = unsafe { url_reader.read_str(row) };
        let username = unsafe { user_reader.read_str(row) };
        let password = unsafe { pass_reader.read_str(row) };
        let mailbox = unsafe { mbox_reader.read_str(row) };
        let uid = unsafe { uid_reader.read_i64(row) };

        let result = imap_write::delete_message(url, username, password, mailbox, uid);

        unsafe { sw.write_bool(row, 0, result.success) };
        unsafe { sw.write_varchar(row, 1, &result.message) };
    }
});

// imap_flag(url, username, password, mailbox, uid, flags) -> STRUCT
quack_rs::scalar_callback!(cb_imap_flag, |_info, input, output| {
    let chunk = unsafe { DataChunk::from_raw(input) };
    let row_count = chunk.size();
    let url_reader = unsafe { chunk.reader(0) };
    let user_reader = unsafe { chunk.reader(1) };
    let pass_reader = unsafe { chunk.reader(2) };
    let mbox_reader = unsafe { chunk.reader(3) };
    let uid_reader = unsafe { chunk.reader(4) };
    let flags_reader = unsafe { chunk.reader(5) };

    let mut sw = unsafe { StructWriter::new(output, 2) };

    for row in 0..row_count {
        let url = unsafe { url_reader.read_str(row) };
        let username = unsafe { user_reader.read_str(row) };
        let password = unsafe { pass_reader.read_str(row) };
        let mailbox = unsafe { mbox_reader.read_str(row) };
        let uid = unsafe { uid_reader.read_i64(row) };
        let flags = unsafe { flags_reader.read_str(row) };

        let result = imap_write::flag_message(url, username, password, mailbox, uid, flags);

        unsafe { sw.write_bool(row, 0, result.success) };
        unsafe { sw.write_varchar(row, 1, &result.message) };
    }
});

pub unsafe fn register_all(con: &Connection) -> Result<(), ExtensionError> {
    let v = TypeId::Varchar;
    let b = TypeId::BigInt;

    // imap_move(url, username, password, mailbox, uid, dest_mailbox)
    ScalarFunctionBuilder::new("imap_move")
        .param(v) // url
        .param(v) // username
        .param(v) // password
        .param(v) // mailbox
        .param(b) // uid
        .param(v) // dest_mailbox
        .returns_logical(write_result_type())
        .function(cb_imap_move)
        .null_handling(NullHandling::SpecialNullHandling)
        .register(con.as_raw_connection())?;

    // imap_delete(url, username, password, mailbox, uid)
    ScalarFunctionBuilder::new("imap_delete")
        .param(v) // url
        .param(v) // username
        .param(v) // password
        .param(v) // mailbox
        .param(b) // uid
        .returns_logical(write_result_type())
        .function(cb_imap_delete)
        .null_handling(NullHandling::SpecialNullHandling)
        .register(con.as_raw_connection())?;

    // imap_flag(url, username, password, mailbox, uid, flags)
    ScalarFunctionBuilder::new("imap_flag")
        .param(v) // url
        .param(v) // username
        .param(v) // password
        .param(v) // mailbox
        .param(b) // uid
        .param(v) // flags
        .returns_logical(write_result_type())
        .function(cb_imap_flag)
        .null_handling(NullHandling::SpecialNullHandling)
        .register(con.as_raw_connection())?;

    Ok(())
}
