// SPDX-License-Identifier: MIT
// Copyright 2026 Tom F. <tomf@tomtomtech.net> (https://github.com/tomtom215)

use libduckdb_sys::*;
use quack_rs::prelude::*;

use crate::caldav;

// ===== caldav_events table function =====

struct CalDavEventsBindData {
    url: String,
    headers: Vec<(String, String)>,
    time_start: Option<String>,
    time_end: Option<String>,
}

struct CalDavEventsInitData {
    events: Vec<caldav::CalDavEvent>,
    idx: usize,
    fetched: bool,
}

unsafe extern "C" fn caldav_events_bind(info: duckdb_bind_info) {
    let bind = BindInfo::new(info);
    let url = bind.get_parameter_value(0).as_str().unwrap_or_default();

    let time_start_val = bind.get_named_parameter_value("time_start");
    let time_start = if time_start_val.is_null() { None } else { time_start_val.as_str().ok() };

    let time_end_val = bind.get_named_parameter_value("time_end");
    let time_end = if time_end_val.is_null() { None } else { time_end_val.as_str().ok() };

    bind.add_result_column("href", TypeId::Varchar);
    bind.add_result_column("etag", TypeId::Varchar);
    bind.add_result_column("data", TypeId::Varchar);

    FfiBindData::<CalDavEventsBindData>::set(
        info,
        CalDavEventsBindData {
            url,
            headers: vec![],
            time_start,
            time_end,
        },
    );
}

unsafe extern "C" fn caldav_events_init(info: duckdb_init_info) {
    FfiInitData::<CalDavEventsInitData>::set(
        info,
        CalDavEventsInitData {
            events: vec![],
            idx: 0,
            fetched: false,
        },
    );
}

// caldav_events_scan table scan callback
quack_rs::table_scan_callback!(caldav_events_scan, |info, output| {
    let bind_data = match unsafe { FfiBindData::<CalDavEventsBindData>::get_from_function(info) } {
        Some(d) => d,
        None => {
            unsafe { duckdb_data_chunk_set_size(output, 0) };
            return;
        }
    };
    let init_data = match unsafe { FfiInitData::<CalDavEventsInitData>::get_mut(info) } {
        Some(d) => d,
        None => {
            unsafe { duckdb_data_chunk_set_size(output, 0) };
            return;
        }
    };

    if !init_data.fetched {
        init_data.fetched = true;
        match caldav::list_events(
            &bind_data.url,
            &bind_data.headers,
            bind_data.time_start.as_deref(),
            bind_data.time_end.as_deref(),
        ) {
            Ok(events) => init_data.events = events,
            Err(e) => {
                let fi = unsafe { FunctionInfo::new(info) };
                fi.set_error(&e);
                unsafe { duckdb_data_chunk_set_size(output, 0) };
                return;
            }
        }
    }

    let out_chunk = unsafe { DataChunk::from_raw(output) };
    let mut href_w = unsafe { out_chunk.writer(0) };
    let mut etag_w = unsafe { out_chunk.writer(1) };
    let mut data_w = unsafe { out_chunk.writer(2) };

    let mut count: idx_t = 0;
    let max_chunk = 2048;

    while init_data.idx < init_data.events.len() && count < max_chunk {
        let e = &init_data.events[init_data.idx];
        unsafe { href_w.write_varchar(count as usize, &e.href) };
        unsafe { etag_w.write_varchar(count as usize, &e.etag) };
        unsafe { data_w.write_varchar(count as usize, &e.data) };
        init_data.idx += 1;
        count += 1;
    }

    unsafe { duckdb_data_chunk_set_size(output, count) };
});

// ===== carddav_contacts table function =====

struct CardDavContactsBindData {
    url: String,
    headers: Vec<(String, String)>,
}

struct CardDavContactsInitData {
    contacts: Vec<caldav::CardDavContact>,
    idx: usize,
    fetched: bool,
}

unsafe extern "C" fn carddav_contacts_bind(info: duckdb_bind_info) {
    let bind = BindInfo::new(info);
    let url = bind.get_parameter_value(0).as_str().unwrap_or_default();

    bind.add_result_column("href", TypeId::Varchar);
    bind.add_result_column("etag", TypeId::Varchar);
    bind.add_result_column("data", TypeId::Varchar);

    FfiBindData::<CardDavContactsBindData>::set(
        info,
        CardDavContactsBindData {
            url,
            headers: vec![],
        },
    );
}

unsafe extern "C" fn carddav_contacts_init(info: duckdb_init_info) {
    FfiInitData::<CardDavContactsInitData>::set(
        info,
        CardDavContactsInitData {
            contacts: vec![],
            idx: 0,
            fetched: false,
        },
    );
}

// carddav_contacts_scan table scan callback
quack_rs::table_scan_callback!(carddav_contacts_scan, |info, output| {
    let bind_data = match unsafe { FfiBindData::<CardDavContactsBindData>::get_from_function(info) } {
        Some(d) => d,
        None => {
            unsafe { duckdb_data_chunk_set_size(output, 0) };
            return;
        }
    };
    let init_data = match unsafe { FfiInitData::<CardDavContactsInitData>::get_mut(info) } {
        Some(d) => d,
        None => {
            unsafe { duckdb_data_chunk_set_size(output, 0) };
            return;
        }
    };

    if !init_data.fetched {
        init_data.fetched = true;
        match caldav::list_contacts(&bind_data.url, &bind_data.headers) {
            Ok(contacts) => init_data.contacts = contacts,
            Err(e) => {
                let fi = unsafe { FunctionInfo::new(info) };
                fi.set_error(&e);
                unsafe { duckdb_data_chunk_set_size(output, 0) };
                return;
            }
        }
    }

    let out_chunk = unsafe { DataChunk::from_raw(output) };
    let mut href_w = unsafe { out_chunk.writer(0) };
    let mut etag_w = unsafe { out_chunk.writer(1) };
    let mut data_w = unsafe { out_chunk.writer(2) };

    let mut count: idx_t = 0;
    let max_chunk = 2048;

    while init_data.idx < init_data.contacts.len() && count < max_chunk {
        let c = &init_data.contacts[init_data.idx];
        unsafe { href_w.write_varchar(count as usize, &c.href) };
        unsafe { etag_w.write_varchar(count as usize, &c.etag) };
        unsafe { data_w.write_varchar(count as usize, &c.data) };
        init_data.idx += 1;
        count += 1;
    }

    unsafe { duckdb_data_chunk_set_size(output, count) };
});

pub unsafe fn register_all(con: duckdb_connection) -> Result<(), ExtensionError> {
    let v = TypeId::Varchar;

    TableFunctionBuilder::new("caldav_events")
        .param(v)
        .named_param("time_start", v)
        .named_param("time_end", v)
        .bind(caldav_events_bind)
        .init(caldav_events_init)
        .scan(caldav_events_scan)
        .register(con)?;

    TableFunctionBuilder::new("carddav_contacts")
        .param(v)
        .bind(carddav_contacts_bind)
        .init(carddav_contacts_init)
        .scan(carddav_contacts_scan)
        .register(con)?;

    Ok(())
}
