// SPDX-License-Identifier: MIT
// Copyright 2026 Tom F. <tomf@tomtomtech.net> (https://github.com/tomtom215)

use std::ffi::CStr;

use libduckdb_sys::*;
use quack_rs::prelude::*;

use crate::caldav;

use super::scalars::write_varchar;

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
    let val = bind.get_parameter(0);
    let cstr = duckdb_get_varchar(val);
    let url = CStr::from_ptr(cstr).to_str().unwrap_or("").to_string();
    duckdb_free(cstr as *mut _);
    duckdb_destroy_value(&mut { val });

    let time_start = read_named_str(info, "time_start");
    let time_end = read_named_str(info, "time_end");

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

unsafe fn read_named_str(info: duckdb_bind_info, name: &str) -> Option<String> {
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

unsafe extern "C" fn caldav_events_scan(info: duckdb_function_info, output: duckdb_data_chunk) {
    let bind_data = match FfiBindData::<CalDavEventsBindData>::get_from_function(info) {
        Some(d) => d,
        None => {
            duckdb_data_chunk_set_size(output, 0);
            return;
        }
    };
    let init_data = match FfiInitData::<CalDavEventsInitData>::get_mut(info) {
        Some(d) => d,
        None => {
            duckdb_data_chunk_set_size(output, 0);
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
                let fi = FunctionInfo::new(info);
                fi.set_error(&e);
                duckdb_data_chunk_set_size(output, 0);
                return;
            }
        }
    }

    let href_vec = duckdb_data_chunk_get_vector(output, 0);
    let etag_vec = duckdb_data_chunk_get_vector(output, 1);
    let data_vec = duckdb_data_chunk_get_vector(output, 2);

    let mut count: idx_t = 0;
    let max_chunk = 2048;

    while init_data.idx < init_data.events.len() && count < max_chunk {
        let e = &init_data.events[init_data.idx];
        write_varchar(href_vec, count, &e.href);
        write_varchar(etag_vec, count, &e.etag);
        write_varchar(data_vec, count, &e.data);
        init_data.idx += 1;
        count += 1;
    }

    duckdb_data_chunk_set_size(output, count);
}

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
    let val = bind.get_parameter(0);
    let cstr = duckdb_get_varchar(val);
    let url = CStr::from_ptr(cstr).to_str().unwrap_or("").to_string();
    duckdb_free(cstr as *mut _);
    duckdb_destroy_value(&mut { val });

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

unsafe extern "C" fn carddav_contacts_scan(info: duckdb_function_info, output: duckdb_data_chunk) {
    let bind_data = match FfiBindData::<CardDavContactsBindData>::get_from_function(info) {
        Some(d) => d,
        None => {
            duckdb_data_chunk_set_size(output, 0);
            return;
        }
    };
    let init_data = match FfiInitData::<CardDavContactsInitData>::get_mut(info) {
        Some(d) => d,
        None => {
            duckdb_data_chunk_set_size(output, 0);
            return;
        }
    };

    if !init_data.fetched {
        init_data.fetched = true;
        match caldav::list_contacts(&bind_data.url, &bind_data.headers) {
            Ok(contacts) => init_data.contacts = contacts,
            Err(e) => {
                let fi = FunctionInfo::new(info);
                fi.set_error(&e);
                duckdb_data_chunk_set_size(output, 0);
                return;
            }
        }
    }

    let href_vec = duckdb_data_chunk_get_vector(output, 0);
    let etag_vec = duckdb_data_chunk_get_vector(output, 1);
    let data_vec = duckdb_data_chunk_get_vector(output, 2);

    let mut count: idx_t = 0;
    let max_chunk = 2048;

    while init_data.idx < init_data.contacts.len() && count < max_chunk {
        let c = &init_data.contacts[init_data.idx];
        write_varchar(href_vec, count, &c.href);
        write_varchar(etag_vec, count, &c.etag);
        write_varchar(data_vec, count, &c.data);
        init_data.idx += 1;
        count += 1;
    }

    duckdb_data_chunk_set_size(output, count);
}

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
