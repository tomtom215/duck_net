// SPDX-License-Identifier: MIT
// Copyright 2026 Tom F. <tomf@tomtomtech.net> (https://github.com/tomtom215)

use libduckdb_sys::*;
use quack_rs::prelude::*;

use crate::http;
use crate::rate_limit;

use super::scalars::write_varchar;

/// Callback: duck_net_set_retry_statuses(statuses VARCHAR) -> VARCHAR
/// Accepts comma-separated status codes, e.g. "429,500,502,503,504"
unsafe extern "C" fn cb_set_retry_statuses(
    _info: duckdb_function_info,
    input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    let row_count = duckdb_data_chunk_get_size(input);
    let statuses_reader = VectorReader::new(input, 0);

    for row in 0..row_count {
        let input_str = statuses_reader.read_str(row as usize);
        let mut codes = Vec::new();
        let mut err = None;
        for part in input_str.split(',') {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }
            match part.parse::<u16>() {
                Ok(code) => codes.push(code),
                Err(_) => {
                    err = Some(format!("Invalid status code: {part}"));
                    break;
                }
            }
        }
        let msg = match err {
            Some(e) => format!("Error: {e}"),
            None => {
                let desc = codes
                    .iter()
                    .map(|c| c.to_string())
                    .collect::<Vec<_>>()
                    .join(",");
                http::set_retry_statuses(codes);
                format!("Retry statuses set to: {desc}")
            }
        };
        write_varchar(output, row, &msg);
    }
}

/// Callback: duck_net_set_domain_rate_limits(config VARCHAR) -> VARCHAR
unsafe extern "C" fn cb_set_domain_rate_limits(
    _info: duckdb_function_info,
    input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    let row_count = duckdb_data_chunk_get_size(input);
    let config_reader = VectorReader::new(input, 0);

    for row in 0..row_count {
        let config = config_reader.read_str(row as usize);
        let msg = match rate_limit::set_domain_limits(config) {
            Ok(m) => m,
            Err(e) => format!("Error: {e}"),
        };
        write_varchar(output, row, &msg);
    }
}

/// Callback: duck_net_set_rate_limit(requests_per_second INTEGER) -> VARCHAR
/// Sets the global rate limit and returns confirmation.
unsafe extern "C" fn cb_set_rate_limit(
    _info: duckdb_function_info,
    input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    let row_count = duckdb_data_chunk_get_size(input);
    let rps_data = duckdb_vector_get_data(duckdb_data_chunk_get_vector(input, 0)) as *const i32;

    for row in 0..row_count {
        let rps = *rps_data.add(row as usize);
        let rps = rps.max(0) as u32;
        rate_limit::set_global_rps(rps);
        let msg = if rps == 0 {
            "Rate limiting disabled".to_string()
        } else {
            format!("Rate limit set to {rps} requests/second")
        };
        write_varchar(output, row, &msg);
    }
}

/// Callback: duck_net_set_retries(max_retries INTEGER, backoff_ms INTEGER) -> VARCHAR
unsafe extern "C" fn cb_set_retries(
    _info: duckdb_function_info,
    input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    let row_count = duckdb_data_chunk_get_size(input);
    let retries_data = duckdb_vector_get_data(duckdb_data_chunk_get_vector(input, 0)) as *const i32;
    let backoff_data = duckdb_vector_get_data(duckdb_data_chunk_get_vector(input, 1)) as *const i32;

    for row in 0..row_count {
        let retries = (*retries_data.add(row as usize)).max(0) as u32;
        let backoff_ms = (*backoff_data.add(row as usize)).max(100) as u64;
        http::set_max_retries(retries);
        http::set_retry_backoff_ms(backoff_ms);
        let msg = if retries == 0 {
            "Retries disabled".to_string()
        } else {
            format!("Retries set to {retries} with {backoff_ms}ms base backoff")
        };
        write_varchar(output, row, &msg);
    }
}

/// Callback: duck_net_set_timeout(seconds INTEGER) -> VARCHAR
unsafe extern "C" fn cb_set_timeout(
    _info: duckdb_function_info,
    input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    let row_count = duckdb_data_chunk_get_size(input);
    let secs_data = duckdb_vector_get_data(duckdb_data_chunk_get_vector(input, 0)) as *const i32;

    for row in 0..row_count {
        let secs = (*secs_data.add(row as usize)).max(1) as u64;
        http::set_timeout_secs(secs);
        write_varchar(output, row, &format!("Timeout set to {secs} seconds"));
    }
}

// ===== Registration =====

pub unsafe fn register_all(con: duckdb_connection) -> Result<(), ExtensionError> {
    // Rate limiting: duck_net_set_rate_limit(requests_per_second INTEGER) -> VARCHAR
    ScalarFunctionBuilder::new("duck_net_set_rate_limit")
        .param(TypeId::Integer)
        .returns(TypeId::Varchar)
        .function(cb_set_rate_limit)
        .register(con)?;

    // Retry config: duck_net_set_retries(max_retries INTEGER, backoff_ms INTEGER) -> VARCHAR
    ScalarFunctionBuilder::new("duck_net_set_retries")
        .param(TypeId::Integer)
        .param(TypeId::Integer)
        .returns(TypeId::Varchar)
        .function(cb_set_retries)
        .register(con)?;

    // Timeout config: duck_net_set_timeout(seconds INTEGER) -> VARCHAR
    ScalarFunctionBuilder::new("duck_net_set_timeout")
        .param(TypeId::Integer)
        .returns(TypeId::Varchar)
        .function(cb_set_timeout)
        .register(con)?;

    // Retry status codes: duck_net_set_retry_statuses(statuses VARCHAR) -> VARCHAR
    ScalarFunctionBuilder::new("duck_net_set_retry_statuses")
        .param(TypeId::Varchar)
        .returns(TypeId::Varchar)
        .function(cb_set_retry_statuses)
        .register(con)?;

    // Per-domain rate limiting: duck_net_set_domain_rate_limits(config VARCHAR) -> VARCHAR
    ScalarFunctionBuilder::new("duck_net_set_domain_rate_limits")
        .param(TypeId::Varchar)
        .returns(TypeId::Varchar)
        .function(cb_set_domain_rate_limits)
        .register(con)?;

    Ok(())
}
