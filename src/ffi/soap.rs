// SPDX-License-Identifier: MIT
// Copyright 2026 Tom F. <tomf@tomtomtech.net> (https://github.com/tomtom215)

use libduckdb_sys::*;
use quack_rs::prelude::*;

use crate::soap::{self, SoapVersion};

use super::scalars::{map_varchar_varchar, read_headers_map, response_type, write_response};

// ===== SOAP Request Callbacks =====

/// soap_request(url, action, body_xml) -> STRUCT
unsafe extern "C" fn cb_soap11_3(
    _info: duckdb_function_info,
    input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    let chunk = DataChunk::from_raw(input);
    let row_count = chunk.size();
    let url_reader = chunk.reader(0);
    let action_reader = chunk.reader(1);
    let body_reader = chunk.reader(2);
    let mut map_offset: usize = 0;

    for row in 0..row_count {
        let url = url_reader.read_str(row);
        let action = action_reader.read_str(row);
        let body_xml = body_reader.read_str(row);
        let resp = soap::send_request(url, action, body_xml, None, &[], SoapVersion::V1_1);
        write_response(output, row, &resp, &mut map_offset);
    }
}

/// soap_request(url, action, body_xml, headers MAP) -> STRUCT
unsafe extern "C" fn cb_soap11_4h(
    _info: duckdb_function_info,
    input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    let chunk = DataChunk::from_raw(input);
    let row_count = chunk.size();
    let url_reader = chunk.reader(0);
    let action_reader = chunk.reader(1);
    let body_reader = chunk.reader(2);
    let mut map_offset: usize = 0;

    for row in 0..row_count {
        let url = url_reader.read_str(row);
        let action = action_reader.read_str(row);
        let body_xml = body_reader.read_str(row);
        let headers = read_headers_map(input, 3, row);
        let resp = soap::send_request(url, action, body_xml, None, &headers, SoapVersion::V1_1);
        write_response(output, row, &resp, &mut map_offset);
    }
}

/// soap_request(url, action, body_xml, soap_header) -> STRUCT
unsafe extern "C" fn cb_soap11_4s(
    _info: duckdb_function_info,
    input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    let chunk = DataChunk::from_raw(input);
    let row_count = chunk.size();
    let url_reader = chunk.reader(0);
    let action_reader = chunk.reader(1);
    let body_reader = chunk.reader(2);
    let soap_hdr_reader = chunk.reader(3);
    let mut map_offset: usize = 0;

    for row in 0..row_count {
        let url = url_reader.read_str(row);
        let action = action_reader.read_str(row);
        let body_xml = body_reader.read_str(row);
        let soap_hdr = soap_hdr_reader.read_str(row);
        let resp = soap::send_request(
            url,
            action,
            body_xml,
            Some(soap_hdr),
            &[],
            SoapVersion::V1_1,
        );
        write_response(output, row, &resp, &mut map_offset);
    }
}

/// soap_request(url, action, body_xml, soap_header, headers MAP) -> STRUCT
unsafe extern "C" fn cb_soap11_5(
    _info: duckdb_function_info,
    input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    let chunk = DataChunk::from_raw(input);
    let row_count = chunk.size();
    let url_reader = chunk.reader(0);
    let action_reader = chunk.reader(1);
    let body_reader = chunk.reader(2);
    let soap_hdr_reader = chunk.reader(3);
    let mut map_offset: usize = 0;

    for row in 0..row_count {
        let url = url_reader.read_str(row);
        let action = action_reader.read_str(row);
        let body_xml = body_reader.read_str(row);
        let soap_hdr = soap_hdr_reader.read_str(row);
        let headers = read_headers_map(input, 4, row);
        let resp = soap::send_request(
            url,
            action,
            body_xml,
            Some(soap_hdr),
            &headers,
            SoapVersion::V1_1,
        );
        write_response(output, row, &resp, &mut map_offset);
    }
}

/// soap12_request(url, action, body_xml) -> STRUCT
unsafe extern "C" fn cb_soap12_3(
    _info: duckdb_function_info,
    input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    let chunk = DataChunk::from_raw(input);
    let row_count = chunk.size();
    let url_reader = chunk.reader(0);
    let action_reader = chunk.reader(1);
    let body_reader = chunk.reader(2);
    let mut map_offset: usize = 0;

    for row in 0..row_count {
        let url = url_reader.read_str(row);
        let action = action_reader.read_str(row);
        let body_xml = body_reader.read_str(row);
        let resp = soap::send_request(url, action, body_xml, None, &[], SoapVersion::V1_2);
        write_response(output, row, &resp, &mut map_offset);
    }
}

/// soap12_request(url, action, body_xml, soap_header) -> STRUCT
unsafe extern "C" fn cb_soap12_4s(
    _info: duckdb_function_info,
    input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    let chunk = DataChunk::from_raw(input);
    let row_count = chunk.size();
    let url_reader = chunk.reader(0);
    let action_reader = chunk.reader(1);
    let body_reader = chunk.reader(2);
    let soap_hdr_reader = chunk.reader(3);
    let mut map_offset: usize = 0;

    for row in 0..row_count {
        let url = url_reader.read_str(row);
        let action = action_reader.read_str(row);
        let body_xml = body_reader.read_str(row);
        let soap_hdr = soap_hdr_reader.read_str(row);
        let resp = soap::send_request(
            url,
            action,
            body_xml,
            Some(soap_hdr),
            &[],
            SoapVersion::V1_2,
        );
        write_response(output, row, &resp, &mut map_offset);
    }
}

/// soap12_request(url, action, body_xml, soap_header, headers MAP) -> STRUCT
unsafe extern "C" fn cb_soap12_5(
    _info: duckdb_function_info,
    input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    let chunk = DataChunk::from_raw(input);
    let row_count = chunk.size();
    let url_reader = chunk.reader(0);
    let action_reader = chunk.reader(1);
    let body_reader = chunk.reader(2);
    let soap_hdr_reader = chunk.reader(3);
    let mut map_offset: usize = 0;

    for row in 0..row_count {
        let url = url_reader.read_str(row);
        let action = action_reader.read_str(row);
        let body_xml = body_reader.read_str(row);
        let soap_hdr = soap_hdr_reader.read_str(row);
        let headers = read_headers_map(input, 4, row);
        let resp = soap::send_request(
            url,
            action,
            body_xml,
            Some(soap_hdr),
            &headers,
            SoapVersion::V1_2,
        );
        write_response(output, row, &resp, &mut map_offset);
    }
}

// ===== SOAP Parsing Callbacks =====

/// soap_extract_body(xml VARCHAR) -> VARCHAR
unsafe extern "C" fn cb_extract_body(
    _info: duckdb_function_info,
    input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    let chunk = DataChunk::from_raw(input);
    let row_count = chunk.size();
    let xml_reader = chunk.reader(0);
    let mut writer = VectorWriter::from_vector(output);

    for row in 0..row_count {
        let xml = xml_reader.read_str(row);
        let body = soap::extract_body(xml).unwrap_or("");
        writer.write_varchar(row, body);
    }
}

/// soap_is_fault(xml VARCHAR) -> BOOLEAN
unsafe extern "C" fn cb_is_fault(
    _info: duckdb_function_info,
    input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    let chunk = DataChunk::from_raw(input);
    let row_count = chunk.size();
    let xml_reader = chunk.reader(0);
    let data = duckdb_vector_get_data(output) as *mut bool;

    for row in 0..row_count {
        let xml = xml_reader.read_str(row);
        *data.add(row) = soap::is_fault(xml);
    }
}

/// soap_fault_string(xml VARCHAR) -> VARCHAR
unsafe extern "C" fn cb_fault_string(
    _info: duckdb_function_info,
    input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    let chunk = DataChunk::from_raw(input);
    let row_count = chunk.size();
    let xml_reader = chunk.reader(0);
    let mut writer = VectorWriter::from_vector(output);

    for row in 0..row_count {
        let xml = xml_reader.read_str(row);
        match soap::fault_string(xml) {
            Some(s) => writer.write_varchar(row, s),
            None => writer.set_null(row),
        }
    }
}

// ===== Registration =====

pub unsafe fn register_all(con: duckdb_connection) -> Result<(), ExtensionError> {
    let v = TypeId::Varchar;

    // soap_request: 4 overloads (3-arg, 4-arg with headers, 4-arg with soap_header, 5-arg)
    ScalarFunctionSetBuilder::new("soap_request")
        .overload(
            ScalarOverloadBuilder::new()
                .param(v)
                .param(v)
                .param(v)
                .returns_logical(response_type())
                .function(cb_soap11_3)
                .null_handling(NullHandling::SpecialNullHandling),
        )
        .overload(
            ScalarOverloadBuilder::new()
                .param(v)
                .param(v)
                .param(v)
                .param_logical(map_varchar_varchar())
                .returns_logical(response_type())
                .function(cb_soap11_4h)
                .null_handling(NullHandling::SpecialNullHandling),
        )
        .overload(
            ScalarOverloadBuilder::new()
                .param(v)
                .param(v)
                .param(v)
                .param(v)
                .returns_logical(response_type())
                .function(cb_soap11_4s)
                .null_handling(NullHandling::SpecialNullHandling),
        )
        .overload(
            ScalarOverloadBuilder::new()
                .param(v)
                .param(v)
                .param(v)
                .param(v)
                .param_logical(map_varchar_varchar())
                .returns_logical(response_type())
                .function(cb_soap11_5)
                .null_handling(NullHandling::SpecialNullHandling),
        )
        .register(con)?;

    // soap12_request: 3 overloads
    ScalarFunctionSetBuilder::new("soap12_request")
        .overload(
            ScalarOverloadBuilder::new()
                .param(v)
                .param(v)
                .param(v)
                .returns_logical(response_type())
                .function(cb_soap12_3)
                .null_handling(NullHandling::SpecialNullHandling),
        )
        .overload(
            ScalarOverloadBuilder::new()
                .param(v)
                .param(v)
                .param(v)
                .param(v)
                .returns_logical(response_type())
                .function(cb_soap12_4s)
                .null_handling(NullHandling::SpecialNullHandling),
        )
        .overload(
            ScalarOverloadBuilder::new()
                .param(v)
                .param(v)
                .param(v)
                .param(v)
                .param_logical(map_varchar_varchar())
                .returns_logical(response_type())
                .function(cb_soap12_5)
                .null_handling(NullHandling::SpecialNullHandling),
        )
        .register(con)?;

    // soap_extract_body(xml) -> VARCHAR
    ScalarFunctionBuilder::new("soap_extract_body")
        .param(v)
        .returns(v)
        .function(cb_extract_body)
        .register(con)?;

    // soap_is_fault(xml) -> BOOLEAN
    ScalarFunctionBuilder::new("soap_is_fault")
        .param(v)
        .returns(TypeId::Boolean)
        .function(cb_is_fault)
        .register(con)?;

    // soap_fault_string(xml) -> VARCHAR
    ScalarFunctionBuilder::new("soap_fault_string")
        .param(v)
        .returns(v)
        .function(cb_fault_string)
        .null_handling(NullHandling::SpecialNullHandling)
        .register(con)?;

    Ok(())
}
