// SPDX-License-Identifier: MIT
// Copyright 2026 Tom F. <tomf@tomtomtech.net> (https://github.com/tomtom215)

use quack_rs::prelude::*;

use crate::soap::{self, SoapVersion};

use super::scalars::{map_varchar_varchar, read_headers_map, response_type, write_response};

// ===== SOAP Request Callbacks =====

// soap_request(url, action, body_xml) -> STRUCT
quack_rs::scalar_callback!(cb_soap11_3, |_info, input, output| {
    let chunk = unsafe { DataChunk::from_raw(input) };
    let row_count = chunk.size();
    let url_reader = unsafe { chunk.reader(0) };
    let action_reader = unsafe { chunk.reader(1) };
    let body_reader = unsafe { chunk.reader(2) };
    let mut map_offset: usize = 0;

    for row in 0..row_count {
        let url = unsafe { url_reader.read_str(row) };
        let action = unsafe { action_reader.read_str(row) };
        let body_xml = unsafe { body_reader.read_str(row) };
        let resp = soap::send_request(url, action, body_xml, None, &[], SoapVersion::V1_1);
        unsafe { write_response(output, row, &resp, &mut map_offset) };
    }
});

// soap_request(url, action, body_xml, headers MAP) -> STRUCT
quack_rs::scalar_callback!(cb_soap11_4h, |_info, input, output| {
    let chunk = unsafe { DataChunk::from_raw(input) };
    let row_count = chunk.size();
    let url_reader = unsafe { chunk.reader(0) };
    let action_reader = unsafe { chunk.reader(1) };
    let body_reader = unsafe { chunk.reader(2) };
    let mut map_offset: usize = 0;

    for row in 0..row_count {
        let url = unsafe { url_reader.read_str(row) };
        let action = unsafe { action_reader.read_str(row) };
        let body_xml = unsafe { body_reader.read_str(row) };
        let headers = unsafe { read_headers_map(&chunk, 3, row) };
        let resp = soap::send_request(url, action, body_xml, None, &headers, SoapVersion::V1_1);
        unsafe { write_response(output, row, &resp, &mut map_offset) };
    }
});

// soap_request(url, action, body_xml, soap_header) -> STRUCT
quack_rs::scalar_callback!(cb_soap11_4s, |_info, input, output| {
    let chunk = unsafe { DataChunk::from_raw(input) };
    let row_count = chunk.size();
    let url_reader = unsafe { chunk.reader(0) };
    let action_reader = unsafe { chunk.reader(1) };
    let body_reader = unsafe { chunk.reader(2) };
    let soap_hdr_reader = unsafe { chunk.reader(3) };
    let mut map_offset: usize = 0;

    for row in 0..row_count {
        let url = unsafe { url_reader.read_str(row) };
        let action = unsafe { action_reader.read_str(row) };
        let body_xml = unsafe { body_reader.read_str(row) };
        let soap_hdr = unsafe { soap_hdr_reader.read_str(row) };
        let resp = soap::send_request(
            url,
            action,
            body_xml,
            Some(soap_hdr),
            &[],
            SoapVersion::V1_1,
        );
        unsafe { write_response(output, row, &resp, &mut map_offset) };
    }
});

// soap_request(url, action, body_xml, soap_header, headers MAP) -> STRUCT
quack_rs::scalar_callback!(cb_soap11_5, |_info, input, output| {
    let chunk = unsafe { DataChunk::from_raw(input) };
    let row_count = chunk.size();
    let url_reader = unsafe { chunk.reader(0) };
    let action_reader = unsafe { chunk.reader(1) };
    let body_reader = unsafe { chunk.reader(2) };
    let soap_hdr_reader = unsafe { chunk.reader(3) };
    let mut map_offset: usize = 0;

    for row in 0..row_count {
        let url = unsafe { url_reader.read_str(row) };
        let action = unsafe { action_reader.read_str(row) };
        let body_xml = unsafe { body_reader.read_str(row) };
        let soap_hdr = unsafe { soap_hdr_reader.read_str(row) };
        let headers = unsafe { read_headers_map(&chunk, 4, row) };
        let resp = soap::send_request(
            url,
            action,
            body_xml,
            Some(soap_hdr),
            &headers,
            SoapVersion::V1_1,
        );
        unsafe { write_response(output, row, &resp, &mut map_offset) };
    }
});

// soap12_request(url, action, body_xml) -> STRUCT
quack_rs::scalar_callback!(cb_soap12_3, |_info, input, output| {
    let chunk = unsafe { DataChunk::from_raw(input) };
    let row_count = chunk.size();
    let url_reader = unsafe { chunk.reader(0) };
    let action_reader = unsafe { chunk.reader(1) };
    let body_reader = unsafe { chunk.reader(2) };
    let mut map_offset: usize = 0;

    for row in 0..row_count {
        let url = unsafe { url_reader.read_str(row) };
        let action = unsafe { action_reader.read_str(row) };
        let body_xml = unsafe { body_reader.read_str(row) };
        let resp = soap::send_request(url, action, body_xml, None, &[], SoapVersion::V1_2);
        unsafe { write_response(output, row, &resp, &mut map_offset) };
    }
});

// soap12_request(url, action, body_xml, soap_header) -> STRUCT
quack_rs::scalar_callback!(cb_soap12_4s, |_info, input, output| {
    let chunk = unsafe { DataChunk::from_raw(input) };
    let row_count = chunk.size();
    let url_reader = unsafe { chunk.reader(0) };
    let action_reader = unsafe { chunk.reader(1) };
    let body_reader = unsafe { chunk.reader(2) };
    let soap_hdr_reader = unsafe { chunk.reader(3) };
    let mut map_offset: usize = 0;

    for row in 0..row_count {
        let url = unsafe { url_reader.read_str(row) };
        let action = unsafe { action_reader.read_str(row) };
        let body_xml = unsafe { body_reader.read_str(row) };
        let soap_hdr = unsafe { soap_hdr_reader.read_str(row) };
        let resp = soap::send_request(
            url,
            action,
            body_xml,
            Some(soap_hdr),
            &[],
            SoapVersion::V1_2,
        );
        unsafe { write_response(output, row, &resp, &mut map_offset) };
    }
});

// soap12_request(url, action, body_xml, soap_header, headers MAP) -> STRUCT
quack_rs::scalar_callback!(cb_soap12_5, |_info, input, output| {
    let chunk = unsafe { DataChunk::from_raw(input) };
    let row_count = chunk.size();
    let url_reader = unsafe { chunk.reader(0) };
    let action_reader = unsafe { chunk.reader(1) };
    let body_reader = unsafe { chunk.reader(2) };
    let soap_hdr_reader = unsafe { chunk.reader(3) };
    let mut map_offset: usize = 0;

    for row in 0..row_count {
        let url = unsafe { url_reader.read_str(row) };
        let action = unsafe { action_reader.read_str(row) };
        let body_xml = unsafe { body_reader.read_str(row) };
        let soap_hdr = unsafe { soap_hdr_reader.read_str(row) };
        let headers = unsafe { read_headers_map(&chunk, 4, row) };
        let resp = soap::send_request(
            url,
            action,
            body_xml,
            Some(soap_hdr),
            &headers,
            SoapVersion::V1_2,
        );
        unsafe { write_response(output, row, &resp, &mut map_offset) };
    }
});

// ===== SOAP Parsing Callbacks =====

// soap_extract_body(xml VARCHAR) -> VARCHAR
quack_rs::scalar_callback!(cb_extract_body, |_info, input, output| {
    let chunk = unsafe { DataChunk::from_raw(input) };
    let row_count = chunk.size();
    let xml_reader = unsafe { chunk.reader(0) };
    let mut writer = unsafe { VectorWriter::from_vector(output) };

    for row in 0..row_count {
        let xml = unsafe { xml_reader.read_str(row) };
        let body = soap::extract_body(xml).unwrap_or("");
        unsafe { writer.write_varchar(row, body) };
    }
});

// soap_is_fault(xml VARCHAR) -> BOOLEAN
quack_rs::scalar_callback!(cb_is_fault, |_info, input, output| {
    let chunk = unsafe { DataChunk::from_raw(input) };
    let row_count = chunk.size();
    let xml_reader = unsafe { chunk.reader(0) };
    let mut writer = unsafe { VectorWriter::from_vector(output) };

    for row in 0..row_count {
        let xml = unsafe { xml_reader.read_str(row) };
        unsafe { writer.write_bool(row, soap::is_fault(xml)) };
    }
});

// soap_fault_string(xml VARCHAR) -> VARCHAR
quack_rs::scalar_callback!(cb_fault_string, |_info, input, output| {
    let chunk = unsafe { DataChunk::from_raw(input) };
    let row_count = chunk.size();
    let xml_reader = unsafe { chunk.reader(0) };
    let mut writer = unsafe { VectorWriter::from_vector(output) };

    for row in 0..row_count {
        let xml = unsafe { xml_reader.read_str(row) };
        match soap::fault_string(xml) {
            Some(s) => unsafe { writer.write_varchar(row, s) },
            None => unsafe { writer.set_null(row) },
        }
    }
});

// ===== Registration =====

pub unsafe fn register_all(con: &Connection) -> Result<(), ExtensionError> {
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
        .register(con.as_raw_connection())?;

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
        .register(con.as_raw_connection())?;

    // soap_extract_body(xml) -> VARCHAR
    ScalarFunctionBuilder::new("soap_extract_body")
        .param(v)
        .returns(v)
        .function(cb_extract_body)
        .register(con.as_raw_connection())?;

    // soap_is_fault(xml) -> BOOLEAN
    ScalarFunctionBuilder::new("soap_is_fault")
        .param(v)
        .returns(TypeId::Boolean)
        .function(cb_is_fault)
        .register(con.as_raw_connection())?;

    // soap_fault_string(xml) -> VARCHAR
    ScalarFunctionBuilder::new("soap_fault_string")
        .param(v)
        .returns(v)
        .function(cb_fault_string)
        .null_handling(NullHandling::SpecialNullHandling)
        .register(con.as_raw_connection())?;

    Ok(())
}
