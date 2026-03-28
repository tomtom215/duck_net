use libduckdb_sys::*;
use quack_rs::prelude::*;

use crate::soap::{self, SoapVersion};

use super::scalars::{read_headers_map, response_type, map_varchar_varchar, write_response, write_varchar};

// ===== SOAP Request Callbacks =====

/// soap_request(url, action, body_xml) -> STRUCT
unsafe extern "C" fn cb_soap11_3(
    _info: duckdb_function_info,
    input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    let row_count = duckdb_data_chunk_get_size(input);
    let url_reader = VectorReader::new(input, 0);
    let action_reader = VectorReader::new(input, 1);
    let body_reader = VectorReader::new(input, 2);
    let mut map_offset: idx_t = 0;

    for row in 0..row_count {
        let url = url_reader.read_str(row as usize);
        let action = action_reader.read_str(row as usize);
        let body_xml = body_reader.read_str(row as usize);
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
    let row_count = duckdb_data_chunk_get_size(input);
    let url_reader = VectorReader::new(input, 0);
    let action_reader = VectorReader::new(input, 1);
    let body_reader = VectorReader::new(input, 2);
    let mut map_offset: idx_t = 0;

    for row in 0..row_count {
        let url = url_reader.read_str(row as usize);
        let action = action_reader.read_str(row as usize);
        let body_xml = body_reader.read_str(row as usize);
        let headers = read_headers_map(input, 3, row as usize);
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
    let row_count = duckdb_data_chunk_get_size(input);
    let url_reader = VectorReader::new(input, 0);
    let action_reader = VectorReader::new(input, 1);
    let body_reader = VectorReader::new(input, 2);
    let soap_hdr_reader = VectorReader::new(input, 3);
    let mut map_offset: idx_t = 0;

    for row in 0..row_count {
        let url = url_reader.read_str(row as usize);
        let action = action_reader.read_str(row as usize);
        let body_xml = body_reader.read_str(row as usize);
        let soap_hdr = soap_hdr_reader.read_str(row as usize);
        let resp = soap::send_request(url, action, body_xml, Some(soap_hdr), &[], SoapVersion::V1_1);
        write_response(output, row, &resp, &mut map_offset);
    }
}

/// soap_request(url, action, body_xml, soap_header, headers MAP) -> STRUCT
unsafe extern "C" fn cb_soap11_5(
    _info: duckdb_function_info,
    input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    let row_count = duckdb_data_chunk_get_size(input);
    let url_reader = VectorReader::new(input, 0);
    let action_reader = VectorReader::new(input, 1);
    let body_reader = VectorReader::new(input, 2);
    let soap_hdr_reader = VectorReader::new(input, 3);
    let mut map_offset: idx_t = 0;

    for row in 0..row_count {
        let url = url_reader.read_str(row as usize);
        let action = action_reader.read_str(row as usize);
        let body_xml = body_reader.read_str(row as usize);
        let soap_hdr = soap_hdr_reader.read_str(row as usize);
        let headers = read_headers_map(input, 4, row as usize);
        let resp = soap::send_request(url, action, body_xml, Some(soap_hdr), &headers, SoapVersion::V1_1);
        write_response(output, row, &resp, &mut map_offset);
    }
}

/// soap12_request(url, action, body_xml) -> STRUCT
unsafe extern "C" fn cb_soap12_3(
    _info: duckdb_function_info,
    input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    let row_count = duckdb_data_chunk_get_size(input);
    let url_reader = VectorReader::new(input, 0);
    let action_reader = VectorReader::new(input, 1);
    let body_reader = VectorReader::new(input, 2);
    let mut map_offset: idx_t = 0;

    for row in 0..row_count {
        let url = url_reader.read_str(row as usize);
        let action = action_reader.read_str(row as usize);
        let body_xml = body_reader.read_str(row as usize);
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
    let row_count = duckdb_data_chunk_get_size(input);
    let url_reader = VectorReader::new(input, 0);
    let action_reader = VectorReader::new(input, 1);
    let body_reader = VectorReader::new(input, 2);
    let soap_hdr_reader = VectorReader::new(input, 3);
    let mut map_offset: idx_t = 0;

    for row in 0..row_count {
        let url = url_reader.read_str(row as usize);
        let action = action_reader.read_str(row as usize);
        let body_xml = body_reader.read_str(row as usize);
        let soap_hdr = soap_hdr_reader.read_str(row as usize);
        let resp = soap::send_request(url, action, body_xml, Some(soap_hdr), &[], SoapVersion::V1_2);
        write_response(output, row, &resp, &mut map_offset);
    }
}

/// soap12_request(url, action, body_xml, soap_header, headers MAP) -> STRUCT
unsafe extern "C" fn cb_soap12_5(
    _info: duckdb_function_info,
    input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    let row_count = duckdb_data_chunk_get_size(input);
    let url_reader = VectorReader::new(input, 0);
    let action_reader = VectorReader::new(input, 1);
    let body_reader = VectorReader::new(input, 2);
    let soap_hdr_reader = VectorReader::new(input, 3);
    let mut map_offset: idx_t = 0;

    for row in 0..row_count {
        let url = url_reader.read_str(row as usize);
        let action = action_reader.read_str(row as usize);
        let body_xml = body_reader.read_str(row as usize);
        let soap_hdr = soap_hdr_reader.read_str(row as usize);
        let headers = read_headers_map(input, 4, row as usize);
        let resp = soap::send_request(url, action, body_xml, Some(soap_hdr), &headers, SoapVersion::V1_2);
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
    let row_count = duckdb_data_chunk_get_size(input);
    let xml_reader = VectorReader::new(input, 0);

    for row in 0..row_count {
        let xml = xml_reader.read_str(row as usize);
        let body = soap::extract_body(xml).unwrap_or("");
        write_varchar(output, row, body);
    }
}

/// soap_is_fault(xml VARCHAR) -> BOOLEAN
unsafe extern "C" fn cb_is_fault(
    _info: duckdb_function_info,
    input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    let row_count = duckdb_data_chunk_get_size(input);
    let xml_reader = VectorReader::new(input, 0);
    let data = duckdb_vector_get_data(output) as *mut bool;

    for row in 0..row_count {
        let xml = xml_reader.read_str(row as usize);
        *data.add(row as usize) = soap::is_fault(xml);
    }
}

/// soap_fault_string(xml VARCHAR) -> VARCHAR
unsafe extern "C" fn cb_fault_string(
    _info: duckdb_function_info,
    input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    let row_count = duckdb_data_chunk_get_size(input);
    let xml_reader = VectorReader::new(input, 0);
    duckdb_vector_ensure_validity_writable(output);
    let validity = duckdb_vector_get_validity(output);

    for row in 0..row_count {
        let xml = xml_reader.read_str(row as usize);
        match soap::fault_string(xml) {
            Some(s) => write_varchar(output, row, s),
            None => duckdb_validity_set_row_invalid(validity, row),
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
                .param(v).param(v).param(v)
                .returns_logical(response_type())
                .function(cb_soap11_3)
                .null_handling(NullHandling::SpecialNullHandling),
        )
        .overload(
            ScalarOverloadBuilder::new()
                .param(v).param(v).param(v).param_logical(map_varchar_varchar())
                .returns_logical(response_type())
                .function(cb_soap11_4h)
                .null_handling(NullHandling::SpecialNullHandling),
        )
        .overload(
            ScalarOverloadBuilder::new()
                .param(v).param(v).param(v).param(v)
                .returns_logical(response_type())
                .function(cb_soap11_4s)
                .null_handling(NullHandling::SpecialNullHandling),
        )
        .overload(
            ScalarOverloadBuilder::new()
                .param(v).param(v).param(v).param(v).param_logical(map_varchar_varchar())
                .returns_logical(response_type())
                .function(cb_soap11_5)
                .null_handling(NullHandling::SpecialNullHandling),
        )
        .register(con)?;

    // soap12_request: 3 overloads
    ScalarFunctionSetBuilder::new("soap12_request")
        .overload(
            ScalarOverloadBuilder::new()
                .param(v).param(v).param(v)
                .returns_logical(response_type())
                .function(cb_soap12_3)
                .null_handling(NullHandling::SpecialNullHandling),
        )
        .overload(
            ScalarOverloadBuilder::new()
                .param(v).param(v).param(v).param(v)
                .returns_logical(response_type())
                .function(cb_soap12_4s)
                .null_handling(NullHandling::SpecialNullHandling),
        )
        .overload(
            ScalarOverloadBuilder::new()
                .param(v).param(v).param(v).param(v).param_logical(map_varchar_varchar())
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
