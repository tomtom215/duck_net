// SPDX-License-Identifier: MIT
// Copyright 2026 Tom F. <tomf@tomtomtech.net> (https://github.com/tomtom215)

use libduckdb_sys::*;
use quack_rs::prelude::*;

use crate::aws_sigv4;

fn sigv4_result_type() -> LogicalType {
    LogicalType::struct_type_from_logical(&[
        ("authorization", LogicalType::new(TypeId::Varchar)),
        ("x_amz_date", LogicalType::new(TypeId::Varchar)),
        ("x_amz_content_sha256", LogicalType::new(TypeId::Varchar)),
    ])
}

// aws_sigv4_sign(method, url, body, access_key, secret_key, region, service) -> STRUCT
quack_rs::scalar_callback!(cb_aws_sigv4_sign, |_info, input, output| {
    let chunk = unsafe { DataChunk::from_raw(input) };
    let row_count = chunk.size();
    let method_reader = unsafe { chunk.reader(0) };
    let url_reader = unsafe { chunk.reader(1) };
    let body_reader = unsafe { chunk.reader(2) };
    let ak_reader = unsafe { chunk.reader(3) };
    let sk_reader = unsafe { chunk.reader(4) };
    let region_reader = unsafe { chunk.reader(5) };
    let service_reader = unsafe { chunk.reader(6) };

    let mut auth_w = unsafe { StructVector::field_writer(output, 0) };
    let mut date_w = unsafe { StructVector::field_writer(output, 1) };
    let mut sha_w = unsafe { StructVector::field_writer(output, 2) };

    for row in 0..row_count {
        let method = unsafe { method_reader.read_str(row) };
        let url = unsafe { url_reader.read_str(row) };
        let body = unsafe { body_reader.read_str(row) };
        let access_key = unsafe { ak_reader.read_str(row) };
        let secret_key = unsafe { sk_reader.read_str(row) };
        let region = unsafe { region_reader.read_str(row) };
        let service = unsafe { service_reader.read_str(row) };

        match aws_sigv4::sign(
            method,
            url,
            &[],
            body,
            access_key,
            secret_key,
            region,
            service,
        ) {
            Ok(signed) => {
                unsafe { auth_w.write_varchar(row, &signed.authorization) };
                unsafe { date_w.write_varchar(row, &signed.x_amz_date) };
                unsafe { sha_w.write_varchar(row, &signed.x_amz_content_sha256) };
            }
            Err(e) => {
                unsafe { auth_w.write_varchar(row, &format!("Error: {e}")) };
                unsafe { date_w.write_varchar(row, "") };
                unsafe { sha_w.write_varchar(row, "") };
            }
        }
    }
});

pub unsafe fn register_all(con: duckdb_connection) -> Result<(), ExtensionError> {
    let v = TypeId::Varchar;

    ScalarFunctionBuilder::new("aws_sigv4_sign")
        .param(v) // method
        .param(v) // url
        .param(v) // body
        .param(v) // access_key
        .param(v) // secret_key
        .param(v) // region
        .param(v) // service
        .returns_logical(sigv4_result_type())
        .function(cb_aws_sigv4_sign)
        .null_handling(NullHandling::SpecialNullHandling)
        .register(con)?;

    Ok(())
}
