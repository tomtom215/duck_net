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

/// aws_sigv4_sign(method, url, body, access_key, secret_key, region, service) -> STRUCT
unsafe extern "C" fn cb_aws_sigv4_sign(
    _info: duckdb_function_info,
    input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    let chunk = DataChunk::from_raw(input);
    let row_count = chunk.size();
    let method_reader = chunk.reader(0);
    let url_reader = chunk.reader(1);
    let body_reader = chunk.reader(2);
    let ak_reader = chunk.reader(3);
    let sk_reader = chunk.reader(4);
    let region_reader = chunk.reader(5);
    let service_reader = chunk.reader(6);

    let mut auth_w = StructVector::field_writer(output, 0);
    let mut date_w = StructVector::field_writer(output, 1);
    let mut sha_w = StructVector::field_writer(output, 2);

    for row in 0..row_count {
        let method = method_reader.read_str(row);
        let url = url_reader.read_str(row);
        let body = body_reader.read_str(row);
        let access_key = ak_reader.read_str(row);
        let secret_key = sk_reader.read_str(row);
        let region = region_reader.read_str(row);
        let service = service_reader.read_str(row);

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
                auth_w.write_varchar(row, &signed.authorization);
                date_w.write_varchar(row, &signed.x_amz_date);
                sha_w.write_varchar(row, &signed.x_amz_content_sha256);
            }
            Err(e) => {
                auth_w.write_varchar(row, &format!("Error: {e}"));
                date_w.write_varchar(row, "");
                sha_w.write_varchar(row, "");
            }
        }
    }
}

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
