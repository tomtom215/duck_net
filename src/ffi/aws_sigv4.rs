use libduckdb_sys::*;
use quack_rs::prelude::*;

use crate::aws_sigv4;

use super::scalars::write_varchar;

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
    let row_count = duckdb_data_chunk_get_size(input);
    let method_reader = VectorReader::new(input, 0);
    let url_reader = VectorReader::new(input, 1);
    let body_reader = VectorReader::new(input, 2);
    let ak_reader = VectorReader::new(input, 3);
    let sk_reader = VectorReader::new(input, 4);
    let region_reader = VectorReader::new(input, 5);
    let service_reader = VectorReader::new(input, 6);

    let auth_vec = duckdb_struct_vector_get_child(output, 0);
    let date_vec = duckdb_struct_vector_get_child(output, 1);
    let sha_vec = duckdb_struct_vector_get_child(output, 2);

    for row in 0..row_count {
        let method = method_reader.read_str(row as usize);
        let url = url_reader.read_str(row as usize);
        let body = body_reader.read_str(row as usize);
        let access_key = ak_reader.read_str(row as usize);
        let secret_key = sk_reader.read_str(row as usize);
        let region = region_reader.read_str(row as usize);
        let service = service_reader.read_str(row as usize);

        match aws_sigv4::sign(method, url, &[], body, access_key, secret_key, region, service) {
            Ok(signed) => {
                write_varchar(auth_vec, row, &signed.authorization);
                write_varchar(date_vec, row, &signed.x_amz_date);
                write_varchar(sha_vec, row, &signed.x_amz_content_sha256);
            }
            Err(e) => {
                write_varchar(auth_vec, row, &format!("Error: {e}"));
                write_varchar(date_vec, row, "");
                write_varchar(sha_vec, row, "");
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
