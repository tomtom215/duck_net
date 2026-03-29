use libduckdb_sys::*;
use quack_rs::prelude::*;

use crate::sip;

use super::scalars::write_varchar;

fn sip_result_type() -> LogicalType {
    LogicalType::struct_type_from_logical(&[
        ("alive", LogicalType::new(TypeId::Boolean)),
        ("status_code", LogicalType::new(TypeId::Integer)),
        ("status_text", LogicalType::new(TypeId::Varchar)),
        ("user_agent", LogicalType::new(TypeId::Varchar)),
        ("allow_methods", LogicalType::new(TypeId::Varchar)),
    ])
}

/// sip_options(host) -> STRUCT
unsafe extern "C" fn cb_sip_options(
    _info: duckdb_function_info,
    input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    let row_count = duckdb_data_chunk_get_size(input);
    let host_reader = VectorReader::new(input, 0);

    let alive_vec = duckdb_struct_vector_get_child(output, 0);
    let code_vec = duckdb_struct_vector_get_child(output, 1);
    let text_vec = duckdb_struct_vector_get_child(output, 2);
    let ua_vec = duckdb_struct_vector_get_child(output, 3);
    let allow_vec = duckdb_struct_vector_get_child(output, 4);

    for row in 0..row_count {
        let host = host_reader.read_str(row as usize);
        let result = sip::options_ping(host, 0);

        let ad = duckdb_vector_get_data(alive_vec) as *mut bool;
        *ad.add(row as usize) = result.alive;
        let cd = duckdb_vector_get_data(code_vec) as *mut i32;
        *cd.add(row as usize) = result.status_code;
        write_varchar(text_vec, row, &result.status_text);
        write_varchar(ua_vec, row, &result.user_agent);
        write_varchar(allow_vec, row, &result.allow_methods);
    }
}

/// sip_options(host, port) -> STRUCT
unsafe extern "C" fn cb_sip_options_port(
    _info: duckdb_function_info,
    input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    let row_count = duckdb_data_chunk_get_size(input);
    let host_reader = VectorReader::new(input, 0);
    let port_data = duckdb_vector_get_data(duckdb_data_chunk_get_vector(input, 1)) as *const i32;

    let alive_vec = duckdb_struct_vector_get_child(output, 0);
    let code_vec = duckdb_struct_vector_get_child(output, 1);
    let text_vec = duckdb_struct_vector_get_child(output, 2);
    let ua_vec = duckdb_struct_vector_get_child(output, 3);
    let allow_vec = duckdb_struct_vector_get_child(output, 4);

    for row in 0..row_count {
        let host = host_reader.read_str(row as usize);
        let port = *port_data.add(row as usize) as u16;
        let result = sip::options_ping(host, port);

        let ad = duckdb_vector_get_data(alive_vec) as *mut bool;
        *ad.add(row as usize) = result.alive;
        let cd = duckdb_vector_get_data(code_vec) as *mut i32;
        *cd.add(row as usize) = result.status_code;
        write_varchar(text_vec, row, &result.status_text);
        write_varchar(ua_vec, row, &result.user_agent);
        write_varchar(allow_vec, row, &result.allow_methods);
    }
}

pub unsafe fn register_all(con: duckdb_connection) -> Result<(), ExtensionError> {
    let v = TypeId::Varchar;

    ScalarFunctionSetBuilder::new("sip_options")
        .overload(
            ScalarOverloadBuilder::new()
                .param(v)
                .returns_logical(sip_result_type())
                .function(cb_sip_options)
                .null_handling(NullHandling::SpecialNullHandling),
        )
        .overload(
            ScalarOverloadBuilder::new()
                .param(v)
                .param(TypeId::Integer)
                .returns_logical(sip_result_type())
                .function(cb_sip_options_port)
                .null_handling(NullHandling::SpecialNullHandling),
        )
        .register(con)?;

    Ok(())
}
