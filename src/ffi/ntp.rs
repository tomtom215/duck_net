use libduckdb_sys::*;
use quack_rs::prelude::*;

use crate::ntp;

use super::scalars::write_varchar;

fn ntp_result_type() -> LogicalType {
    LogicalType::struct_type_from_logical(&[
        ("offset_ms", LogicalType::new(TypeId::Double)),
        ("delay_ms", LogicalType::new(TypeId::Double)),
        ("stratum", LogicalType::new(TypeId::Integer)),
        ("reference_id", LogicalType::new(TypeId::Varchar)),
        ("server_time_unix", LogicalType::new(TypeId::Double)),
    ])
}

/// ntp_query(server) -> STRUCT(offset_ms, delay_ms, stratum, reference_id, server_time_unix)
unsafe extern "C" fn cb_ntp_query(
    _info: duckdb_function_info,
    input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    let row_count = duckdb_data_chunk_get_size(input);
    let server_reader = VectorReader::new(input, 0);

    let offset_vec = duckdb_struct_vector_get_child(output, 0);
    let delay_vec = duckdb_struct_vector_get_child(output, 1);
    let stratum_vec = duckdb_struct_vector_get_child(output, 2);
    let refid_vec = duckdb_struct_vector_get_child(output, 3);
    let time_vec = duckdb_struct_vector_get_child(output, 4);

    for row in 0..row_count {
        let server = server_reader.read_str(row as usize);
        match ntp::query(server) {
            Ok(result) => {
                let od = duckdb_vector_get_data(offset_vec) as *mut f64;
                *od.add(row as usize) = result.offset_ms;
                let dd = duckdb_vector_get_data(delay_vec) as *mut f64;
                *dd.add(row as usize) = result.delay_ms;
                let sd = duckdb_vector_get_data(stratum_vec) as *mut i32;
                *sd.add(row as usize) = result.stratum as i32;
                write_varchar(refid_vec, row, &result.reference_id);
                let td = duckdb_vector_get_data(time_vec) as *mut f64;
                *td.add(row as usize) = result.server_time_unix;
            }
            Err(e) => {
                let od = duckdb_vector_get_data(offset_vec) as *mut f64;
                *od.add(row as usize) = 0.0;
                let dd = duckdb_vector_get_data(delay_vec) as *mut f64;
                *dd.add(row as usize) = 0.0;
                let sd = duckdb_vector_get_data(stratum_vec) as *mut i32;
                *sd.add(row as usize) = -1;
                write_varchar(refid_vec, row, &format!("Error: {e}"));
                let td = duckdb_vector_get_data(time_vec) as *mut f64;
                *td.add(row as usize) = 0.0;
            }
        }
    }
}

pub unsafe fn register_all(con: duckdb_connection) -> Result<(), ExtensionError> {
    ScalarFunctionBuilder::new("ntp_query")
        .param(TypeId::Varchar)
        .returns_logical(ntp_result_type())
        .function(cb_ntp_query)
        .null_handling(NullHandling::SpecialNullHandling)
        .register(con)?;

    Ok(())
}
