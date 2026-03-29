use libduckdb_sys::*;
use quack_rs::prelude::*;

use crate::whois;

use super::scalars::write_varchar;

/// whois_lookup(domain) -> VARCHAR (raw WHOIS text)
unsafe extern "C" fn cb_whois_lookup(
    _info: duckdb_function_info,
    input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    let row_count = duckdb_data_chunk_get_size(input);
    let domain_reader = VectorReader::new(input, 0);

    for row in 0..row_count {
        let domain = domain_reader.read_str(row as usize);
        let result = whois::lookup(domain).unwrap_or_else(|e| format!("WHOIS error: {e}"));
        write_varchar(output, row, &result);
    }
}

/// whois_query(domain) -> STRUCT(registrar, creation_date, expiration_date, updated_date, name_servers VARCHAR[], status VARCHAR[], raw)
unsafe extern "C" fn cb_whois_query(
    _info: duckdb_function_info,
    input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    let row_count = duckdb_data_chunk_get_size(input);
    let domain_reader = VectorReader::new(input, 0);

    let registrar_vec = duckdb_struct_vector_get_child(output, 0);
    let creation_vec = duckdb_struct_vector_get_child(output, 1);
    let expiration_vec = duckdb_struct_vector_get_child(output, 2);
    let updated_vec = duckdb_struct_vector_get_child(output, 3);
    let raw_vec = duckdb_struct_vector_get_child(output, 4);

    for row in 0..row_count {
        let domain = domain_reader.read_str(row as usize);
        let raw = whois::lookup(domain).unwrap_or_else(|e| format!("WHOIS error: {e}"));
        let info = whois::parse_info(&raw);

        write_varchar(registrar_vec, row, &info.registrar);
        write_varchar(creation_vec, row, &info.creation_date);
        write_varchar(expiration_vec, row, &info.expiration_date);
        write_varchar(updated_vec, row, &info.updated_date);
        write_varchar(raw_vec, row, &info.raw);
    }
}

fn whois_query_type() -> LogicalType {
    LogicalType::struct_type_from_logical(&[
        ("registrar", LogicalType::new(TypeId::Varchar)),
        ("creation_date", LogicalType::new(TypeId::Varchar)),
        ("expiration_date", LogicalType::new(TypeId::Varchar)),
        ("updated_date", LogicalType::new(TypeId::Varchar)),
        ("raw", LogicalType::new(TypeId::Varchar)),
    ])
}

pub unsafe fn register_all(con: duckdb_connection) -> Result<(), ExtensionError> {
    let v = TypeId::Varchar;

    ScalarFunctionBuilder::new("whois_lookup")
        .param(v)
        .returns(v)
        .function(cb_whois_lookup)
        .register(con)?;

    ScalarFunctionBuilder::new("whois_query")
        .param(v)
        .returns_logical(whois_query_type())
        .function(cb_whois_query)
        .register(con)?;

    Ok(())
}
