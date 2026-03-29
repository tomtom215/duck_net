use libduckdb_sys::*;
use quack_rs::prelude::*;

use crate::amqp;

use super::scalars::write_varchar;

fn amqp_result_type() -> LogicalType {
    LogicalType::struct_type_from_logical(&[
        ("success", LogicalType::new(TypeId::Boolean)),
        ("message", LogicalType::new(TypeId::Varchar)),
    ])
}

/// amqp_publish(url, exchange, routing_key, message) -> STRUCT(success, message)
unsafe extern "C" fn cb_amqp_publish(
    _info: duckdb_function_info,
    input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    let row_count = duckdb_data_chunk_get_size(input);
    let url_reader = VectorReader::new(input, 0);
    let exchange_reader = VectorReader::new(input, 1);
    let rk_reader = VectorReader::new(input, 2);
    let msg_reader = VectorReader::new(input, 3);

    let success_vec = duckdb_struct_vector_get_child(output, 0);
    let message_vec = duckdb_struct_vector_get_child(output, 1);

    for row in 0..row_count {
        let url = url_reader.read_str(row as usize);
        let exchange = exchange_reader.read_str(row as usize);
        let routing_key = rk_reader.read_str(row as usize);
        let msg = msg_reader.read_str(row as usize);

        let result = amqp::publish(url, exchange, routing_key, msg, None);
        let sd = duckdb_vector_get_data(success_vec) as *mut bool;
        *sd.add(row as usize) = result.success;
        write_varchar(message_vec, row, &result.message);
    }
}

/// amqp_publish(url, exchange, routing_key, message, content_type) -> STRUCT
unsafe extern "C" fn cb_amqp_publish_ct(
    _info: duckdb_function_info,
    input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    let row_count = duckdb_data_chunk_get_size(input);
    let url_reader = VectorReader::new(input, 0);
    let exchange_reader = VectorReader::new(input, 1);
    let rk_reader = VectorReader::new(input, 2);
    let msg_reader = VectorReader::new(input, 3);
    let ct_reader = VectorReader::new(input, 4);

    let success_vec = duckdb_struct_vector_get_child(output, 0);
    let message_vec = duckdb_struct_vector_get_child(output, 1);

    for row in 0..row_count {
        let url = url_reader.read_str(row as usize);
        let exchange = exchange_reader.read_str(row as usize);
        let routing_key = rk_reader.read_str(row as usize);
        let msg = msg_reader.read_str(row as usize);
        let ct = ct_reader.read_str(row as usize);

        let result = amqp::publish(url, exchange, routing_key, msg, Some(ct));
        let sd = duckdb_vector_get_data(success_vec) as *mut bool;
        *sd.add(row as usize) = result.success;
        write_varchar(message_vec, row, &result.message);
    }
}

pub unsafe fn register_all(con: duckdb_connection) -> Result<(), ExtensionError> {
    let v = TypeId::Varchar;

    ScalarFunctionSetBuilder::new("amqp_publish")
        .overload(
            ScalarOverloadBuilder::new()
                .param(v) // url
                .param(v) // exchange
                .param(v) // routing_key
                .param(v) // message
                .returns_logical(amqp_result_type())
                .function(cb_amqp_publish)
                .null_handling(NullHandling::SpecialNullHandling),
        )
        .overload(
            ScalarOverloadBuilder::new()
                .param(v) // url
                .param(v) // exchange
                .param(v) // routing_key
                .param(v) // message
                .param(v) // content_type
                .returns_logical(amqp_result_type())
                .function(cb_amqp_publish_ct)
                .null_handling(NullHandling::SpecialNullHandling),
        )
        .register(con)?;

    Ok(())
}
