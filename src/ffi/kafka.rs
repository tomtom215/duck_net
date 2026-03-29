use libduckdb_sys::*;
use quack_rs::prelude::*;

use crate::kafka;

use super::scalars::write_varchar;

fn kafka_result_type() -> LogicalType {
    LogicalType::struct_type_from_logical(&[
        ("success", LogicalType::new(TypeId::Boolean)),
        ("partition", LogicalType::new(TypeId::Integer)),
        ("offset", LogicalType::new(TypeId::BigInt)),
        ("message", LogicalType::new(TypeId::Varchar)),
    ])
}

/// kafka_produce(brokers, topic, key, value) -> STRUCT(success, partition, offset, message)
unsafe extern "C" fn cb_kafka_produce(
    _info: duckdb_function_info,
    input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    let row_count = duckdb_data_chunk_get_size(input);
    let brokers_reader = VectorReader::new(input, 0);
    let topic_reader = VectorReader::new(input, 1);
    let key_reader = VectorReader::new(input, 2);
    let value_reader = VectorReader::new(input, 3);

    let success_vec = duckdb_struct_vector_get_child(output, 0);
    let partition_vec = duckdb_struct_vector_get_child(output, 1);
    let offset_vec = duckdb_struct_vector_get_child(output, 2);
    let message_vec = duckdb_struct_vector_get_child(output, 3);

    for row in 0..row_count {
        let brokers = brokers_reader.read_str(row as usize);
        let topic = topic_reader.read_str(row as usize);
        let key = key_reader.read_str(row as usize);
        let value = value_reader.read_str(row as usize);

        let key_opt = if key.is_empty() { None } else { Some(key) };
        let result = kafka::produce(brokers, topic, key_opt, value);

        let sd = duckdb_vector_get_data(success_vec) as *mut bool;
        *sd.add(row as usize) = result.success;
        let pd = duckdb_vector_get_data(partition_vec) as *mut i32;
        *pd.add(row as usize) = result.partition;
        let od = duckdb_vector_get_data(offset_vec) as *mut i64;
        *od.add(row as usize) = result.offset;
        write_varchar(message_vec, row, &result.message);
    }
}

/// kafka_produce(brokers, topic, value) -> STRUCT (no key)
unsafe extern "C" fn cb_kafka_produce_no_key(
    _info: duckdb_function_info,
    input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    let row_count = duckdb_data_chunk_get_size(input);
    let brokers_reader = VectorReader::new(input, 0);
    let topic_reader = VectorReader::new(input, 1);
    let value_reader = VectorReader::new(input, 2);

    let success_vec = duckdb_struct_vector_get_child(output, 0);
    let partition_vec = duckdb_struct_vector_get_child(output, 1);
    let offset_vec = duckdb_struct_vector_get_child(output, 2);
    let message_vec = duckdb_struct_vector_get_child(output, 3);

    for row in 0..row_count {
        let brokers = brokers_reader.read_str(row as usize);
        let topic = topic_reader.read_str(row as usize);
        let value = value_reader.read_str(row as usize);

        let result = kafka::produce(brokers, topic, None, value);

        let sd = duckdb_vector_get_data(success_vec) as *mut bool;
        *sd.add(row as usize) = result.success;
        let pd = duckdb_vector_get_data(partition_vec) as *mut i32;
        *pd.add(row as usize) = result.partition;
        let od = duckdb_vector_get_data(offset_vec) as *mut i64;
        *od.add(row as usize) = result.offset;
        write_varchar(message_vec, row, &result.message);
    }
}

pub unsafe fn register_all(con: duckdb_connection) -> Result<(), ExtensionError> {
    let v = TypeId::Varchar;

    ScalarFunctionSetBuilder::new("kafka_produce")
        .overload(
            ScalarOverloadBuilder::new()
                .param(v) // brokers
                .param(v) // topic
                .param(v) // key
                .param(v) // value
                .returns_logical(kafka_result_type())
                .function(cb_kafka_produce)
                .null_handling(NullHandling::SpecialNullHandling),
        )
        .overload(
            ScalarOverloadBuilder::new()
                .param(v) // brokers
                .param(v) // topic
                .param(v) // value
                .returns_logical(kafka_result_type())
                .function(cb_kafka_produce_no_key)
                .null_handling(NullHandling::SpecialNullHandling),
        )
        .register(con)?;

    Ok(())
}
