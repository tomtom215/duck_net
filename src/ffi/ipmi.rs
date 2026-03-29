// SPDX-License-Identifier: MIT
// Copyright 2026 Tom F. <tomf@tomtomtech.net> (https://github.com/tomtom215)

use libduckdb_sys::*;
use quack_rs::prelude::*;

use crate::ipmi;

use super::scalars::write_varchar;

// ===== Return Type Helpers =====

fn ipmi_device_type() -> LogicalType {
    LogicalType::struct_type_from_logical(&[
        ("success", LogicalType::new(TypeId::Boolean)),
        ("device_id", LogicalType::new(TypeId::Integer)),
        ("device_revision", LogicalType::new(TypeId::Integer)),
        ("firmware_major", LogicalType::new(TypeId::Integer)),
        ("firmware_minor", LogicalType::new(TypeId::Integer)),
        ("ipmi_version", LogicalType::new(TypeId::Varchar)),
        ("manufacturer_id", LogicalType::new(TypeId::Integer)),
        ("product_id", LogicalType::new(TypeId::Integer)),
        ("message", LogicalType::new(TypeId::Varchar)),
    ])
}

fn ipmi_chassis_type() -> LogicalType {
    LogicalType::struct_type_from_logical(&[
        ("success", LogicalType::new(TypeId::Boolean)),
        ("power_on", LogicalType::new(TypeId::Boolean)),
        ("power_overload", LogicalType::new(TypeId::Boolean)),
        ("interlock", LogicalType::new(TypeId::Boolean)),
        ("power_fault", LogicalType::new(TypeId::Boolean)),
        ("power_control_fault", LogicalType::new(TypeId::Boolean)),
        ("power_restore_policy", LogicalType::new(TypeId::Varchar)),
        ("last_power_event", LogicalType::new(TypeId::Varchar)),
        ("message", LogicalType::new(TypeId::Varchar)),
    ])
}

fn ipmi_result_type() -> LogicalType {
    LogicalType::struct_type_from_logical(&[
        ("success", LogicalType::new(TypeId::Boolean)),
        ("data", LogicalType::new(TypeId::Varchar)),
        ("completion_code", LogicalType::new(TypeId::Integer)),
        ("message", LogicalType::new(TypeId::Varchar)),
    ])
}

// ===== Scalar Callbacks =====

/// ipmi_device_id(host) -> STRUCT(success, device_id, device_revision, firmware_major, firmware_minor, ipmi_version, manufacturer_id, product_id, message)
unsafe extern "C" fn cb_ipmi_device_id(
    _info: duckdb_function_info,
    input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    let chunk = DataChunk::from_raw(input);
    let row_count = chunk.size();
    let host_reader = chunk.reader(0);

    let mut success_w = StructVector::field_writer(output, 0);
    let mut device_id_w = StructVector::field_writer(output, 1);
    let mut device_revision_w = StructVector::field_writer(output, 2);
    let mut firmware_major_w = StructVector::field_writer(output, 3);
    let mut firmware_minor_w = StructVector::field_writer(output, 4);
    let ipmi_version_vec = duckdb_struct_vector_get_child(output, 5);
    let mut manufacturer_id_w = StructVector::field_writer(output, 6);
    let mut product_id_w = StructVector::field_writer(output, 7);
    let message_vec = duckdb_struct_vector_get_child(output, 8);

    for row in 0..row_count {
        let host = host_reader.read_str(row as usize);
        let r = ipmi::get_device_id(host);

        success_w.write_bool(row as usize, r.success);
        device_id_w.write_i32(row as usize, r.device_id as i32);
        device_revision_w.write_i32(row as usize, r.device_revision as i32);
        firmware_major_w.write_i32(row as usize, r.firmware_major as i32);
        firmware_minor_w.write_i32(row as usize, r.firmware_minor as i32);
        write_varchar(ipmi_version_vec, row, &r.ipmi_version);
        manufacturer_id_w.write_i32(row as usize, r.manufacturer_id as i32);
        product_id_w.write_i32(row as usize, r.product_id as i32);
        write_varchar(message_vec, row, &r.message);
    }
}

/// ipmi_chassis_status(host) -> STRUCT(success, power_on, power_overload, interlock, power_fault, power_control_fault, power_restore_policy, last_power_event, message)
unsafe extern "C" fn cb_ipmi_chassis_status(
    _info: duckdb_function_info,
    input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    let chunk = DataChunk::from_raw(input);
    let row_count = chunk.size();
    let host_reader = chunk.reader(0);

    let mut success_w = StructVector::field_writer(output, 0);
    let mut power_on_w = StructVector::field_writer(output, 1);
    let mut power_overload_w = StructVector::field_writer(output, 2);
    let mut interlock_w = StructVector::field_writer(output, 3);
    let mut power_fault_w = StructVector::field_writer(output, 4);
    let mut power_control_fault_w = StructVector::field_writer(output, 5);
    let power_restore_policy_vec = duckdb_struct_vector_get_child(output, 6);
    let last_power_event_vec = duckdb_struct_vector_get_child(output, 7);
    let message_vec = duckdb_struct_vector_get_child(output, 8);

    for row in 0..row_count {
        let host = host_reader.read_str(row as usize);
        let r = ipmi::get_chassis_status(host);

        success_w.write_bool(row as usize, r.success);
        power_on_w.write_bool(row as usize, r.power_on);
        power_overload_w.write_bool(row as usize, r.power_overload);
        interlock_w.write_bool(row as usize, r.interlock);
        power_fault_w.write_bool(row as usize, r.power_fault);
        power_control_fault_w.write_bool(row as usize, r.power_control_fault);
        write_varchar(power_restore_policy_vec, row, &r.power_restore_policy);
        write_varchar(last_power_event_vec, row, &r.last_power_event);
        write_varchar(message_vec, row, &r.message);
    }
}

/// ipmi_chassis_control(host, action) -> STRUCT(success, data, completion_code, message)
unsafe extern "C" fn cb_ipmi_chassis_control(
    _info: duckdb_function_info,
    input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    let chunk = DataChunk::from_raw(input);
    let row_count = chunk.size();
    let host_reader = chunk.reader(0);
    let action_reader = chunk.reader(1);

    let mut success_w = StructVector::field_writer(output, 0);
    let data_vec = duckdb_struct_vector_get_child(output, 1);
    let mut completion_code_w = StructVector::field_writer(output, 2);
    let message_vec = duckdb_struct_vector_get_child(output, 3);

    for row in 0..row_count {
        let host = host_reader.read_str(row as usize);
        let action = action_reader.read_str(row as usize);
        let r = ipmi::chassis_control(host, action);

        success_w.write_bool(row as usize, r.success);
        write_varchar(data_vec, row, &r.data);
        completion_code_w.write_i32(row as usize, r.completion_code as i32);
        write_varchar(message_vec, row, &r.message);
    }
}

// ===== Registration =====

pub unsafe fn register_all(con: duckdb_connection) -> Result<(), ExtensionError> {
    let v = TypeId::Varchar;

    ScalarFunctionBuilder::new("ipmi_device_id")
        .param(v)
        .returns_logical(ipmi_device_type())
        .function(cb_ipmi_device_id)
        .register(con)?;

    ScalarFunctionBuilder::new("ipmi_chassis_status")
        .param(v)
        .returns_logical(ipmi_chassis_type())
        .function(cb_ipmi_chassis_status)
        .register(con)?;

    ScalarFunctionBuilder::new("ipmi_chassis_control")
        .param(v)
        .param(v)
        .returns_logical(ipmi_result_type())
        .function(cb_ipmi_chassis_control)
        .register(con)?;

    Ok(())
}
