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
    let row_count = duckdb_data_chunk_get_size(input);
    let host_reader = VectorReader::new(input, 0);

    let success_vec = duckdb_struct_vector_get_child(output, 0);
    let device_id_vec = duckdb_struct_vector_get_child(output, 1);
    let device_revision_vec = duckdb_struct_vector_get_child(output, 2);
    let firmware_major_vec = duckdb_struct_vector_get_child(output, 3);
    let firmware_minor_vec = duckdb_struct_vector_get_child(output, 4);
    let ipmi_version_vec = duckdb_struct_vector_get_child(output, 5);
    let manufacturer_id_vec = duckdb_struct_vector_get_child(output, 6);
    let product_id_vec = duckdb_struct_vector_get_child(output, 7);
    let message_vec = duckdb_struct_vector_get_child(output, 8);

    for row in 0..row_count {
        let host = host_reader.read_str(row as usize);
        let r = ipmi::get_device_id(host);

        let sd = duckdb_vector_get_data(success_vec) as *mut bool;
        *sd.add(row as usize) = r.success;
        let did = duckdb_vector_get_data(device_id_vec) as *mut i32;
        *did.add(row as usize) = r.device_id as i32;
        let drd = duckdb_vector_get_data(device_revision_vec) as *mut i32;
        *drd.add(row as usize) = r.device_revision as i32;
        let fmajd = duckdb_vector_get_data(firmware_major_vec) as *mut i32;
        *fmajd.add(row as usize) = r.firmware_major as i32;
        let fmind = duckdb_vector_get_data(firmware_minor_vec) as *mut i32;
        *fmind.add(row as usize) = r.firmware_minor as i32;
        write_varchar(ipmi_version_vec, row, &r.ipmi_version);
        let mid = duckdb_vector_get_data(manufacturer_id_vec) as *mut i32;
        *mid.add(row as usize) = r.manufacturer_id as i32;
        let pid = duckdb_vector_get_data(product_id_vec) as *mut i32;
        *pid.add(row as usize) = r.product_id as i32;
        write_varchar(message_vec, row, &r.message);
    }
}

/// ipmi_chassis_status(host) -> STRUCT(success, power_on, power_overload, interlock, power_fault, power_control_fault, power_restore_policy, last_power_event, message)
unsafe extern "C" fn cb_ipmi_chassis_status(
    _info: duckdb_function_info,
    input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    let row_count = duckdb_data_chunk_get_size(input);
    let host_reader = VectorReader::new(input, 0);

    let success_vec = duckdb_struct_vector_get_child(output, 0);
    let power_on_vec = duckdb_struct_vector_get_child(output, 1);
    let power_overload_vec = duckdb_struct_vector_get_child(output, 2);
    let interlock_vec = duckdb_struct_vector_get_child(output, 3);
    let power_fault_vec = duckdb_struct_vector_get_child(output, 4);
    let power_control_fault_vec = duckdb_struct_vector_get_child(output, 5);
    let power_restore_policy_vec = duckdb_struct_vector_get_child(output, 6);
    let last_power_event_vec = duckdb_struct_vector_get_child(output, 7);
    let message_vec = duckdb_struct_vector_get_child(output, 8);

    for row in 0..row_count {
        let host = host_reader.read_str(row as usize);
        let r = ipmi::get_chassis_status(host);

        let sd = duckdb_vector_get_data(success_vec) as *mut bool;
        *sd.add(row as usize) = r.success;
        let pod = duckdb_vector_get_data(power_on_vec) as *mut bool;
        *pod.add(row as usize) = r.power_on;
        let pold = duckdb_vector_get_data(power_overload_vec) as *mut bool;
        *pold.add(row as usize) = r.power_overload;
        let ild = duckdb_vector_get_data(interlock_vec) as *mut bool;
        *ild.add(row as usize) = r.interlock;
        let pfd = duckdb_vector_get_data(power_fault_vec) as *mut bool;
        *pfd.add(row as usize) = r.power_fault;
        let pcfd = duckdb_vector_get_data(power_control_fault_vec) as *mut bool;
        *pcfd.add(row as usize) = r.power_control_fault;
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
    let row_count = duckdb_data_chunk_get_size(input);
    let host_reader = VectorReader::new(input, 0);
    let action_reader = VectorReader::new(input, 1);

    let success_vec = duckdb_struct_vector_get_child(output, 0);
    let data_vec = duckdb_struct_vector_get_child(output, 1);
    let completion_code_vec = duckdb_struct_vector_get_child(output, 2);
    let message_vec = duckdb_struct_vector_get_child(output, 3);

    for row in 0..row_count {
        let host = host_reader.read_str(row as usize);
        let action = action_reader.read_str(row as usize);
        let r = ipmi::chassis_control(host, action);

        let sd = duckdb_vector_get_data(success_vec) as *mut bool;
        *sd.add(row as usize) = r.success;
        write_varchar(data_vec, row, &r.data);
        let ccd = duckdb_vector_get_data(completion_code_vec) as *mut i32;
        *ccd.add(row as usize) = r.completion_code as i32;
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
