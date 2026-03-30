// SPDX-License-Identifier: MIT
// Copyright 2026 Tom F. <tomf@tomtomtech.net> (https://github.com/tomtom215)

use quack_rs::prelude::*;

use crate::ipmi;

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

// ipmi_device_id(host) -> STRUCT(success, device_id, device_revision, firmware_major, firmware_minor, ipmi_version, manufacturer_id, product_id, message)
quack_rs::scalar_callback!(cb_ipmi_device_id, |_info, input, output| {
    let chunk = unsafe { DataChunk::from_raw(input) };
    let row_count = chunk.size();
    let host_reader = unsafe { chunk.reader(0) };

    let mut sw = unsafe { StructWriter::new(output, 9) };

    for row in 0..row_count {
        let host = unsafe { host_reader.read_str(row as usize) };
        let r = ipmi::get_device_id(host);

        unsafe { sw.write_bool(row as usize, 0, r.success) };
        unsafe { sw.write_i32(row as usize, 1, r.device_id as i32) };
        unsafe { sw.write_i32(row as usize, 2, r.device_revision as i32) };
        unsafe { sw.write_i32(row as usize, 3, r.firmware_major as i32) };
        unsafe { sw.write_i32(row as usize, 4, r.firmware_minor as i32) };
        unsafe { sw.write_varchar(row as usize, 5, &r.ipmi_version) };
        unsafe { sw.write_i32(row as usize, 6, r.manufacturer_id as i32) };
        unsafe { sw.write_i32(row as usize, 7, r.product_id as i32) };
        unsafe { sw.write_varchar(row as usize, 8, &r.message) };
    }
});

// ipmi_chassis_status(host) -> STRUCT(success, power_on, power_overload, interlock, power_fault, power_control_fault, power_restore_policy, last_power_event, message)
quack_rs::scalar_callback!(cb_ipmi_chassis_status, |_info, input, output| {
    let chunk = unsafe { DataChunk::from_raw(input) };
    let row_count = chunk.size();
    let host_reader = unsafe { chunk.reader(0) };

    let mut sw = unsafe { StructWriter::new(output, 9) };

    for row in 0..row_count {
        let host = unsafe { host_reader.read_str(row as usize) };
        let r = ipmi::get_chassis_status(host);

        unsafe { sw.write_bool(row as usize, 0, r.success) };
        unsafe { sw.write_bool(row as usize, 1, r.power_on) };
        unsafe { sw.write_bool(row as usize, 2, r.power_overload) };
        unsafe { sw.write_bool(row as usize, 3, r.interlock) };
        unsafe { sw.write_bool(row as usize, 4, r.power_fault) };
        unsafe { sw.write_bool(row as usize, 5, r.power_control_fault) };
        unsafe { sw.write_varchar(row as usize, 6, &r.power_restore_policy) };
        unsafe { sw.write_varchar(row as usize, 7, &r.last_power_event) };
        unsafe { sw.write_varchar(row as usize, 8, &r.message) };
    }
});

// ipmi_chassis_control(host, action) -> STRUCT(success, data, completion_code, message)
quack_rs::scalar_callback!(cb_ipmi_chassis_control, |_info, input, output| {
    let chunk = unsafe { DataChunk::from_raw(input) };
    let row_count = chunk.size();
    let host_reader = unsafe { chunk.reader(0) };
    let action_reader = unsafe { chunk.reader(1) };

    let mut sw = unsafe { StructWriter::new(output, 4) };

    for row in 0..row_count {
        let host = unsafe { host_reader.read_str(row as usize) };
        let action = unsafe { action_reader.read_str(row as usize) };
        let r = ipmi::chassis_control(host, action);

        unsafe { sw.write_bool(row as usize, 0, r.success) };
        unsafe { sw.write_varchar(row as usize, 1, &r.data) };
        unsafe { sw.write_i32(row as usize, 2, r.completion_code as i32) };
        unsafe { sw.write_varchar(row as usize, 3, &r.message) };
    }
});

// ===== Registration =====

pub unsafe fn register_all(con: libduckdb_sys::duckdb_connection) -> Result<(), ExtensionError> {
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
