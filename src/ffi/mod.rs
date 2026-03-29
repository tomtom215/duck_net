// SPDX-License-Identifier: MIT
// Copyright 2026 Tom F. <tomf@tomtomtech.net> (https://github.com/tomtom215)

mod amqp;
mod aws_sigv4;
mod bgp;
mod caldav;
mod consul;
pub(crate) mod dns;
mod doh;
mod elasticsearch;
mod ftp;
mod graphql;
mod grpc;
mod imap;
mod influxdb;
mod ipmi;
mod jsonrpc;
mod kafka;
mod ldap;
mod mdns;
mod memcached;
mod mqtt;
mod nats;
mod ntp;
mod ocsp;
mod odata;
mod ping;
mod prometheus;
mod ptp;
mod radius;
mod redis_client;
mod s3;
pub(crate) mod scalars;
mod scalars_config;
mod secrets;
mod secrets_protocols;
mod secrets_protocols_ext;
mod security_warnings;
mod sip;
mod smtp;
mod snmp;
mod soap;
mod ssh;
mod stun;
mod syslog;
mod table;
mod tls_inspect;
mod vault;
mod webdav;
mod websocket;
mod whois;
mod zeromq;

use quack_rs::prelude::*;

pub fn register_all(con: &Connection) -> Result<(), ExtensionError> {
    let raw_con = con.as_raw_connection();
    unsafe {
        // Core HTTP
        scalars::register_all(raw_con)?;
        soap::register_all(raw_con)?;
        table::register_all(raw_con)?;

        // Existing protocols
        dns::register_all(raw_con)?;
        smtp::register_all(raw_con)?;
        ftp::register_all(raw_con)?;

        // Tier 1: High value
        graphql::register_all(raw_con)?;
        tls_inspect::register_all(raw_con)?;
        whois::register_all(raw_con)?;
        webdav::register_all(raw_con)?;
        odata::register_all(raw_con)?;
        ldap::register_all(raw_con)?;
        jsonrpc::register_all(raw_con)?;

        // Tier 2: Strong value
        imap::register_all(raw_con)?;
        snmp::register_all(raw_con)?;
        ping::register_all(raw_con)?;

        // Tier 3: Niche but valid
        ntp::register_all(raw_con)?;
        sip::register_all(raw_con)?;
        caldav::register_all(raw_con)?;
        syslog::register_all(raw_con)?;
        aws_sigv4::register_all(raw_con)?;
        amqp::register_all(raw_con)?;
        kafka::register_all(raw_con)?;

        // New Tier 1: High Impact
        ssh::register_all(raw_con)?;
        redis_client::register_all(raw_con)?;
        grpc::register_all(raw_con)?;
        websocket::register_all(raw_con)?;

        // New Tier 2: Infrastructure
        mqtt::register_all(raw_con)?;
        memcached::register_all(raw_con)?;
        prometheus::register_all(raw_con)?;
        elasticsearch::register_all(raw_con)?;

        // New Tier 3: Niche but Clean Fits
        radius::register_all(raw_con)?;
        doh::register_all(raw_con)?;
        mdns::register_all(raw_con)?;
        stun::register_all(raw_con)?;
        bgp::register_all(raw_con)?;

        // Precision Time
        ptp::register_all(raw_con)?;

        // Certificate revocation: OCSP
        ocsp::register_all(raw_con)?;

        // S3-compatible storage
        s3::register_all(raw_con)?;

        // Time-series: InfluxDB
        influxdb::register_all(raw_con)?;

        // Service discovery & config: Consul/etcd
        consul::register_all(raw_con)?;

        // Cloud-native messaging: NATS, ZeroMQ
        nats::register_all(raw_con)?;
        zeromq::register_all(raw_con)?;

        // Secrets: Vault
        vault::register_all(raw_con)?;

        // Hardware: IPMI
        ipmi::register_all(raw_con)?;

        // Security: Secrets manager + hardening configuration
        secrets::register_all(raw_con)?;

        // Security warnings subsystem
        security_warnings::register_all(raw_con)?;
    }
    Ok(())
}
