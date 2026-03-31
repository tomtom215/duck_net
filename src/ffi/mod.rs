// SPDX-License-Identifier: MIT
// Copyright 2026 Tom F. <tomf@tomtomtech.net> (https://github.com/tomtom215)

mod amqp;
mod aws_sigv4;
mod bgp;
mod caldav;
mod consul;
pub(crate) mod dns;
mod doh;
mod duckdb_secrets_bridge;
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
mod oauth2;
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
mod sftp;
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
    unsafe {
        // Core HTTP
        scalars::register_all(con)?;
        soap::register_all(con)?;
        table::register_all(con)?;

        // Existing protocols
        dns::register_all(con)?;
        smtp::register_all(con)?;
        ftp::register_all(con)?;

        // Tier 1: High value
        graphql::register_all(con)?;
        tls_inspect::register_all(con)?;
        whois::register_all(con)?;
        webdav::register_all(con)?;
        odata::register_all(con)?;
        ldap::register_all(con)?;
        jsonrpc::register_all(con)?;

        // Tier 2: Strong value
        imap::register_all(con)?;
        snmp::register_all(con)?;
        ping::register_all(con)?;

        // Tier 3: Niche but valid
        ntp::register_all(con)?;
        sip::register_all(con)?;
        caldav::register_all(con)?;
        syslog::register_all(con)?;
        aws_sigv4::register_all(con)?;
        amqp::register_all(con)?;
        kafka::register_all(con)?;

        // New Tier 1: High Impact
        ssh::register_all(con)?;
        redis_client::register_all(con)?;
        grpc::register_all(con)?;
        websocket::register_all(con)?;

        // New Tier 2: Infrastructure
        mqtt::register_all(con)?;
        memcached::register_all(con)?;
        prometheus::register_all(con)?;
        elasticsearch::register_all(con)?;

        // New Tier 3: Niche but Clean Fits
        radius::register_all(con)?;
        doh::register_all(con)?;
        mdns::register_all(con)?;
        stun::register_all(con)?;
        bgp::register_all(con)?;

        // Precision Time
        ptp::register_all(con)?;

        // Certificate revocation: OCSP
        ocsp::register_all(con)?;

        // S3-compatible storage
        s3::register_all(con)?;

        // Time-series: InfluxDB
        influxdb::register_all(con)?;

        // Service discovery & config: Consul/etcd
        consul::register_all(con)?;

        // Cloud-native messaging: NATS, ZeroMQ
        nats::register_all(con)?;
        zeromq::register_all(con)?;

        // Secrets: Vault
        vault::register_all(con)?;

        // Hardware: IPMI
        ipmi::register_all(con)?;

        // Security: Secrets manager + hardening configuration
        secrets::register_all(con)?;

        // Security warnings subsystem
        security_warnings::register_all(con)?;

        // DuckDB secrets manager bridge
        duckdb_secrets_bridge::register_all(con)?;

        // Configuration: TLS / rate-limiting / retry / timeout
        scalars_config::register_all(con)?;

        // OAuth2 client credentials
        oauth2::register_all(con)?;
    }
    Ok(())
}
