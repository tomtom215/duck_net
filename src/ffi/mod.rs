// SPDX-License-Identifier: MIT
// Copyright 2026 Tom F. <tomf@tomtomtech.net> (https://github.com/tomtom215)

mod amqp;
mod aws_sigv4;
mod bgp;
mod caldav;
pub(crate) mod dns;
mod doh;
mod elasticsearch;
mod ftp;
mod graphql;
mod grpc;
mod imap;
mod jsonrpc;
mod kafka;
mod ldap;
mod mdns;
mod memcached;
mod mqtt;
mod ntp;
mod odata;
mod ping;
mod prometheus;
mod radius;
mod redis_client;
pub(crate) mod scalars;
mod sip;
mod smtp;
mod snmp;
mod soap;
mod ssh;
mod stun;
mod syslog;
mod table;
mod tls_inspect;
mod webdav;
mod websocket;
mod whois;

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
    }
    Ok(())
}
