// SPDX-License-Identifier: MIT
// Copyright 2026 Tom F. <tomf@tomtomtech.net> (https://github.com/tomtom215)

mod amqp;
mod aws_sigv4;
mod bgp;
mod caldav;
mod dns;
mod doh;
mod elasticsearch;
mod ffi;
mod ftp;
mod ftp_cache;
mod graphql;
mod grpc;
mod http;
mod imap;
mod json;
mod jsonrpc;
mod kafka;
mod ldap;
mod mdns;
mod memcached;
mod mqtt;
mod ntp;
mod odata;
mod pagination;
mod ping;
mod prometheus;
mod radius;
mod rate_limit;
mod redis_client;
mod runtime;
mod sftp;
mod sip;
mod smtp;
mod snmp;
mod soap;
mod ssh;
mod stun;
mod syslog;
mod tls_inspect;
mod webdav;
mod websocket;
mod whois;

quack_rs::entry_point_v2!(duck_net_init_c_api, |con| { ffi::register_all(con) });
