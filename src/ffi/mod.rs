mod amqp;
mod aws_sigv4;
mod caldav;
pub(crate) mod dns;
mod ftp;
mod graphql;
mod imap;
mod jsonrpc;
mod kafka;
mod ldap;
mod ntp;
mod odata;
mod ping;
pub(crate) mod scalars;
mod sip;
mod smtp;
mod snmp;
mod soap;
mod syslog;
mod table;
mod tls_inspect;
mod webdav;
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
    }
    Ok(())
}
