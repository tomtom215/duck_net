// SPDX-License-Identifier: MIT
// Copyright 2026 Tom F. <tomf@tomtomtech.net> (https://github.com/tomtom215)

#[path = "ldap_write_async.rs"]
mod ldap_write_async;

use crate::ldap::parse_ldap_url;
use crate::runtime;

/// Result of an LDAP write operation (add, modify, delete).
pub struct LdapWriteResult {
    pub success: bool,
    pub message: String,
}

/// Validate common parameters for LDAP write operations.
fn validate_write_params(
    url: &str,
    bind_dn: &str,
    password: &str,
    entry_dn: &str,
) -> Option<LdapWriteResult> {
    if bind_dn.is_empty() {
        return Some(LdapWriteResult {
            success: false,
            message: "bind_dn must not be empty".to_string(),
        });
    }
    if password.is_empty() {
        return Some(LdapWriteResult {
            success: false,
            message: "password must not be empty".to_string(),
        });
    }
    if entry_dn.is_empty() {
        return Some(LdapWriteResult {
            success: false,
            message: "entry_dn must not be empty".to_string(),
        });
    }
    let lower = url.to_ascii_lowercase();
    if !lower.starts_with("ldap://") && !lower.starts_with("ldaps://") {
        return Some(LdapWriteResult {
            success: false,
            message: format!(
                "Invalid LDAP URL scheme: expected ldap:// or ldaps://, got: {}",
                url.split("://").next().unwrap_or("(none)")
            ),
        });
    }
    None
}

/// Parse the attributes string for an LDAP add operation.
///
/// Format: `attr1=val1,attr2=val2,objectClass=top;person;inetOrgPerson`
/// Multiple values for an attribute are separated by semicolons.
fn parse_add_attributes(input: &str) -> Result<Vec<(String, Vec<String>)>, String> {
    if input.is_empty() {
        return Err("attributes string must not be empty".to_string());
    }

    let mut attrs: Vec<(String, Vec<String>)> = Vec::new();

    for pair in input.split(',') {
        let pair = pair.trim();
        if pair.is_empty() {
            continue;
        }
        let (key, value_part) = pair
            .split_once('=')
            .ok_or_else(|| format!("Invalid attribute pair (missing '='): {pair}"))?;
        let key = key.trim();
        if key.is_empty() {
            return Err(format!("Empty attribute name in pair: {pair}"));
        }
        let values: Vec<String> = value_part
            .split(';')
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty())
            .collect();
        if values.is_empty() {
            return Err(format!("No values for attribute: {key}"));
        }
        attrs.push((key.to_string(), values));
    }

    if attrs.is_empty() {
        return Err("No attributes parsed from input".to_string());
    }

    Ok(attrs)
}

/// Add a new entry to the LDAP directory.
///
/// `attributes` format: `attr1=val1,attr2=val2,objectClass=top;person;inetOrgPerson`
/// Multiple values for an attribute are separated by semicolons.
pub fn add(
    url: &str,
    bind_dn: &str,
    password: &str,
    entry_dn: &str,
    attributes: &str,
) -> LdapWriteResult {
    if let Some(err) = validate_write_params(url, bind_dn, password, entry_dn) {
        return err;
    }

    let parsed_attrs = match parse_add_attributes(attributes) {
        Ok(a) => a,
        Err(e) => {
            return LdapWriteResult {
                success: false,
                message: format!("Failed to parse attributes: {e}"),
            }
        }
    };

    let (host, port, use_tls) = match parse_ldap_url(url) {
        Ok(v) => v,
        Err(e) => {
            return LdapWriteResult {
                success: false,
                message: e,
            }
        }
    };

    runtime::block_on(async {
        ldap_write_async::add_async(
            &host,
            port,
            use_tls,
            bind_dn,
            password,
            entry_dn,
            &parsed_attrs,
        )
        .await
    })
}

/// Modify an existing LDAP entry.
///
/// `modifications` format: `replace:attr=value,add:attr=value,delete:attr`
/// Each modification is `operation:attribute=value` where operation is add, replace, or delete.
/// Multiple values for a single modification can be separated by semicolons.
pub fn modify(
    url: &str,
    bind_dn: &str,
    password: &str,
    entry_dn: &str,
    modifications: &str,
) -> LdapWriteResult {
    if let Some(err) = validate_write_params(url, bind_dn, password, entry_dn) {
        return err;
    }

    let parsed_mods = match ldap_write_async::parse_modifications(modifications) {
        Ok(m) => m,
        Err(e) => {
            return LdapWriteResult {
                success: false,
                message: format!("Failed to parse modifications: {e}"),
            }
        }
    };

    let (host, port, use_tls) = match parse_ldap_url(url) {
        Ok(v) => v,
        Err(e) => {
            return LdapWriteResult {
                success: false,
                message: e,
            }
        }
    };

    runtime::block_on(async {
        ldap_write_async::modify_async(
            &host,
            port,
            use_tls,
            bind_dn,
            password,
            entry_dn,
            &parsed_mods,
        )
        .await
    })
}

/// Delete an entry from the LDAP directory.
pub fn delete(url: &str, bind_dn: &str, password: &str, entry_dn: &str) -> LdapWriteResult {
    if let Some(err) = validate_write_params(url, bind_dn, password, entry_dn) {
        return err;
    }

    let (host, port, use_tls) = match parse_ldap_url(url) {
        Ok(v) => v,
        Err(e) => {
            return LdapWriteResult {
                success: false,
                message: e,
            }
        }
    };

    runtime::block_on(async {
        ldap_write_async::delete_async(&host, port, use_tls, bind_dn, password, entry_dn).await
    })
}
