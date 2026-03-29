// SPDX-License-Identifier: MIT
// Copyright 2026 Tom F. <tomf@tomtomtech.net> (https://github.com/tomtom215)

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

/// Parse the modifications string for an LDAP modify operation.
///
/// Format: `replace:attr=value,add:attr=value,delete:attr`
/// Each modification is `operation:attribute=value` (value is optional for delete).
fn parse_modifications(input: &str) -> Result<Vec<(String, String, Vec<String>)>, String> {
    if input.is_empty() {
        return Err("modifications string must not be empty".to_string());
    }

    let mut mods: Vec<(String, String, Vec<String>)> = Vec::new();

    for item in input.split(',') {
        let item = item.trim();
        if item.is_empty() {
            continue;
        }
        let (op, rest) = item
            .split_once(':')
            .ok_or_else(|| format!("Invalid modification (missing ':'): {item}"))?;
        let op = op.trim().to_ascii_lowercase();
        match op.as_str() {
            "add" | "replace" | "delete" => {}
            _ => return Err(format!("Unknown modification operation: {op}")),
        }
        let rest = rest.trim();
        if let Some((attr, value)) = rest.split_once('=') {
            let attr = attr.trim();
            if attr.is_empty() {
                return Err(format!("Empty attribute name in modification: {item}"));
            }
            let values: Vec<String> = value
                .split(';')
                .map(|v| v.trim().to_string())
                .filter(|v| !v.is_empty())
                .collect();
            mods.push((op, attr.to_string(), values));
        } else {
            // No '=' — valid only for delete (remove entire attribute)
            let attr = rest;
            if attr.is_empty() {
                return Err(format!("Empty attribute name in modification: {item}"));
            }
            if op != "delete" {
                return Err(format!(
                    "Modification '{op}' requires a value (attr=value): {item}"
                ));
            }
            mods.push((op, attr.to_string(), vec![]));
        }
    }

    if mods.is_empty() {
        return Err("No modifications parsed from input".to_string());
    }

    Ok(mods)
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
        add_async(
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

async fn add_async(
    host: &str,
    port: u16,
    use_tls: bool,
    bind_dn: &str,
    password: &str,
    entry_dn: &str,
    attributes: &[(String, Vec<String>)],
) -> LdapWriteResult {
    use ldap3::LdapConnAsync;
    use std::collections::HashSet;

    // SSRF protection (CWE-918)
    if let Err(e) = crate::security::validate_no_ssrf_host(host) {
        return LdapWriteResult {
            success: false,
            message: e,
        };
    }

    let url = if use_tls {
        format!("ldaps://{}:{}", host, port)
    } else {
        format!("ldap://{}:{}", host, port)
    };

    let (conn, mut ldap) = match LdapConnAsync::new(&url).await {
        Ok(v) => v,
        Err(e) => {
            return LdapWriteResult {
                success: false,
                message: format!("LDAP connection failed: {e}"),
            }
        }
    };

    tokio::spawn(async move {
        if let Err(e) = conn.drive().await {
            eprintln!("LDAP connection error: {e}");
        }
    });

    // Bind with credentials
    match ldap.simple_bind(bind_dn, password).await {
        Ok(result) => {
            if let Err(e) = result.success() {
                let _ = ldap.unbind().await;
                return LdapWriteResult {
                    success: false,
                    message: format!("Bind failed: {e}"),
                };
            }
        }
        Err(e) => {
            let _ = ldap.unbind().await;
            return LdapWriteResult {
                success: false,
                message: format!("Bind failed: {e}"),
            };
        }
    }

    // Build attribute list as Vec<(&str, HashSet<&str>)>
    let attr_sets: Vec<(&str, HashSet<&str>)> = attributes
        .iter()
        .map(|(name, values)| {
            let set: HashSet<&str> = values.iter().map(|v| v.as_str()).collect();
            (name.as_str(), set)
        })
        .collect();

    match ldap.add(entry_dn, attr_sets).await {
        Ok(result) => {
            let _ = ldap.unbind().await;
            match result.success() {
                Ok(_) => LdapWriteResult {
                    success: true,
                    message: format!("Entry '{}' added successfully", entry_dn),
                },
                Err(e) => LdapWriteResult {
                    success: false,
                    message: format!("LDAP add failed: {e}"),
                },
            }
        }
        Err(e) => {
            let _ = ldap.unbind().await;
            LdapWriteResult {
                success: false,
                message: format!("LDAP add failed: {e}"),
            }
        }
    }
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

    let parsed_mods = match parse_modifications(modifications) {
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
        modify_async(
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

async fn modify_async(
    host: &str,
    port: u16,
    use_tls: bool,
    bind_dn: &str,
    password: &str,
    entry_dn: &str,
    modifications: &[(String, String, Vec<String>)],
) -> LdapWriteResult {
    use ldap3::{LdapConnAsync, Mod};
    use std::collections::HashSet;

    // SSRF protection (CWE-918)
    if let Err(e) = crate::security::validate_no_ssrf_host(host) {
        return LdapWriteResult {
            success: false,
            message: e,
        };
    }

    let url = if use_tls {
        format!("ldaps://{}:{}", host, port)
    } else {
        format!("ldap://{}:{}", host, port)
    };

    let (conn, mut ldap) = match LdapConnAsync::new(&url).await {
        Ok(v) => v,
        Err(e) => {
            return LdapWriteResult {
                success: false,
                message: format!("LDAP connection failed: {e}"),
            }
        }
    };

    tokio::spawn(async move {
        if let Err(e) = conn.drive().await {
            eprintln!("LDAP connection error: {e}");
        }
    });

    // Bind with credentials
    match ldap.simple_bind(bind_dn, password).await {
        Ok(result) => {
            if let Err(e) = result.success() {
                let _ = ldap.unbind().await;
                return LdapWriteResult {
                    success: false,
                    message: format!("Bind failed: {e}"),
                };
            }
        }
        Err(e) => {
            let _ = ldap.unbind().await;
            return LdapWriteResult {
                success: false,
                message: format!("Bind failed: {e}"),
            };
        }
    }

    // Build modification list
    let mods: Vec<Mod<&str>> = modifications
        .iter()
        .map(|(op, attr, values)| {
            let value_set: HashSet<&str> = values.iter().map(|v| v.as_str()).collect();
            match op.as_str() {
                "add" => Mod::Add(attr.as_str(), value_set),
                "replace" => Mod::Replace(attr.as_str(), value_set),
                "delete" => Mod::Delete(attr.as_str(), value_set),
                _ => unreachable!(), // validated in parse_modifications
            }
        })
        .collect();

    match ldap.modify(entry_dn, mods).await {
        Ok(result) => {
            let _ = ldap.unbind().await;
            match result.success() {
                Ok(_) => LdapWriteResult {
                    success: true,
                    message: format!("Entry '{}' modified successfully", entry_dn),
                },
                Err(e) => LdapWriteResult {
                    success: false,
                    message: format!("LDAP modify failed: {e}"),
                },
            }
        }
        Err(e) => {
            let _ = ldap.unbind().await;
            LdapWriteResult {
                success: false,
                message: format!("LDAP modify failed: {e}"),
            }
        }
    }
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
        delete_async(&host, port, use_tls, bind_dn, password, entry_dn).await
    })
}

async fn delete_async(
    host: &str,
    port: u16,
    use_tls: bool,
    bind_dn: &str,
    password: &str,
    entry_dn: &str,
) -> LdapWriteResult {
    use ldap3::LdapConnAsync;

    // SSRF protection (CWE-918)
    if let Err(e) = crate::security::validate_no_ssrf_host(host) {
        return LdapWriteResult {
            success: false,
            message: e,
        };
    }

    let url = if use_tls {
        format!("ldaps://{}:{}", host, port)
    } else {
        format!("ldap://{}:{}", host, port)
    };

    let (conn, mut ldap) = match LdapConnAsync::new(&url).await {
        Ok(v) => v,
        Err(e) => {
            return LdapWriteResult {
                success: false,
                message: format!("LDAP connection failed: {e}"),
            }
        }
    };

    tokio::spawn(async move {
        if let Err(e) = conn.drive().await {
            eprintln!("LDAP connection error: {e}");
        }
    });

    // Bind with credentials
    match ldap.simple_bind(bind_dn, password).await {
        Ok(result) => {
            if let Err(e) = result.success() {
                let _ = ldap.unbind().await;
                return LdapWriteResult {
                    success: false,
                    message: format!("Bind failed: {e}"),
                };
            }
        }
        Err(e) => {
            let _ = ldap.unbind().await;
            return LdapWriteResult {
                success: false,
                message: format!("Bind failed: {e}"),
            };
        }
    }

    match ldap.delete(entry_dn).await {
        Ok(result) => {
            let _ = ldap.unbind().await;
            match result.success() {
                Ok(_) => LdapWriteResult {
                    success: true,
                    message: format!("Entry '{}' deleted successfully", entry_dn),
                },
                Err(e) => LdapWriteResult {
                    success: false,
                    message: format!("LDAP delete failed: {e}"),
                },
            }
        }
        Err(e) => {
            let _ = ldap.unbind().await;
            LdapWriteResult {
                success: false,
                message: format!("LDAP delete failed: {e}"),
            }
        }
    }
}
