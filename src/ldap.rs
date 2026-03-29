// SPDX-License-Identifier: MIT
// Copyright 2026 Tom F. <tomf@tomtomtech.net> (https://github.com/tomtom215)

use crate::runtime;

/// An LDAP search result entry.
pub struct LdapEntry {
    pub dn: String,
    pub attributes: Vec<(String, Vec<String>)>,
}

/// An LDAP search result.
pub struct LdapSearchResult {
    pub success: bool,
    pub entries: Vec<LdapEntry>,
    pub message: String,
}

/// An LDAP bind (authentication) result.
pub struct LdapBindResult {
    pub success: bool,
    pub message: String,
}

/// Parse an LDAP URL into (host, port, use_tls).
fn parse_ldap_url(url: &str) -> Result<(String, u16, bool), String> {
    let lower = url.to_ascii_lowercase();
    let (use_tls, rest) = if lower.strip_prefix("ldaps://").is_some() {
        (true, &url[8..])
    } else if lower.strip_prefix("ldap://").is_some() {
        (false, &url[7..])
    } else {
        return Err(format!(
            "Invalid LDAP URL scheme: expected ldap:// or ldaps://, got: {}",
            url.split("://").next().unwrap_or("(none)")
        ));
    };

    let host_port = rest.split('/').next().unwrap_or(rest);
    let (host, port) = if let Some((h, p)) = host_port.rsplit_once(':') {
        let port = p
            .parse::<u16>()
            .map_err(|e| format!("Invalid LDAP port: {e}"))?;
        (h.to_string(), port)
    } else {
        let default_port = if use_tls { 636 } else { 389 };
        (host_port.to_string(), default_port)
    };

    Ok((host, port, use_tls))
}

/// Search LDAP directory.
pub fn search(url: &str, base_dn: &str, filter: &str, attributes: &[&str]) -> LdapSearchResult {
    let (host, port, use_tls) = match parse_ldap_url(url) {
        Ok(v) => v,
        Err(e) => {
            return LdapSearchResult {
                success: false,
                entries: vec![],
                message: e,
            }
        }
    };

    runtime::block_on(async {
        search_async(&host, port, use_tls, base_dn, filter, attributes).await
    })
}

async fn search_async(
    host: &str,
    port: u16,
    use_tls: bool,
    base_dn: &str,
    filter: &str,
    attributes: &[&str],
) -> LdapSearchResult {
    use ldap3::{LdapConnAsync, Scope, SearchEntry};

    let url = if use_tls {
        format!("ldaps://{}:{}", host, port)
    } else {
        format!("ldap://{}:{}", host, port)
    };

    let (conn, mut ldap) = match LdapConnAsync::new(&url).await {
        Ok(v) => v,
        Err(e) => {
            return LdapSearchResult {
                success: false,
                entries: vec![],
                message: format!("LDAP connection failed: {e}"),
            }
        }
    };

    // Drive the connection in the background
    tokio::spawn(async move {
        if let Err(e) = conn.drive().await {
            eprintln!("LDAP connection error: {e}");
        }
    });

    let attr_vec: Vec<&str> = attributes.to_vec();

    let result = match ldap.search(base_dn, Scope::Subtree, filter, attr_vec).await {
        Ok(r) => r,
        Err(e) => {
            let _ = ldap.unbind().await;
            return LdapSearchResult {
                success: false,
                entries: vec![],
                message: format!("LDAP search failed: {e}"),
            };
        }
    };

    let (entries, _result) = match result.success() {
        Ok(v) => v,
        Err(e) => {
            let _ = ldap.unbind().await;
            return LdapSearchResult {
                success: false,
                entries: vec![],
                message: format!("LDAP search error: {e}"),
            };
        }
    };

    let parsed: Vec<LdapEntry> = entries
        .into_iter()
        .map(|e| {
            let se = SearchEntry::construct(e);
            LdapEntry {
                dn: se.dn,
                attributes: se.attrs.into_iter().map(|(k, v)| (k, v)).collect(),
            }
        })
        .collect();

    let count = parsed.len();
    let _ = ldap.unbind().await;

    LdapSearchResult {
        success: true,
        entries: parsed,
        message: format!("Found {count} entries"),
    }
}

/// Test LDAP bind (authentication).
pub fn bind(url: &str, bind_dn: &str, password: &str) -> LdapBindResult {
    let (host, port, use_tls) = match parse_ldap_url(url) {
        Ok(v) => v,
        Err(e) => {
            return LdapBindResult {
                success: false,
                message: e,
            }
        }
    };

    runtime::block_on(async { bind_async(&host, port, use_tls, bind_dn, password).await })
}

async fn bind_async(
    host: &str,
    port: u16,
    use_tls: bool,
    bind_dn: &str,
    password: &str,
) -> LdapBindResult {
    use ldap3::LdapConnAsync;

    let url = if use_tls {
        format!("ldaps://{}:{}", host, port)
    } else {
        format!("ldap://{}:{}", host, port)
    };

    let (conn, mut ldap) = match LdapConnAsync::new(&url).await {
        Ok(v) => v,
        Err(e) => {
            return LdapBindResult {
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

    match ldap.simple_bind(bind_dn, password).await {
        Ok(result) => {
            let _ = ldap.unbind().await;
            match result.success() {
                Ok(_) => LdapBindResult {
                    success: true,
                    message: "Bind successful".to_string(),
                },
                Err(e) => LdapBindResult {
                    success: false,
                    message: format!("Bind failed: {e}"),
                },
            }
        }
        Err(e) => {
            let _ = ldap.unbind().await;
            LdapBindResult {
                success: false,
                message: format!("Bind failed: {e}"),
            }
        }
    }
}
