// SPDX-License-Identifier: MIT
// Copyright 2026 Tom F. <tomf@tomtomtech.net> (https://github.com/tomtom215)

use std::io::{BufRead, BufReader, Write};
use std::net::TcpStream;
use std::time::Duration;

pub struct SmtpResult {
    pub success: bool,
    pub message: String,
}

pub struct SmtpConfig {
    pub host: String,
    pub port: u16,
    pub use_tls: bool,
    pub from: String,
    pub to: String,
    pub subject: String,
    pub body: String,
    pub username: Option<String>,
    pub password: Option<String>,
}

/// Parse an SMTP server URL: smtp://host:port or smtps://host:port
pub fn parse_server_url(url: &str) -> Result<(String, u16, bool), String> {
    let (scheme, rest) = if let Some(r) = url.strip_prefix("smtps://") {
        (true, r)
    } else if let Some(r) = url.strip_prefix("smtp://") {
        (false, r)
    } else {
        return Err("Invalid SMTP URL: must start with smtp:// or smtps://".into());
    };

    let (host, port) = if let Some(colon) = rest.rfind(':') {
        let port_str = &rest[colon + 1..].trim_end_matches('/');
        let port: u16 = port_str
            .parse()
            .map_err(|_| format!("Invalid port: {port_str}"))?;
        (rest[..colon].to_string(), port)
    } else {
        let default_port = if scheme { 465 } else { 587 };
        (rest.trim_end_matches('/').to_string(), default_port)
    };

    Ok((host, port, scheme))
}

/// Sanitize a string for SMTP to prevent CRLF injection (CWE-93).
fn sanitize_header(s: &str) -> String {
    s.replace('\r', "").replace('\n', " ")
}

/// Dot-stuff the message body per RFC 5321 section 4.5.2.
fn dot_stuff(body: &str) -> String {
    let mut out = String::with_capacity(body.len() + 64);
    for line in body.split('\n') {
        let line = line.trim_end_matches('\r');
        if line.starts_with('.') {
            out.push('.');
        }
        out.push_str(line);
        out.push_str("\r\n");
    }
    out
}

pub fn send(config: &SmtpConfig) -> SmtpResult {
    match send_inner(config) {
        Ok(msg) => SmtpResult {
            success: true,
            message: msg,
        },
        Err(msg) => SmtpResult {
            success: false,
            message: msg,
        },
    }
}

fn send_inner(config: &SmtpConfig) -> Result<String, String> {
    // SSRF protection: block connections to private/reserved IPs (CWE-918)
    crate::security::validate_no_ssrf_host(&config.host)?;

    // Rate limiting: apply per-host token bucket (honours global + per-domain config)
    crate::rate_limit::acquire_for_host(&config.host);

    let addr = format!("{}:{}", config.host, config.port);
    let stream = TcpStream::connect_timeout(
        &addr
            .parse()
            .map_err(|e| format!("Invalid address {addr}: {e}"))?,
        Duration::from_secs(10),
    )
    .map_err(|e| format!("Connection failed to {addr}: {e}"))?;

    // Post-connect SSRF check: validate actual peer IP to prevent DNS rebinding (CWE-918)
    crate::security::validate_tcp_peer(&stream)?;

    stream
        .set_read_timeout(Some(Duration::from_secs(15)))
        .map_err(|e| format!("Set timeout failed: {e}"))?;
    stream
        .set_write_timeout(Some(Duration::from_secs(15)))
        .map_err(|e| format!("Set timeout failed: {e}"))?;

    if config.use_tls {
        // Direct TLS (SMTPS on port 465)
        send_over_tls(config, stream)
    } else {
        // STARTTLS upgrade (port 587)
        send_with_starttls(config, stream)
    }
}

fn send_with_starttls(config: &SmtpConfig, stream: TcpStream) -> Result<String, String> {
    let mut reader = BufReader::new(stream.try_clone().map_err(|e| e.to_string())?);
    let mut writer = stream;

    // Read greeting
    let greeting = read_response(&mut reader)?;
    expect_code(&greeting, 220)?;

    // EHLO
    write_cmd(&mut writer, "EHLO duck_net\r\n")?;
    let ehlo_resp = read_response(&mut reader)?;
    expect_code(&ehlo_resp, 250)?;

    // Check if STARTTLS is advertised
    let supports_starttls = ehlo_resp.to_uppercase().contains("STARTTLS");

    if supports_starttls {
        write_cmd(&mut writer, "STARTTLS\r\n")?;
        let tls_resp = read_response(&mut reader)?;
        expect_code(&tls_resp, 220)?;

        // Upgrade to TLS
        return send_over_tls(config, writer);
    }

    // Refuse plaintext AUTH: if credentials are provided but STARTTLS is not
    // available, abort to prevent sending credentials in cleartext (CWE-319).
    if config.username.is_some() && config.password.is_some() {
        return Err(
            "SMTP server does not support STARTTLS; refusing to send credentials in plaintext. \
             Use smtps:// (direct TLS on port 465) or configure the server for STARTTLS."
                .to_string(),
        );
    }

    // Continue in plaintext (no auth needed)
    send_mail_commands(&mut reader, &mut writer, config)
}

fn send_over_tls(config: &SmtpConfig, stream: TcpStream) -> Result<String, String> {
    use rustls::pki_types::ServerName;
    use std::sync::Arc;

    let root_store =
        rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let tls_config = rustls::ClientConfig::builder_with_protocol_versions(&[
        &rustls::version::TLS12,
        &rustls::version::TLS13,
    ])
    .with_root_certificates(root_store)
    .with_no_client_auth();

    let server_name = ServerName::try_from(config.host.clone())
        .map_err(|e| format!("Invalid server name: {e}"))?;

    let tls_conn = rustls::ClientConnection::new(Arc::new(tls_config), server_name)
        .map_err(|e| format!("TLS init failed: {e}"))?;

    let mut tls_stream = rustls::StreamOwned::new(tls_conn, stream);

    // Read greeting
    let mut buf_reader = BufReader::new(&mut tls_stream);
    let greeting = read_response_generic(&mut buf_reader)?;
    // For STARTTLS upgrade, we may not get a new greeting
    if !greeting.is_empty() {
        expect_code(&greeting, 220).ok(); // Ignore if no greeting (STARTTLS case)
    }

    // Use a line-based approach over TLS
    drop(buf_reader);

    // EHLO
    tls_stream
        .write_all(b"EHLO duck_net\r\n")
        .map_err(|e| format!("Write failed: {e}"))?;
    tls_stream
        .flush()
        .map_err(|e| format!("Flush failed: {e}"))?;

    let mut buf_reader = BufReader::new(&mut tls_stream);
    let ehlo_resp = read_response_generic(&mut buf_reader)?;
    expect_code(&ehlo_resp, 250)?;
    drop(buf_reader);

    // AUTH if credentials provided
    if let (Some(user), Some(pass)) = (&config.username, &config.password) {
        let auth_str = format!("\x00{user}\x00{pass}");
        let encoded = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            auth_str.as_bytes(),
        );
        let auth_cmd = format!("AUTH PLAIN {encoded}\r\n");
        tls_stream
            .write_all(auth_cmd.as_bytes())
            .map_err(|e| format!("Write failed: {e}"))?;
        tls_stream
            .flush()
            .map_err(|e| format!("Flush failed: {e}"))?;

        let mut buf_reader = BufReader::new(&mut tls_stream);
        let auth_resp = read_response_generic(&mut buf_reader)?;
        expect_code(&auth_resp, 235)?;
        drop(buf_reader);
    }

    // MAIL FROM
    let from_cmd = format!("MAIL FROM:<{}>\r\n", sanitize_header(&config.from));
    tls_stream
        .write_all(from_cmd.as_bytes())
        .map_err(|e| format!("Write failed: {e}"))?;
    tls_stream
        .flush()
        .map_err(|e| format!("Flush failed: {e}"))?;
    let mut buf_reader = BufReader::new(&mut tls_stream);
    let from_resp = read_response_generic(&mut buf_reader)?;
    expect_code(&from_resp, 250)?;
    drop(buf_reader);

    // RCPT TO
    let to_cmd = format!("RCPT TO:<{}>\r\n", sanitize_header(&config.to));
    tls_stream
        .write_all(to_cmd.as_bytes())
        .map_err(|e| format!("Write failed: {e}"))?;
    tls_stream
        .flush()
        .map_err(|e| format!("Flush failed: {e}"))?;
    let mut buf_reader = BufReader::new(&mut tls_stream);
    let to_resp = read_response_generic(&mut buf_reader)?;
    expect_code(&to_resp, 250)?;
    drop(buf_reader);

    // DATA
    tls_stream
        .write_all(b"DATA\r\n")
        .map_err(|e| format!("Write failed: {e}"))?;
    tls_stream
        .flush()
        .map_err(|e| format!("Flush failed: {e}"))?;
    let mut buf_reader = BufReader::new(&mut tls_stream);
    let data_resp = read_response_generic(&mut buf_reader)?;
    expect_code(&data_resp, 354)?;
    drop(buf_reader);

    // Send message
    let message = format!(
        "From: {}\r\nTo: {}\r\nSubject: {}\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n{}",
        sanitize_header(&config.from),
        sanitize_header(&config.to),
        sanitize_header(&config.subject),
        dot_stuff(&config.body),
    );
    tls_stream
        .write_all(message.as_bytes())
        .map_err(|e| format!("Write failed: {e}"))?;
    tls_stream
        .write_all(b"\r\n.\r\n")
        .map_err(|e| format!("Write failed: {e}"))?;
    tls_stream
        .flush()
        .map_err(|e| format!("Flush failed: {e}"))?;

    let mut buf_reader = BufReader::new(&mut tls_stream);
    let send_resp = read_response_generic(&mut buf_reader)?;
    expect_code(&send_resp, 250)?;
    drop(buf_reader);

    // QUIT
    tls_stream
        .write_all(b"QUIT\r\n")
        .map_err(|e| format!("Write failed: {e}"))?;
    tls_stream.flush().ok();

    Ok(send_resp)
}

fn send_mail_commands<R: BufRead, W: Write>(
    reader: &mut R,
    writer: &mut W,
    config: &SmtpConfig,
) -> Result<String, String> {
    // AUTH if credentials provided
    if let (Some(user), Some(pass)) = (&config.username, &config.password) {
        let auth_str = format!("\x00{user}\x00{pass}");
        let encoded = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            auth_str.as_bytes(),
        );
        write_cmd(writer, &format!("AUTH PLAIN {encoded}\r\n"))?;
        let resp = read_response(reader)?;
        expect_code(&resp, 235)?;
    }

    // MAIL FROM
    write_cmd(
        writer,
        &format!("MAIL FROM:<{}>\r\n", sanitize_header(&config.from)),
    )?;
    let resp = read_response(reader)?;
    expect_code(&resp, 250)?;

    // RCPT TO
    write_cmd(
        writer,
        &format!("RCPT TO:<{}>\r\n", sanitize_header(&config.to)),
    )?;
    let resp = read_response(reader)?;
    expect_code(&resp, 250)?;

    // DATA
    write_cmd(writer, "DATA\r\n")?;
    let resp = read_response(reader)?;
    expect_code(&resp, 354)?;

    // Message content
    let message = format!(
        "From: {}\r\nTo: {}\r\nSubject: {}\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n{}",
        sanitize_header(&config.from),
        sanitize_header(&config.to),
        sanitize_header(&config.subject),
        dot_stuff(&config.body),
    );
    write_cmd(writer, &message)?;
    write_cmd(writer, "\r\n.\r\n")?;
    let resp = read_response(reader)?;
    expect_code(&resp, 250)?;

    // QUIT
    write_cmd(writer, "QUIT\r\n").ok();
    Ok(resp)
}

fn write_cmd<W: Write>(w: &mut W, cmd: &str) -> Result<(), String> {
    w.write_all(cmd.as_bytes())
        .map_err(|e| format!("Write failed: {e}"))?;
    w.flush().map_err(|e| format!("Flush failed: {e}"))
}

fn read_response<R: BufRead>(reader: &mut R) -> Result<String, String> {
    read_response_generic(reader)
}

fn read_response_generic<R: BufRead>(reader: &mut R) -> Result<String, String> {
    let mut full_response = String::new();
    loop {
        let mut line = String::new();
        reader
            .read_line(&mut line)
            .map_err(|e| format!("Read failed: {e}"))?;
        if line.is_empty() {
            break;
        }
        full_response.push_str(&line);
        // Multi-line: "250-..." continues, "250 ..." is last
        if line.len() >= 4 && line.as_bytes()[3] == b' ' {
            break;
        }
        if line.len() < 4 {
            break;
        }
    }
    Ok(full_response.trim_end().to_string())
}

fn expect_code(response: &str, expected: u16) -> Result<(), String> {
    let code_str = &response[..3.min(response.len())];
    let code: u16 = code_str.parse().unwrap_or(0);
    if code == expected {
        Ok(())
    } else {
        Err(format!("Expected SMTP {expected}, got: {response}"))
    }
}
