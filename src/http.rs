use std::sync::LazyLock;
use std::time::Duration;
use ureq::Agent;

static AGENT: LazyLock<Agent> = LazyLock::new(|| {
    Agent::config_builder()
        .http_status_as_error(false)
        .timeout_global(Some(Duration::from_secs(30)))
        .build()
        .into()
});

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Method {
    Get = 0,
    Post = 1,
    Put = 2,
    Patch = 3,
    Delete = 4,
    Head = 5,
    Options = 6,
}

impl Method {
    pub fn from_str(s: &str) -> Option<Self> {
        if s.eq_ignore_ascii_case("GET") {
            Some(Self::Get)
        } else if s.eq_ignore_ascii_case("POST") {
            Some(Self::Post)
        } else if s.eq_ignore_ascii_case("PUT") {
            Some(Self::Put)
        } else if s.eq_ignore_ascii_case("PATCH") {
            Some(Self::Patch)
        } else if s.eq_ignore_ascii_case("DELETE") {
            Some(Self::Delete)
        } else if s.eq_ignore_ascii_case("HEAD") {
            Some(Self::Head)
        } else if s.eq_ignore_ascii_case("OPTIONS") {
            Some(Self::Options)
        } else {
            None
        }
    }
}

pub struct HttpResponse {
    pub status: u16,
    pub reason: String,
    pub headers: Vec<(String, String)>,
    pub body: String,
}

pub fn execute(
    method: Method,
    url: &str,
    headers: &[(String, String)],
    body: Option<&str>,
) -> HttpResponse {
    match execute_inner(method, url, headers, body) {
        Ok(resp) => resp,
        Err(e) => HttpResponse {
            status: 0,
            reason: format!("Request failed: {e}"),
            headers: vec![],
            body: String::new(),
        },
    }
}

fn execute_inner(
    method: Method,
    url: &str,
    headers: &[(String, String)],
    body: Option<&str>,
) -> Result<HttpResponse, ureq::Error> {
    // ureq 3.x uses typed builders: WithBody vs WithoutBody.
    // We dispatch based on whether the method carries a body.
    let mut response = match method {
        Method::Post | Method::Put | Method::Patch => {
            let mut b = match method {
                Method::Post => AGENT.post(url),
                Method::Put => AGENT.put(url),
                _ => AGENT.patch(url),
            };
            for (key, value) in headers {
                b = b.header(key.as_str(), value.as_str());
            }
            b.send(body.unwrap_or(""))?
        }
        _ => {
            let mut b = match method {
                Method::Get => AGENT.get(url),
                Method::Delete => AGENT.delete(url),
                Method::Head => AGENT.head(url),
                _ => AGENT.options(url),
            };
            for (key, value) in headers {
                b = b.header(key.as_str(), value.as_str());
            }
            b.call()?
        }
    };

    let status = response.status().as_u16();
    let reason = response
        .status()
        .canonical_reason()
        .unwrap_or("")
        .to_string();

    let resp_headers: Vec<(String, String)> = response
        .headers()
        .iter()
        .map(|(name, value)| {
            let (name, value): (&ureq::http::HeaderName, &ureq::http::HeaderValue) = (name, value);
            (
                name.as_str().to_string(),
                value.to_str().unwrap_or("").to_string(),
            )
        })
        .collect();

    let resp_body = match method {
        Method::Head => String::new(),
        _ => response.body_mut().read_to_string().unwrap_or_default(),
    };

    Ok(HttpResponse {
        status,
        reason,
        headers: resp_headers,
        body: resp_body,
    })
}

// ===== Multipart/Form-Data =====

pub fn execute_multipart(
    url: &str,
    headers: &[(String, String)],
    form_fields: &[(String, String)],
    file_fields: &[(String, String)],
) -> HttpResponse {
    match execute_multipart_inner(url, headers, form_fields, file_fields) {
        Ok(resp) => resp,
        Err(msg) => HttpResponse {
            status: 0,
            reason: msg,
            headers: vec![],
            body: String::new(),
        },
    }
}

fn execute_multipart_inner(
    url: &str,
    headers: &[(String, String)],
    form_fields: &[(String, String)],
    file_fields: &[(String, String)],
) -> Result<HttpResponse, String> {
    use ureq::unversioned::multipart::Form;

    let mut form = Form::new();

    for (name, value) in form_fields {
        form = form.text(name.as_str(), value.as_str());
    }

    for (name, path) in file_fields {
        form = form
            .file(name.as_str(), path.as_str())
            .map_err(|e| format!("Failed to read file '{path}': {e}"))?;
    }

    let mut builder = AGENT.post(url);
    for (key, value) in headers {
        builder = builder.header(key.as_str(), value.as_str());
    }

    let mut response = builder.send(form).map_err(|e| format!("Request failed: {e}"))?;

    let status = response.status().as_u16();
    let reason = response
        .status()
        .canonical_reason()
        .unwrap_or("")
        .to_string();

    let resp_headers: Vec<(String, String)> = response
        .headers()
        .iter()
        .map(|(name, value)| {
            let (name, value): (&ureq::http::HeaderName, &ureq::http::HeaderValue) = (name, value);
            (
                name.as_str().to_string(),
                value.to_str().unwrap_or("").to_string(),
            )
        })
        .collect();

    let resp_body = response.body_mut().read_to_string().unwrap_or_default();

    Ok(HttpResponse {
        status,
        reason,
        headers: resp_headers,
        body: resp_body,
    })
}
