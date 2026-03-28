"""Comprehensive end-to-end test suite for duck_net DuckDB extension.

Covers all functions across HTTP, SOAP, DNS, SMTP, FTP, SFTP, auth,
rate limiting, retry, timeout, and pagination.
"""
import base64
import duckdb
import sys
import time

con = duckdb.connect(config={"allow_unsigned_extensions": "true"})
con.execute("LOAD 'target/release/duck_net.duckdb_extension'")
print("Extension loaded!")

passed = 0
failed = 0
skipped = 0

def check(name, condition, detail=""):
    global passed, failed
    if condition:
        passed += 1
        print(f"  [PASS] {name}")
    else:
        failed += 1
        print(f"  [FAIL] {name}: {detail}")

def skip(name, reason=""):
    global skipped
    skipped += 1
    print(f"  [SKIP] {name}: {reason}")

def fetch(sql):
    return con.execute(sql).fetchone()[0]

def fetch_all(sql):
    return con.execute(sql).fetchall()


# =====================================================
# 1. AUTH HELPERS
# =====================================================
print("\n--- 1. Auth Helper Tests ---")

r = fetch("SELECT http_basic_auth('user', 'pass')")
check("basic_auth standard", r == "Basic " + base64.b64encode(b"user:pass").decode())

r = fetch("SELECT http_basic_auth('', '')")
check("basic_auth empty", r == "Basic " + base64.b64encode(b":").decode())

r = fetch("SELECT http_basic_auth('user:colon', 'p@ss!')")
check("basic_auth special", r == "Basic " + base64.b64encode(b"user:colon:p@ss!").decode())

r = fetch("SELECT http_bearer_auth('tok123')")
check("bearer_auth", r == "Bearer tok123")

r = fetch("SELECT http_bearer_auth('')")
check("bearer_auth empty", r == "Bearer ")


# =====================================================
# 2. SSRF PROTECTION
# =====================================================
print("\n--- 2. SSRF Protection Tests ---")

for scheme in ["ftp", "file", "gopher", "javascript", "data", "ldap", "dict", "ssh"]:
    r = fetch(f"SELECT http_get('{scheme}://evil.com/x')")
    check(f"block {scheme}://", r["status"] == 0 and "only http://" in r["reason"])

r = fetch("SELECT http_request('INVALID', 'https://x.com', MAP{}, '')")
check("invalid method", r["status"] == 0 and "Unsupported" in r["reason"])


# =====================================================
# 3. SOAP OFFLINE
# =====================================================
print("\n--- 3. SOAP Tests ---")

# Extract body with multiple namespace prefixes
for prefix, open_ns, close_ns in [
    ("soap:", '<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">', '</soap:Envelope>'),
    ("SOAP-ENV:", '<SOAP-ENV:Envelope>', '</SOAP-ENV:Envelope>'),
    ("soapenv:", '<soapenv:Envelope>', '</soapenv:Envelope>'),
    ("s:", '<s:Envelope>', '</s:Envelope>'),
    ("S:", '<S:Envelope>', '</S:Envelope>'),
]:
    xml = f"""{open_ns}<{prefix}Body><R>OK</R></{prefix}Body>{close_ns}"""
    r = con.execute(f"SELECT soap_extract_body($1)", [xml]).fetchone()[0]
    check(f"extract_body {prefix}", r is not None and "<R>OK</R>" in r, f"got: {r}")

# Fault detection
r = fetch("SELECT soap_is_fault('<soap:Fault>err</soap:Fault>')")
check("is_fault true", r == True)

r = fetch("SELECT soap_is_fault('<Result>OK</Result>')")
check("is_fault false", r == False)

r = fetch("SELECT soap_fault_string('<soap:Fault><faultstring>Broken</faultstring></soap:Fault>')")
check("fault_string 1.1", r == "Broken")

xml12 = '<soap:Fault><soap:Reason><soap:Text xml:lang="en">Denied</soap:Text></soap:Reason></soap:Fault>'
r = con.execute("SELECT soap_fault_string($1)", [xml12]).fetchone()[0]
check("fault_string 1.2", r == "Denied")

r = fetch("SELECT soap_fault_string('<Result>OK</Result>')")
check("fault_string null", r is None)


# =====================================================
# 4. RATE LIMITING
# =====================================================
print("\n--- 4. Rate Limiting Tests ---")

r = fetch("SELECT duck_net_set_rate_limit(0)")
check("rate_limit disable", "disabled" in r.lower())

r = fetch("SELECT duck_net_set_rate_limit(100)")
check("rate_limit set", "100" in r)

con.execute("SELECT duck_net_set_rate_limit(0)")


# =====================================================
# 5. RETRY & TIMEOUT CONFIG
# =====================================================
print("\n--- 5. Retry & Timeout Config Tests ---")

r = fetch("SELECT duck_net_set_retries(3, 500)")
check("set_retries", "3" in r and "500" in r)

r = fetch("SELECT duck_net_set_retries(0, 1000)")
check("set_retries disable", "disabled" in r.lower())

r = fetch("SELECT duck_net_set_timeout(60)")
check("set_timeout", "60" in r)

r = fetch("SELECT duck_net_set_timeout(30)")
check("set_timeout restore", "30" in r)

# Configurable retry status codes
r = fetch("SELECT duck_net_set_retry_statuses('429,500,502,503,504')")
check("set_retry_statuses", "429" in r and "504" in r)

r = fetch("SELECT duck_net_set_retry_statuses('429,503')")
check("set_retry_statuses custom", "429" in r and "503" in r)

r = fetch("SELECT duck_net_set_retry_statuses('notanumber')")
check("set_retry_statuses invalid", "error" in r.lower())


# =====================================================
# 6. SMTP (URL parsing / error handling)
# =====================================================
print("\n--- 6. SMTP Tests ---")

r = fetch("SELECT smtp_send('smtp://localhost:9999', 'a@b.com', 'c@d.com', 'test', 'body')")
check("smtp struct type", isinstance(r, dict) and "success" in r and "message" in r)
check("smtp conn fail", r["success"] == False and len(r["message"]) > 0)

r = fetch("SELECT smtp_send('invalid://host', 'a@b.com', 'c@d.com', 'test', 'body')")
check("smtp bad scheme", r["success"] == False and "smtp://" in r["message"])

r = fetch("SELECT smtp_send('smtps://mail.invalid:465', 'a@b', 'c@d', 'subj', 'body', 'user', 'pass')")
check("smtp 7-param", isinstance(r, dict) and "success" in r)


# =====================================================
# 7. FTP/SFTP (struct types / error handling)
# =====================================================
print("\n--- 7. FTP/SFTP Tests ---")

r = fetch("SELECT ftp_read('ftp://nonexistent.invalid/file.txt')")
check("ftp_read struct", "success" in str(r) and "content" in str(r))
check("ftp_read fail", r["success"] == False)

r = fetch("SELECT ftp_write('ftp://nonexistent.invalid/f.txt', 'data')")
check("ftp_write struct", "success" in str(r) and "bytes_written" in str(r))
check("ftp_write fail", r["success"] == False)

r = fetch("SELECT ftp_delete('ftp://nonexistent.invalid/f.txt')")
check("ftp_delete struct", "success" in str(r) and "message" in str(r))
check("ftp_delete fail", r["success"] == False)

r = fetch("SELECT sftp_read('sftp://nonexistent.invalid/f.txt')")
check("sftp_read struct", "success" in str(r) and "content" in str(r))
check("sftp_read fail", r["success"] == False)

# SFTP with key_file overload
r = fetch("SELECT sftp_read('sftp://user@nonexistent.invalid/f.txt', '/nonexistent/key')")
check("sftp_read key overload", r["success"] == False)

r = fetch("SELECT sftp_write('sftp://nonexistent.invalid/f.txt', 'data')")
check("sftp_write fail", r["success"] == False)

r = fetch("SELECT sftp_delete('sftp://nonexistent.invalid/f.txt')")
check("sftp_delete fail", r["success"] == False)

# Credential scrubbing: verify passwords don't leak in FTP error messages
r = fetch("SELECT ftp_read('ftp://secretuser:secretpass@nonexistent.invalid/f.txt')")
check("ftp cred scrub", "secretpass" not in r.get("message", ""), f"leaked: {r.get('message','')[:80]}")


# =====================================================
# 7b. FTP/SFTP BLOB + LIST + CONNECTION CACHE
# =====================================================
print("\n--- 7b. FTP/SFTP Blob & List Tests ---")

# ftp_read_blob returns STRUCT with BLOB data field
r = fetch("SELECT ftp_read_blob('ftp://nonexistent.invalid/file.bin')")
check("ftp_read_blob struct", "success" in str(r) and "data" in str(r))
check("ftp_read_blob fail", r["success"] == False)

# sftp_read_blob returns STRUCT with BLOB data field
r = fetch("SELECT sftp_read_blob('sftp://nonexistent.invalid/file.bin')")
check("sftp_read_blob struct", "success" in str(r) and "data" in str(r))
check("sftp_read_blob fail", r["success"] == False)

# sftp_read_blob with key_file
r = fetch("SELECT sftp_read_blob('sftp://user@nonexistent.invalid/f.bin', '/no/key')")
check("sftp_read_blob key", r["success"] == False)

# ftp_list table function (will fail to connect but validates registration)
try:
    rows = fetch_all("SELECT * FROM ftp_list('ftp://nonexistent.invalid/')")
    check("ftp_list registered", False, "should have errored")
except Exception as e:
    check("ftp_list registered", "ftp" in str(e).lower() or "connection" in str(e).lower(),
          str(e)[:80])

# sftp_list table function
try:
    rows = fetch_all("SELECT * FROM sftp_list('sftp://nonexistent.invalid/')")
    check("sftp_list registered", False, "should have errored")
except Exception as e:
    check("sftp_list registered", "ssh" in str(e).lower() or "sftp" in str(e).lower()
          or "connection" in str(e).lower(), str(e)[:80])


# =====================================================
# 7c. OAuth2 WITH SCOPES
# =====================================================
print("\n--- 7c. OAuth2 Scopes Test ---")

# Verify 4-param overload exists (will fail at network level but validates registration)
r = fetch("""SELECT http_oauth2_token(
    'https://auth.invalid/token', 'id', 'secret', 'read write'
)""")
check("oauth2 scopes overload", isinstance(r, str) and "OAuth2" in r, f"got: {r}")


# =====================================================
# 7d. PER-DOMAIN RATE LIMITING
# =====================================================
print("\n--- 7d. Per-Domain Rate Limiting Tests ---")

# JSON format
r = fetch("""SELECT duck_net_set_domain_rate_limits('{"api.example.com": 10, "*.slow.com": 2}')""")
check("domain limits json", "2 domain" in r, f"got: {r}")

# Simple format
r = fetch("SELECT duck_net_set_domain_rate_limits('api.fast.com=50,api.slow.com=5')")
check("domain limits simple", "2 domain" in r, f"got: {r}")

# Clear
r = fetch("SELECT duck_net_set_domain_rate_limits('')")
check("domain limits clear", "cleared" in r.lower(), f"got: {r}")

# Invalid format
r = fetch("SELECT duck_net_set_domain_rate_limits('bad=notanumber')")
check("domain limits invalid", "error" in r.lower(), f"got: {r}")


# =====================================================
# 8. HTTP NETWORK TESTS
# =====================================================
print("\n--- 8. HTTP Network Tests ---")

r = fetch("SELECT http_get('https://httpbin.org/get')")
network_ok = r["status"] == 200

if not network_ok:
    for name in ["http_get","http_post","http_head","http_delete","http_put","http_patch",
                  "http_request","basic_auth_roundtrip","bearer_auth_roundtrip","pagination"]:
        skip(name, "no network")
else:
    check("http_get 200", r["status"] == 200)

    r = fetch("""SELECT http_post(
        'https://httpbin.org/post',
        MAP{'Content-Type': 'application/json'},
        '{"key": "value"}'
    )""")
    check("http_post 200", r["status"] == 200 and '"key"' in r["body"])

    r = fetch("SELECT http_head('https://httpbin.org/get')")
    check("http_head empty body", r["status"] == 200 and r["body"] == "")

    r = fetch("SELECT http_delete('https://httpbin.org/delete')")
    check("http_delete 200", r["status"] == 200)

    r = fetch("""SELECT http_put('https://httpbin.org/put', '{"x":1}')""")
    check("http_put 200", r["status"] == 200)

    r = fetch("""SELECT http_patch('https://httpbin.org/patch', '{"y":2}')""")
    check("http_patch 200", r["status"] == 200)

    r = fetch("SELECT http_options('https://httpbin.org/get')")
    check("http_options 200", r["status"] == 200)

    r = fetch("""SELECT http_request('PUT', 'https://httpbin.org/put', MAP{}, '{"z":3}')""")
    check("http_request generic", r["status"] == 200)

    # Auth roundtrips
    r = fetch("""SELECT http_get(
        'https://httpbin.org/headers',
        MAP{'Authorization': http_basic_auth('u', 'p')}
    )""")
    check("basic_auth_roundtrip", base64.b64encode(b"u:p").decode() in r["body"])

    r = fetch("""SELECT http_get(
        'https://httpbin.org/headers',
        MAP{'Authorization': http_bearer_auth('jwt999')}
    )""")
    check("bearer_auth_roundtrip", "Bearer jwt999" in r["body"])

    # Pagination
    rows = fetch_all("""SELECT * FROM http_paginate(
        'https://httpbin.org/get?page={page}',
        page_param := 'page', start_page := 1, max_pages := 3
    )""")
    check("paginate 3 pages", len(rows) == 3)
    if len(rows) > 0:
        check("paginate status", rows[0][1] == 200)

    # Response headers present
    r = fetch("SELECT http_get('https://httpbin.org/get')")
    check("response headers", "content-type" in r["headers"])


# =====================================================
# 9. DNS TESTS
# =====================================================
print("\n--- 9. DNS Tests ---")

try:
    r = fetch("SELECT dns_lookup('example.com')")
    check("dns_lookup type", isinstance(r, list))

    r = fetch("SELECT dns_lookup_a('example.com')")
    check("dns_lookup_a type", isinstance(r, list))

    r = fetch("SELECT dns_lookup_aaaa('example.com')")
    check("dns_lookup_aaaa type", isinstance(r, list))

    r = fetch("SELECT dns_reverse('8.8.8.8')")
    check("dns_reverse type", r is None or isinstance(r, str))

    r = fetch("SELECT dns_txt('example.com')")
    check("dns_txt type", isinstance(r, list))

    r = fetch("SELECT dns_mx('example.com')")
    check("dns_mx type", isinstance(r, list))

    r = fetch("SELECT dns_lookup('this-domain-does-not-exist-12345.invalid')")
    check("dns nonexistent", isinstance(r, list) and len(r) == 0)
except Exception as e:
    skip("dns tests", str(e)[:80])


# =====================================================
# SUMMARY
# =====================================================
total = passed + failed + skipped
print(f"\n{'='*50}")
print(f"Results: {passed} passed, {failed} failed, {skipped} skipped / {total} total")
if failed > 0:
    print("\nFAILED TESTS - see details above")
    sys.exit(1)
print("=== ALL E2E TESTS PASSED ===")
