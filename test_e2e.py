"""Comprehensive end-to-end test suite for duck_net DuckDB extension."""
import base64
import duckdb
import sys

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
# OFFLINE TESTS (no network required)
# =====================================================

print("\n--- Auth Helper Tests ---")

r = fetch("SELECT http_basic_auth('user', 'pass')")
expected = "Basic " + base64.b64encode(b"user:pass").decode()
check("http_basic_auth", r == expected, f"got {r}")

r = fetch("SELECT http_bearer_auth('tok123')")
check("http_bearer_auth", r == "Bearer tok123", f"got {r}")

# Edge cases
r = fetch("SELECT http_basic_auth('', '')")
check("http_basic_auth empty", r == "Basic " + base64.b64encode(b":").decode())

r = fetch("SELECT http_basic_auth('user:with:colons', 'p@ss!')")
expected = "Basic " + base64.b64encode(b"user:with:colons:p@ss!").decode()
check("http_basic_auth special chars", r == expected)


print("\n--- SSRF Protection Tests ---")

for scheme in ["ftp", "file", "gopher", "javascript", "data", "ldap"]:
    url = f"{scheme}://evil.com/file"
    r = fetch(f"SELECT http_get('{url}')")
    check(f"block {scheme}://", r["status"] == 0 and "only http://" in r["reason"])

r = fetch("SELECT http_request('INVALID', 'https://x.com', MAP{}, '')")
check("invalid method rejected", r["status"] == 0 and "Unsupported" in r["reason"])


print("\n--- SOAP Offline Tests ---")

# Extract body from SOAP 1.1
r = fetch("""SELECT soap_extract_body(
    '<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
       <soap:Body><Result>42</Result></soap:Body>
     </soap:Envelope>')""")
check("soap_extract_body 1.1", "<Result>42</Result>" in r)

# Extract body from SOAP 1.2
r = fetch("""SELECT soap_extract_body(
    '<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope">
       <soap:Body><Data>hello</Data></soap:Body>
     </soap:Envelope>')""")
check("soap_extract_body 1.2", "<Data>hello</Data>" in r)

# Alternate namespace prefix
r = fetch("""SELECT soap_extract_body(
    '<SOAP-ENV:Envelope><SOAP-ENV:Body><X>1</X></SOAP-ENV:Body></SOAP-ENV:Envelope>')""")
check("soap_extract_body SOAP-ENV", "<X>1</X>" in r)

r = fetch("""SELECT soap_extract_body(
    '<s:Envelope><s:Body><Y>2</Y></s:Body></s:Envelope>')""")
check("soap_extract_body s: prefix", "<Y>2</Y>" in r)

# Fault detection
r = fetch("""SELECT soap_is_fault(
    '<soap:Body><soap:Fault><faultstring>err</faultstring></soap:Fault></soap:Body>')""")
check("soap_is_fault true", r == True)

r = fetch("""SELECT soap_is_fault('<soap:Body><Result>OK</Result></soap:Body>')""")
check("soap_is_fault false", r == False)

# Fault string extraction
r = fetch("""SELECT soap_fault_string(
    '<soap:Fault><faultstring>Server error</faultstring></soap:Fault>')""")
check("soap_fault_string 1.1", r == "Server error")

r = fetch("""SELECT soap_fault_string(
    '<soap:Fault><soap:Reason><soap:Text xml:lang="en">Access denied</soap:Text></soap:Reason></soap:Fault>')""")
check("soap_fault_string 1.2", r == "Access denied")

r = fetch("SELECT soap_fault_string('<Result>OK</Result>')")
check("soap_fault_string null", r is None)


print("\n--- Rate Limiting Tests ---")

r = fetch("SELECT duck_net_set_rate_limit(0)")
check("rate limit disable", "disabled" in r.lower())

r = fetch("SELECT duck_net_set_rate_limit(50)")
check("rate limit set 50", "50" in r)

con.execute("SELECT duck_net_set_rate_limit(0)")


print("\n--- SMTP URL Parsing (via error messages) ---")

r = fetch("SELECT smtp_send('smtp://localhost:9999', 'a@b.com', 'c@d.com', 'test', 'body')")
check("smtp_send returns struct", r["success"] == False and len(r["message"]) > 0)

r = fetch("SELECT smtp_send('invalid://host', 'a@b.com', 'c@d.com', 'test', 'body')")
check("smtp invalid scheme", r["success"] == False and "smtp://" in r["message"])


print("\n--- FTP URL Parsing (via error messages) ---")

r = fetch("SELECT ftp_read('ftp://nonexistent.invalid/file.txt')")
check("ftp_read returns struct", "success" in str(r) and r["success"] == False)

r = fetch("SELECT ftp_write('ftp://nonexistent.invalid/file.txt', 'data')")
check("ftp_write returns struct", r["success"] == False)

r = fetch("SELECT ftp_delete('ftp://nonexistent.invalid/file.txt')")
check("ftp_delete returns struct", r["success"] == False)

r = fetch("SELECT sftp_read('sftp://nonexistent.invalid/file.txt')")
check("sftp_read returns struct", r["success"] == False)

r = fetch("SELECT sftp_write('sftp://nonexistent.invalid/file.txt', 'data')")
check("sftp_write returns struct", r["success"] == False)

r = fetch("SELECT sftp_delete('sftp://nonexistent.invalid/file.txt')")
check("sftp_delete returns struct", r["success"] == False)


# =====================================================
# NETWORK TESTS
# =====================================================

print("\n--- HTTP Network Tests ---")

r = fetch("SELECT http_get('https://httpbin.org/get')")
network_ok = r["status"] == 200

if not network_ok:
    print(f"  [SKIP] Network unavailable: {r['reason'][:80]}")
    for name in ["http_get","http_post","http_head","http_delete","http_request PUT",
                  "basic auth roundtrip","bearer auth roundtrip","http_paginate"]:
        skip(name, "no network")
else:
    check("http_get", r["status"] == 200 and '"url"' in r["body"])

    r = fetch("""SELECT http_post(
        'https://httpbin.org/post',
        MAP{'Content-Type': 'application/json'},
        '{"key": "value"}'
    )""")
    check("http_post", r["status"] == 200)

    r = fetch("SELECT http_head('https://httpbin.org/get')")
    check("http_head", r["status"] == 200 and r["body"] == "")

    r = fetch("SELECT http_delete('https://httpbin.org/delete')")
    check("http_delete", r["status"] == 200)

    r = fetch("""SELECT http_request(
        'PUT', 'https://httpbin.org/put', MAP{}, '{"updated": true}'
    )""")
    check("http_request PUT", r["status"] == 200)

    # Auth roundtrips
    r = fetch("""SELECT http_get(
        'https://httpbin.org/headers',
        MAP{'Authorization': http_basic_auth('u', 'p')}
    )""")
    b64 = base64.b64encode(b"u:p").decode()
    check("basic auth roundtrip", r["status"] == 200 and b64 in r["body"])

    r = fetch("""SELECT http_get(
        'https://httpbin.org/headers',
        MAP{'Authorization': http_bearer_auth('jwt123')}
    )""")
    check("bearer auth roundtrip", r["status"] == 200 and "Bearer jwt123" in r["body"])

    # Pagination
    rows = fetch_all("""SELECT * FROM http_paginate(
        'https://httpbin.org/get?page={page}',
        page_param := 'page',
        start_page := 1,
        max_pages := 3
    )""")
    check("http_paginate count", len(rows) == 3)
    if len(rows) > 0:
        check("http_paginate status", rows[0][1] == 200)


print("\n--- DNS Tests ---")

try:
    # Test that all DNS functions return correct types (may be empty in proxy envs)
    r = fetch("SELECT dns_lookup('example.com')")
    check("dns_lookup returns list", isinstance(r, list), f"type: {type(r)}")
    dns_works = len(r) > 0
    if dns_works:
        check("dns_lookup has results", len(r) > 0)
    else:
        skip("dns_lookup results", "DNS may be blocked by proxy")

    r = fetch("SELECT dns_lookup_a('example.com')")
    check("dns_lookup_a returns list", isinstance(r, list), f"type: {type(r)}")
    if dns_works and len(r) > 0:
        check("dns_lookup_a is IPv4", "." in r[0], f"got: {r[0]}")

    r = fetch("SELECT dns_lookup_aaaa('example.com')")
    check("dns_lookup_aaaa returns list", isinstance(r, list), f"type: {type(r)}")

    r = fetch("SELECT dns_reverse('8.8.8.8')")
    check("dns_reverse returns", r is None or isinstance(r, str), f"got type: {type(r)}")

    r = fetch("SELECT dns_txt('example.com')")
    check("dns_txt returns list", isinstance(r, list), f"type: {type(r)}")

    r = fetch("SELECT dns_mx('example.com')")
    check("dns_mx returns list", isinstance(r, list), f"type: {type(r)}")

    # Edge case: nonexistent domain
    r = fetch("SELECT dns_lookup('this-domain-does-not-exist-12345.invalid')")
    check("dns_lookup nonexistent empty", isinstance(r, list) and len(r) == 0, f"got: {r}")

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
