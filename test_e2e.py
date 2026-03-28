"""End-to-end test suite for duck_net DuckDB extension."""
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

def fetch(sql):
    return con.execute(sql).fetchone()[0]

def fetch_all(sql):
    return con.execute(sql).fetchall()


# ===== Offline tests (no network) =====
print("\n--- Auth Helper Tests (Offline) ---")

r = fetch("SELECT http_basic_auth('user', 'pass')")
expected = "Basic " + base64.b64encode(b"user:pass").decode()
check("http_basic_auth", r == expected, f"got {r}")

r = fetch("SELECT http_bearer_auth('tok123')")
check("http_bearer_auth", r == "Bearer tok123", f"got {r}")


print("\n--- SSRF Protection Tests (Offline) ---")

r = fetch("SELECT http_get('ftp://evil.com/file')")
check("block ftp://", r["status"] == 0 and "only http://" in r["reason"])

r = fetch("SELECT http_get('file:///etc/passwd')")
check("block file://", r["status"] == 0 and "only http://" in r["reason"])

r = fetch("SELECT http_get('gopher://evil.com')")
check("block gopher://", r["status"] == 0 and "only http://" in r["reason"])

r = fetch("SELECT http_get('javascript:alert(1)')")
check("block javascript:", r["status"] == 0 and "only http://" in r["reason"])

r = fetch("SELECT http_request('INVALID', 'https://x.com', MAP{}, '')")
check("invalid method rejected", r["status"] == 0 and "Unsupported" in r["reason"])


print("\n--- SOAP Offline Tests ---")

# Test SOAP envelope building via soap_extract_body round-trip
r = fetch("""SELECT soap_extract_body(
    '<?xml version="1.0"?>
     <soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
       <soap:Body>
         <GetAccountResponse><Balance>1000</Balance></GetAccountResponse>
       </soap:Body>
     </soap:Envelope>'
)""")
check("soap_extract_body", "<GetAccountResponse>" in r and "1000" in r, f"got: {r[:80]}")

r = fetch("""SELECT soap_is_fault(
    '<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
       <soap:Body><soap:Fault><faultstring>Server error</faultstring></soap:Fault></soap:Body>
     </soap:Envelope>'
)""")
check("soap_is_fault (true)", r == True, f"got: {r}")

r = fetch("""SELECT soap_is_fault(
    '<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
       <soap:Body><GetResponse>OK</GetResponse></soap:Body>
     </soap:Envelope>'
)""")
check("soap_is_fault (false)", r == False, f"got: {r}")

r = fetch("""SELECT soap_fault_string(
    '<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
       <soap:Body><soap:Fault><faultstring>Something broke</faultstring></soap:Fault></soap:Body>
     </soap:Envelope>'
)""")
check("soap_fault_string", r == "Something broke", f"got: {r}")

r = fetch("""SELECT soap_fault_string(
    '<soap:Body><GetResponse>OK</GetResponse></soap:Body>'
)""")
check("soap_fault_string (null)", r is None, f"got: {r}")

# SOAP 1.2 fault
r = fetch("""SELECT soap_extract_body(
    '<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope">
       <soap:Body><soap:Fault>
         <soap:Reason><soap:Text xml:lang="en">Access denied</soap:Text></soap:Reason>
       </soap:Fault></soap:Body>
     </soap:Envelope>'
)""")
check("soap_extract_body (1.2 fault)", "Access denied" in r, f"got: {r[:80]}")

r = fetch("""SELECT soap_fault_string(
    '<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope">
       <soap:Body><soap:Fault>
         <soap:Reason><soap:Text xml:lang="en">Access denied</soap:Text></soap:Reason>
       </soap:Fault></soap:Body>
     </soap:Envelope>'
)""")
check("soap_fault_string (1.2)", r == "Access denied", f"got: {r}")


print("\n--- Rate Limiting Tests (Offline) ---")

r = fetch("SELECT duck_net_set_rate_limit(0)")
check("rate limit disable", "disabled" in r.lower(), f"got: {r}")

r = fetch("SELECT duck_net_set_rate_limit(100)")
check("rate limit set", "100" in r, f"got: {r}")

# Reset for network tests
con.execute("SELECT duck_net_set_rate_limit(0)")


# ===== Network tests =====
print("\n--- Network Tests ---")

r = fetch("SELECT http_get('https://httpbin.org/get')")
network_ok = r["status"] == 200

if not network_ok:
    print(f"  [SKIP] Network unavailable: {r['reason'][:80]}")
    skipped = 10
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

    # SOAP network test (public SOAP service)
    r = fetch("""SELECT soap_request(
        'http://www.dneonline.com/calculator.asmx',
        'http://tempuri.org/Add',
        '<Add xmlns="http://tempuri.org/"><intA>5</intA><intB>3</intB></Add>'
    )""")
    soap_ok = r["status"] == 200
    if soap_ok:
        check("soap_request (calculator)", True)
        body = r["body"]
        extracted = con.execute(f"SELECT soap_extract_body('{body.replace(chr(39), chr(39)+chr(39))}')").fetchone()[0]
        check("soap_extract_body (live)", "AddResult" in (extracted or ""), f"got: {str(extracted)[:80]}")
    else:
        print(f"  [SKIP] SOAP service unavailable: {r['status']} {r['reason'][:60]}")
        skipped += 2

    # Pagination table function
    rows = fetch_all("""SELECT * FROM http_paginate(
        'https://httpbin.org/get?page={page}',
        page_param := 'page',
        start_page := 1,
        max_pages := 3
    )""")
    check("http_paginate row count", len(rows) == 3, f"got {len(rows)} rows")
    if len(rows) > 0:
        check("http_paginate status", rows[0][1] == 200, f"status={rows[0][1]}")


# ===== Summary =====
total = passed + failed + skipped
print(f"\n{'='*40}")
print(f"Results: {passed} passed, {failed} failed, {skipped} skipped / {total} total")
if failed > 0:
    sys.exit(1)
print("=== E2E TESTS PASSED ===")
