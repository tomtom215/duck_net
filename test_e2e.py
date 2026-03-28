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


# ===== Offline tests (no network) =====
print("\n--- Offline Tests ---")

# Auth helpers
r = fetch("SELECT http_basic_auth('user', 'pass')")
expected = "Basic " + base64.b64encode(b"user:pass").decode()
check("http_basic_auth", r == expected, f"got {r}")

r = fetch("SELECT http_bearer_auth('tok123')")
check("http_bearer_auth", r == "Bearer tok123", f"got {r}")

# SSRF protection
r = fetch("SELECT http_get('ftp://evil.com/file')")
check("block ftp://", r["status"] == 0 and "only http://" in r["reason"])

r = fetch("SELECT http_get('file:///etc/passwd')")
check("block file://", r["status"] == 0 and "only http://" in r["reason"])

r = fetch("SELECT http_get('gopher://evil.com')")
check("block gopher://", r["status"] == 0 and "only http://" in r["reason"])

r = fetch("SELECT http_get('javascript:alert(1)')")
check("block javascript:", r["status"] == 0 and "only http://" in r["reason"])

# Invalid method
r = fetch("SELECT http_request('INVALID', 'https://x.com', MAP{}, '')")
check("invalid method rejected", r["status"] == 0 and "Unsupported" in r["reason"])


# ===== Network tests =====
print("\n--- Network Tests ---")

r = fetch("SELECT http_get('https://httpbin.org/get')")
network_ok = r["status"] == 200

if not network_ok:
    print(f"  [SKIP] Network unavailable: {r['reason'][:80]}")
    skipped = 7
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

    # Auth roundtrip
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


# ===== Summary =====
total = passed + failed + skipped
print(f"\n{'='*40}")
print(f"Results: {passed} passed, {failed} failed, {skipped} skipped / {total} total")
if failed > 0:
    sys.exit(1)
print("=== E2E TESTS PASSED ===")
