import http.server
import threading
import unittest

import headercheck as hc

GOOD = [
    ("Strict-Transport-Security", "max-age=31536000; includeSubDomains"),
    ("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'"),
    ("X-Content-Type-Options", "nosniff"),
    ("Referrer-Policy", "strict-origin-when-cross-origin"),
    ("Permissions-Policy", "camera=()"),
]


def rules(headers, https=True):
    return {(f[0], f[1]) for f in hc.audit(headers, https)}


class AuditTests(unittest.TestCase):
    def test_good_headers_clean(self):
        self.assertEqual(hc.audit(GOOD), [])
        self.assertEqual(hc.score([]), (100, "A"))

    def test_empty_headers(self):
        r = rules([])
        for e in (("MEDIUM", "hsts-missing"), ("MEDIUM", "csp-missing"), ("MEDIUM", "clickjacking"),
                  ("LOW", "nosniff-missing"), ("LOW", "referrer-missing"), ("LOW", "permissions-missing")):
            self.assertIn(e, r)

    def test_case_insensitive_names(self):
        h = [(k.lower(), v) for k, v in GOOD]
        self.assertEqual(hc.audit(h), [])

    def test_plain_http(self):
        r = rules(GOOD, https=False)
        self.assertIn(("HIGH", "no-https"), r)
        self.assertNotIn(("MEDIUM", "hsts-missing"), r)

    def test_hsts_short(self):
        h = [x for x in GOOD if x[0] != "Strict-Transport-Security"] + [("Strict-Transport-Security", "max-age=60")]
        self.assertIn(("LOW", "hsts-short"), rules(h))

    def test_csp_weaknesses(self):
        base = [x for x in GOOD if x[0] != "Content-Security-Policy"]
        unsafe = base + [("Content-Security-Policy", "script-src 'self' 'unsafe-inline'; frame-ancestors 'self'")]
        wild = base + [("Content-Security-Policy", "default-src *; frame-ancestors 'self'")]
        self.assertIn(("MEDIUM", "csp-unsafe"), rules(unsafe))
        self.assertIn(("MEDIUM", "csp-wildcard"), rules(wild))

    def test_xfo_alternative_to_frame_ancestors(self):
        h = [x for x in GOOD if x[0] != "Content-Security-Policy"] + [
            ("Content-Security-Policy", "default-src 'self'"), ("X-Frame-Options", "DENY")]
        self.assertNotIn(("MEDIUM", "clickjacking"), rules(h))

    def test_info_leaks(self):
        r = rules(GOOD + [("Server", "nginx/1.18.0"), ("X-Powered-By", "Express")])
        self.assertIn(("LOW", "server-version"), r)
        self.assertIn(("LOW", "x-powered-by"), r)
        self.assertNotIn(("LOW", "server-version"), rules(GOOD + [("Server", "nginx")]))

    def test_cors(self):
        h = GOOD + [("Access-Control-Allow-Origin", "*"), ("Access-Control-Allow-Credentials", "true")]
        self.assertIn(("HIGH", "cors-credentials"), rules(h))

    def test_cookies_each_checked(self):
        h = GOOD + [("Set-Cookie", "sid=1; Path=/"), ("Set-Cookie", "ok=1; Secure; HttpOnly; SameSite=Lax")]
        findings = [f for f in hc.audit(h) if f[1].startswith("cookie")]
        self.assertEqual({f[1] for f in findings}, {"cookie-secure", "cookie-httponly", "cookie-samesite"})
        self.assertTrue(all("'sid'" in f[2] for f in findings))

    def test_score_grades(self):
        # no headers at all: 3 MEDIUM (30) + 3 LOW (9) = 61 points
        self.assertEqual(hc.score(hc.audit([])), (61, "C"))
        self.assertEqual(hc.score([("HIGH", "x", "", "")] * 6), (0, "F"))


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("X-Powered-By", "demo")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, *a):
        pass


class LocalServerTests(unittest.TestCase):
    def test_fetch_and_cli_against_localhost(self):
        srv = http.server.HTTPServer(("127.0.0.1", 0), Handler)
        t = threading.Thread(target=srv.serve_forever, daemon=True)
        t.start()
        try:
            url = "http://127.0.0.1:%d/" % srv.server_address[1]
            final, status, headers = hc.fetch(url, 5)
            self.assertEqual(status, 200)
            self.assertIn("x-powered-by", [k.lower() for k, _ in headers])
            self.assertEqual(hc.main([url]), 1)
        finally:
            srv.shutdown()
            srv.server_close()

    def test_unreachable_and_bad_scheme(self):
        self.assertEqual(hc.main(["http://127.0.0.1:1/", "--timeout", "2"]), 2)
        self.assertEqual(hc.main(["ftp://example.com"]), 2)

    def test_injected_fetcher_good_site(self):
        self.assertEqual(hc.main(["https://example.test"], fetcher=lambda u, t: (u, 200, GOOD)), 0)


if __name__ == "__main__":
    unittest.main()
