import contextlib
import http.server
import io
import json
import os
import tempfile
import threading
import unittest

import headercheck as hc

GOOD = [
    ("Strict-Transport-Security", "max-age=31536000; includeSubDomains"),
    ("Content-Security-Policy", "default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'"),
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


def swap_csp(value):
    return [(k, value if k == "Content-Security-Policy" else v) for k, v in GOOD]


class NewRuleTests(unittest.TestCase):
    def test_object_src(self):
        self.assertIn(("LOW", "csp-object-src"), rules(swap_csp("default-src 'self'; base-uri 'self'; frame-ancestors 'none'")))
        self.assertNotIn("csp-object-src", {r for _, r in rules(swap_csp("default-src 'none'; base-uri 'self'; frame-ancestors 'none'"))})
        self.assertNotIn("csp-object-src", {r for _, r in rules(GOOD)})

    def test_object_src_explicit_overrides_default(self):
        csp = "default-src 'self'; object-src 'self'; base-uri 'self'; frame-ancestors 'none'"
        self.assertIn(("LOW", "csp-object-src"), rules(swap_csp(csp)))

    def test_base_uri(self):
        csp = "default-src 'self'; object-src 'none'; frame-ancestors 'none'"
        self.assertIn(("LOW", "csp-base-uri"), rules(swap_csp(csp)))

    def test_no_csp_object_or_base_rules_when_csp_is_missing(self):
        r = {x for _, x in rules([])}
        self.assertIn("csp-missing", r)
        self.assertNotIn("csp-object-src", r)
        self.assertNotIn("csp-base-uri", r)

    def test_report_only(self):
        headers = [(k, v) for k, v in GOOD if k != "Content-Security-Policy"] + [
            ("Content-Security-Policy-Report-Only", "default-src 'self'")]
        r = rules(headers)
        self.assertIn(("LOW", "csp-report-only"), r)
        self.assertIn(("MEDIUM", "csp-missing"), r)

    def test_legacy_xss_protection(self):
        self.assertIn(("LOW", "xss-protection-legacy"), rules(GOOD + [("X-XSS-Protection", "1; mode=block")]))
        self.assertNotIn("xss-protection-legacy", {r for _, r in rules(GOOD + [("X-XSS-Protection", "0")])})

    def test_cors_null(self):
        self.assertIn(("MEDIUM", "cors-null"), rules(GOOD + [("Access-Control-Allow-Origin", "null")]))
        self.assertNotIn("cors-null", {r for _, r in rules(GOOD + [("Access-Control-Allow-Origin", "https://a.example")])})

    def test_samesite_none_without_secure(self):
        r = rules(GOOD + [("Set-Cookie", "sid=1; SameSite=None; HttpOnly")])
        self.assertIn(("MEDIUM", "cookie-samesite-none"), r)
        ok = rules(GOOD + [("Set-Cookie", "sid=1; SameSite=None; Secure; HttpOnly")])
        self.assertNotIn("cookie-samesite-none", {x for _, x in ok})

    def test_good_headers_still_perfect(self):
        self.assertEqual(hc.audit(GOOD), [])


def fake_fetcher(headers_by_host):
    def fetcher(url, timeout):
        host = url.split("//")[1].split("/")[0]
        if host not in headers_by_host:
            raise OSError("unreachable")
        return url + "/", 200, headers_by_host[host]
    return fetcher


def run_main(*argv, fetcher):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = hc.main(list(argv), fetcher=fetcher)
    return code, out.getvalue(), err.getvalue()


class CliTests(unittest.TestCase):
    F = staticmethod(fake_fetcher({"good.example": GOOD, "bare.example": [],
                                   "low.example": [h for h in GOOD if h[0] != "Referrer-Policy"]}))

    def test_json_output(self):
        code, out, _ = run_main("good.example", "bare.example", "--json", fetcher=self.F)
        data = json.loads(out)
        self.assertEqual(code, 1)
        self.assertEqual([d["url"] for d in data], ["good.example", "bare.example"])
        self.assertEqual((data[0]["score"], data[0]["grade"], data[0]["findings"]), (100, "A", []))
        self.assertIn("csp-missing", {f["rule"] for f in data[1]["findings"]})
        self.assertEqual(set(data[1]["findings"][0]), {"severity", "rule", "message", "fix"})

    def test_json_has_no_text_banner_on_stdout(self):
        _, out, _ = run_main("good.example", "--json", fetcher=self.F)
        json.loads(out)

    def test_min_severity_hides_but_still_scores(self):
        _, out, _ = run_main("bare.example", "--json", "--min-severity", "MEDIUM", fetcher=self.F)
        data = json.loads(out)[0]
        self.assertTrue(all(f["severity"] in ("HIGH", "MEDIUM") for f in data["findings"]))
        _, full, _ = run_main("bare.example", "--json", fetcher=self.F)
        self.assertEqual(data["score"], json.loads(full)[0]["score"])

    def test_fail_on_levels(self):
        self.assertEqual(run_main("low.example", fetcher=self.F)[0], 0)             # only LOW findings
        self.assertEqual(run_main("low.example", "--fail-on", "LOW", fetcher=self.F)[0], 1)
        self.assertEqual(run_main("good.example", "--fail-on", "LOW", fetcher=self.F)[0], 0)
        self.assertEqual(run_main("bare.example", "--fail-on", "HIGH", fetcher=self.F)[0], 0)

    def test_file_of_urls(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "sites.txt")
            with open(p, "w") as fh:
                fh.write("# mine\ngood.example  # prod\n\nbare.example\n")
            code, out, _ = run_main("-f", p, "--json", fetcher=self.F)
        self.assertEqual([d["url"] for d in json.loads(out)], ["good.example", "bare.example"])

    def test_no_urls_is_usage_error(self):
        self.assertEqual(run_main(fetcher=self.F)[0], 2)

    def test_missing_file(self):
        self.assertEqual(run_main("-f", "/nonexistent/sites.txt", fetcher=self.F)[0], 2)

    def test_unreachable_host(self):
        code, _, err = run_main("nowhere.example", fetcher=self.F)
        self.assertEqual(code, 2)
        self.assertIn("unreachable", err)

    def test_text_output_format_unchanged(self):
        _, out, _ = run_main("bare.example", fetcher=self.F)
        self.assertTrue(out.startswith("== bare.example -> https://bare.example/ (HTTP 200)  score "))
        self.assertIn("fix:", out)

    def test_authorisation_notice_still_printed(self):
        self.assertIn("authorized", run_main("good.example", fetcher=self.F)[2])


if __name__ == "__main__":
    unittest.main()
