#!/usr/bin/env python3
"""headercheck - grade the HTTP security headers of a website you operate.

Sends ONE ordinary GET request per URL and inspects the response headers (the
body is never read). Only use it on sites you own or are authorized to test.
Standard library only. Exit code 0 = no HIGH/MEDIUM findings, 1 = findings, 2 = error.
"""
import argparse
import json
import re
import sys
import urllib.error
import urllib.parse
import urllib.request

__version__ = "1.1.0"
USER_AGENT = "headercheck/%s (security header audit by the site owner)" % __version__
SEV = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3}
PENALTY = {"HIGH": 20, "MEDIUM": 10, "LOW": 3, "INFO": 0}
VERSIONED = re.compile(r"(?i)[a-z][\w.-]*/\d+(\.\d+)+")


def get(headers, name):
    vals = [v for k, v in headers if k.lower() == name.lower()]
    return vals[0] if vals else None


def directive(csp, name):
    for part in csp.split(";"):
        toks = part.strip().split()
        if toks and toks[0].lower() == name:
            return toks[1:]
    return None


def audit(headers, https=True):
    """headers: list of (name, value). Returns list of (severity, rule, message, fix)."""
    out = []
    add = lambda sev, rule, msg, fix="": out.append((sev, rule, msg, fix))
    if not https:
        add("HIGH", "no-https", "response was served over plain http", "serve the site over https and redirect http to https")
    hsts = get(headers, "strict-transport-security")
    if https:
        if hsts is None:
            add("MEDIUM", "hsts-missing", "no Strict-Transport-Security header",
                "add `Strict-Transport-Security: max-age=31536000; includeSubDomains`")
        else:
            m = re.search(r"max-age=(\d+)", hsts, re.I)
            if not m or int(m.group(1)) < 15552000:
                add("LOW", "hsts-short", "HSTS max-age is under 180 days", "use max-age of at least 15552000 (1 year is common)")
    csp = get(headers, "content-security-policy")
    if csp is None:
        add("MEDIUM", "csp-missing", "no Content-Security-Policy header", "start with a restrictive policy such as `default-src 'self'`")
    else:
        script = directive(csp, "script-src") or directive(csp, "default-src") or []
        if "'unsafe-inline'" in script or "'unsafe-eval'" in script:
            add("MEDIUM", "csp-unsafe", "CSP allows 'unsafe-inline' or 'unsafe-eval' for scripts", "use nonces or hashes instead")
        if "*" in script or "data:" in script or "http:" in script:
            add("MEDIUM", "csp-wildcard", "CSP script sources are overly broad (*, data: or http:)", "list specific https origins")
        obj = directive(csp, "object-src")
        effective = obj if obj is not None else directive(csp, "default-src")
        if effective is None or [t.lower() for t in effective] != ["'none'"]:
            add("LOW", "csp-object-src", "CSP does not set object-src 'none' (plugins and legacy content)",
                "add `object-src 'none'`")
        if directive(csp, "base-uri") is None:
            add("LOW", "csp-base-uri", "CSP has no base-uri directive, so an injected <base> tag can redirect relative URLs",
                "add `base-uri 'self'` (or 'none')")
    if csp is None and get(headers, "content-security-policy-report-only"):
        add("LOW", "csp-report-only", "CSP is only in Report-Only mode and is not enforced", "switch to Content-Security-Policy once the reports are clean")
    xfo = get(headers, "x-frame-options")
    if xfo is None and not (csp and directive(csp, "frame-ancestors") is not None):
        add("MEDIUM", "clickjacking", "no X-Frame-Options and no CSP frame-ancestors", "add `frame-ancestors 'none'` (or 'self') to the CSP")
    if (get(headers, "x-content-type-options") or "").lower() != "nosniff":
        add("LOW", "nosniff-missing", "X-Content-Type-Options: nosniff is not set", "add `X-Content-Type-Options: nosniff`")
    ref = get(headers, "referrer-policy")
    if ref is None:
        add("LOW", "referrer-missing", "no Referrer-Policy header", "add `Referrer-Policy: strict-origin-when-cross-origin`")
    elif ref.strip().lower() in ("unsafe-url", "no-referrer-when-downgrade"):
        add("LOW", "referrer-weak", "Referrer-Policy %r leaks full URLs" % ref, "use strict-origin-when-cross-origin or stricter")
    if (get(headers, "x-xss-protection") or "").strip().startswith("1"):
        add("LOW", "xss-protection-legacy", "X-XSS-Protection enables the legacy browser filter, which can itself introduce flaws",
            "remove it or set `X-XSS-Protection: 0` and rely on CSP")
    if get(headers, "permissions-policy") is None:
        add("LOW", "permissions-missing", "no Permissions-Policy header", "disable features you do not use, e.g. `camera=(), microphone=()`")
    server = get(headers, "server")
    if server and VERSIONED.search(server):
        add("LOW", "server-version", "Server header reveals a version (%s)" % server, "hide version details")
    if get(headers, "x-powered-by"):
        add("LOW", "x-powered-by", "X-Powered-By reveals the technology stack", "remove the header")
    acao, acac = get(headers, "access-control-allow-origin"), get(headers, "access-control-allow-credentials")
    if (acao or "").strip().lower() == "null":
        add("MEDIUM", "cors-null", "CORS allows the 'null' origin, which sandboxed iframes and local files can use",
            "do not allow the null origin")
    if acao == "*" and (acac or "").lower() == "true":
        add("HIGH", "cors-credentials", "CORS allows any origin together with credentials", "echo only trusted origins")
    for k, v in headers:
        if k.lower() != "set-cookie":
            continue
        name = v.split("=", 1)[0].strip()
        flags = v.lower()
        if https and "secure" not in flags:
            add("MEDIUM", "cookie-secure", "cookie %r lacks the Secure flag" % name, "add Secure")
        if "httponly" not in flags:
            add("LOW", "cookie-httponly", "cookie %r lacks HttpOnly" % name, "add HttpOnly unless scripts need it")
        if "samesite" not in flags:
            add("LOW", "cookie-samesite", "cookie %r lacks SameSite" % name, "add SameSite=Lax (or Strict)")
        elif re.search(r"samesite\s*=\s*none", flags) and "secure" not in flags:
            add("MEDIUM", "cookie-samesite-none", "cookie %r uses SameSite=None without Secure; browsers reject it" % name,
                "add Secure, or use SameSite=Lax")
    return sorted(out, key=lambda f: SEV[f[0]])


def score(findings):
    pts = max(0, 100 - sum(PENALTY[f[0]] for f in findings))
    grade = "A" if pts >= 90 else "B" if pts >= 75 else "C" if pts >= 60 else "D" if pts >= 40 else "F"
    return pts, grade


def fetch(url, timeout=10):
    """Return (final_url, status, [(name, value), ...]). Reads no body."""
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        resp = urllib.request.urlopen(req, timeout=timeout)
    except urllib.error.HTTPError as err:  # 4xx/5xx still carry headers
        resp = err
    try:
        return resp.geturl(), resp.status, list(resp.headers.items())
    finally:
        resp.close()


def read_urls(args):
    urls = list(args.urls)
    if args.file:
        with open(args.file, encoding="utf-8", errors="replace") as fh:
            urls += [l.split("#")[0].strip() for l in fh if l.split("#")[0].strip()]
    return urls


def main(argv=None, fetcher=fetch):
    ap = argparse.ArgumentParser(description="Grade HTTP security headers of a site you operate.")
    ap.add_argument("urls", nargs="*", help="https://example.com (scheme optional, defaults to https)")
    ap.add_argument("-f", "--file", help="file with one URL per line (# comments ok)")
    ap.add_argument("--timeout", type=int, default=10)
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument("--min-severity", choices=("LOW", "MEDIUM", "HIGH"), default="LOW",
                    help="hide findings below this severity (the score still counts them)")
    ap.add_argument("--fail-on", choices=("LOW", "MEDIUM", "HIGH"), default="MEDIUM",
                    help="exit 1 when a finding of at least this severity exists (default MEDIUM)")
    ap.add_argument("--version", action="version", version=__version__)
    args = ap.parse_args(argv)
    try:
        urls = read_urls(args)
    except OSError as exc:
        print("headercheck: %s" % exc, file=sys.stderr)
        return 2
    if not urls:
        ap.print_usage(sys.stderr)
        return 2
    print("Only scan sites you own or are authorized to test.", file=sys.stderr)
    shown, fail_at = SEV[args.min_severity], SEV[args.fail_on]
    bad, results = False, []
    for raw in urls:
        url = raw if "://" in raw else "https://" + raw
        if urllib.parse.urlparse(url).scheme not in ("http", "https"):
            print("headercheck: unsupported URL scheme: %s" % raw, file=sys.stderr)
            return 2
        try:
            final, status, headers = fetcher(url, args.timeout)
        except (urllib.error.URLError, OSError, ValueError) as exc:
            print("headercheck: %s: %s" % (raw, getattr(exc, "reason", exc)), file=sys.stderr)
            return 2
        findings = audit(headers, urllib.parse.urlparse(final).scheme == "https")
        pts, grade = score(findings)
        results.append({"url": raw, "final_url": final, "status": status, "score": pts, "grade": grade,
                        "findings": [{"severity": sv, "rule": r, "message": m, "fix": f}
                                     for sv, r, m, f in findings if SEV[sv] <= shown]})
        bad = bad or any(SEV[f[0]] <= fail_at for f in findings)
        if not args.json:
            print("== %s -> %s (HTTP %s)  score %d/100  grade %s" % (raw, final, status, pts, grade))
            for sev, rule, msg, fix in findings:
                if SEV[sev] <= shown:
                    print("%-6s %-20s %s%s" % (sev, rule, msg, "\n         fix: " + fix if fix else ""))
    if args.json:
        print(json.dumps(results, indent=2))
    return 1 if bad else 0

if __name__ == "__main__":
    sys.exit(main())
