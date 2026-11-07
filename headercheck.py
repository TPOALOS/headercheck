#!/usr/bin/env python3
"""headercheck - grade the HTTP security headers of a website you operate.

Sends ONE ordinary GET request per URL and inspects the response headers (the
body is never read). Only use it on sites you own or are authorized to test.
Standard library only. Exit code 0 = no HIGH/MEDIUM findings, 1 = findings, 2 = error.
"""
import argparse
import re
import sys
import urllib.error
import urllib.parse
import urllib.request

__version__ = "1.0.0"
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
    if get(headers, "permissions-policy") is None:
        add("LOW", "permissions-missing", "no Permissions-Policy header", "disable features you do not use, e.g. `camera=(), microphone=()`")
    server = get(headers, "server")
    if server and VERSIONED.search(server):
        add("LOW", "server-version", "Server header reveals a version (%s)" % server, "hide version details")
    if get(headers, "x-powered-by"):
        add("LOW", "x-powered-by", "X-Powered-By reveals the technology stack", "remove the header")
    acao, acac = get(headers, "access-control-allow-origin"), get(headers, "access-control-allow-credentials")
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


def main(argv=None, fetcher=fetch):
    ap = argparse.ArgumentParser(description="Grade HTTP security headers of a site you operate.")
    ap.add_argument("urls", nargs="+", help="https://example.com (scheme optional, defaults to https)")
    ap.add_argument("--timeout", type=int, default=10)
    ap.add_argument("--version", action="version", version=__version__)
    args = ap.parse_args(argv)
    print("Only scan sites you own or are authorized to test.", file=sys.stderr)
    bad = False
    for raw in args.urls:
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
        print("== %s -> %s (HTTP %s)  score %d/100  grade %s" % (raw, final, status, pts, grade))
        for sev, rule, msg, fix in findings:
            print("%-6s %-20s %s%s" % (sev, rule, msg, "\n         fix: " + fix if fix else ""))
        bad = bad or any(f[0] in ("HIGH", "MEDIUM") for f in findings)
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
