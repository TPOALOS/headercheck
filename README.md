# headercheck

Grade the HTTP security headers of a website **you operate**. It sends one ordinary
`GET` request per URL, inspects the response headers (the body is never read) and
prints a score, a grade and a fix for each problem. One file, standard library only.

> Only use it on sites you own or are authorized to test. It identifies itself with
> a `headercheck/1.0` User-Agent and makes a single request per URL.

## Usage

```bash
python3 headercheck.py example.com
python3 headercheck.py https://staging.example.org https://www.example.org --timeout 5
python3 headercheck.py -f my-sites.txt --json                 # one URL per line, # comments ok
python3 headercheck.py example.com --fail-on LOW --min-severity MEDIUM
# or: pip install git+https://github.com/TPOALOS/headercheck && headercheck example.com
```

`--fail-on` sets the severity that makes the exit code `1` (default `MEDIUM`); `--min-severity` only hides lower findings
from the output, the score still counts them.

Example output:

```
== example.com -> https://example.com/ (HTTP 200)  score 61/100  grade C
MEDIUM hsts-missing         no Strict-Transport-Security header
         fix: add `Strict-Transport-Security: max-age=31536000; includeSubDomains`
MEDIUM csp-missing          no Content-Security-Policy header
         fix: start with a restrictive policy such as `default-src 'self'`
LOW    referrer-missing     no Referrer-Policy header
         fix: add `Referrer-Policy: strict-origin-when-cross-origin`
```

## Checks

| Area | Rules |
|------|-------|
| Transport | `no-https` (HIGH), `hsts-missing` (MEDIUM), `hsts-short` (LOW) |
| Content-Security-Policy | `csp-missing`, `csp-unsafe` (`'unsafe-inline'`/`'unsafe-eval'`), `csp-wildcard` (`*`, `data:`, `http:`), `clickjacking` (no `frame-ancestors` and no `X-Frame-Options`), all MEDIUM; `csp-object-src`, `csp-base-uri`, `csp-report-only` (LOW) |
| Hardening headers | `nosniff-missing`, `referrer-missing`, `referrer-weak`, `permissions-missing` (LOW) |
| Information leaks | `server-version`, `x-powered-by` (LOW) |
| CORS | `cors-credentials`: `*` together with credentials (HIGH); `cors-null`: the `null` origin is allowed (MEDIUM) |
| Cookies | `cookie-secure`, `cookie-samesite-none` (MEDIUM), `cookie-httponly`, `cookie-samesite` (LOW), checked for every `Set-Cookie` |
| Legacy | `xss-protection-legacy`: `X-XSS-Protection: 1` (LOW) |

Score starts at 100 and loses 20 per HIGH, 10 per MEDIUM, 3 per LOW finding
(A 90+, B 75+, C 60+, D 40+, F below).

Redirects are followed and the final response is graded. Exit codes: `0` no HIGH/MEDIUM
findings, `1` findings, `2` network error or unsupported URL.

## Limits

It checks header presence and a few obvious weaknesses, not whether your CSP is
actually effective. Headers can differ per path or per client, and the single request
only sees one of them.

## Tests

Tests run fully offline: header analysis uses sample data, and the fetch test talks
only to a throwaway server on `127.0.0.1`.

```bash
python3 -m unittest -v
```

## License

MIT (c) TPOALOS
