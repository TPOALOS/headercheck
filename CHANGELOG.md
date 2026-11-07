# Changelog

## 1.1.0

- New checks: CSP `object-src` and `base-uri`, Report-Only CSP, `null` CORS origin, `SameSite=None` without `Secure`, legacy `X-XSS-Protection`
- `--json`, `--file` (URL list), `--min-severity` and `--fail-on`
- The new LOW checks lower the score of sites that lack `object-src` or `base-uri` in their CSP
- Installable with pip (`headercheck` command), CI on Linux and macOS

## 1.0.0

Initial release.
