# Web Security Posture Checker

A small, dependency-free tool that scores the security posture of an HTTP
response — the browser-facing controls that are cheap to get right and
routinely found missing in penetration tests and configuration reviews.

## The problem it solves

Missing or weak security headers and cookie flags are among the most
common findings in web assessments: no HSTS, a CSP with `unsafe-inline`,
session cookies without `Secure`/`HttpOnly`/`SameSite`, and servers
advertising exact version numbers to anyone who asks. Reviewing them by
hand is tedious and inconsistent. This tool checks a response in one pass
and produces a 0–100 score with a severity-rated, remediation-backed
finding for every gap.

## What it checks

| Area | Checks |
|---|---|
| Transport | `Strict-Transport-Security` presence and `max-age` (≥ 1 year), `includeSubDomains` |
| Script/content policy | `Content-Security-Policy` presence, `unsafe-inline`, `unsafe-eval`, fallback directives |
| MIME sniffing | `X-Content-Type-Options: nosniff` |
| Clickjacking | CSP `frame-ancestors` or `X-Frame-Options` |
| Privacy | `Referrer-Policy`, `Permissions-Policy` |
| Cookies | `Secure`, `HttpOnly`, `SameSite` on every `Set-Cookie` |
| Information disclosure | Version numbers in `Server`, presence of `X-Powered-By` |

## How to run

```bash
# Demo mode — fully offline, uses the bundled sample responses
python3 checker.py --demo

# Analyse a live URL
python3 checker.py --url https://example.com

# Analyse a saved raw HTTP response (e.g. captured with curl -i)
python3 checker.py --file response.txt
```

Python 3, standard library only.

## Demo output (actual run)

```
========================================================================
Target: sample: hardened.txt
Status line: HTTP/1.1 200 OK
Score: 100/100  Grade: A
------------------------------------------------------------------------
No findings. All checks passed.

========================================================================
Target: sample: weak.txt
Status line: HTTP/1.1 200 OK
Score: 10/100  Grade: F
------------------------------------------------------------------------
[  High] Strict-Transport-Security: Header missing
         -> Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains' on all HTTPS responses.
[  High] Cookie 'session_id': Missing Secure flag
         -> Set the Secure attribute so the cookie is only sent over HTTPS.
[  High] Cookie 'prefs': Missing Secure flag
         -> Set the Secure attribute so the cookie is only sent over HTTPS.
[Medium] Content-Security-Policy: 'unsafe-inline' present
         -> Remove 'unsafe-inline'; use nonces or hashes for inline scripts/styles.
[Medium] Content-Security-Policy: 'unsafe-eval' present
         -> Remove 'unsafe-eval' to block eval()-based code execution.
[Medium] X-Content-Type-Options: Header missing
         -> Add 'X-Content-Type-Options: nosniff' to prevent MIME sniffing.
[Medium] Clickjacking protection: No frame-ancestors in CSP and no X-Frame-Options
         -> Add CSP frame-ancestors 'self' (preferred) or 'X-Frame-Options: SAMEORIGIN'.
[Medium] Cookie 'session_id': Missing HttpOnly flag
         -> Set HttpOnly on session cookies to limit XSS cookie theft.
[Medium] Cookie 'session_id': Missing SameSite attribute
         -> Set SameSite=Lax (or Strict) to reduce CSRF exposure.
[Medium] Cookie 'prefs': Missing HttpOnly flag
         -> Set HttpOnly on session cookies to limit XSS cookie theft.
[Medium] Cookie 'prefs': Missing SameSite attribute
         -> Set SameSite=Lax (or Strict) to reduce CSRF exposure.
[   Low] Referrer-Policy: Header missing
         -> Add 'Referrer-Policy: strict-origin-when-cross-origin' (or stricter).
[   Low] Permissions-Policy: Header missing
         -> Add a Permissions-Policy disabling unused features, e.g. camera=(), microphone=(), geolocation=().
[   Low] Server disclosure: Server header reveals version: 'Apache/2.4.49 (Unix)'
         -> Suppress version numbers in the Server header (e.g. ServerTokens Prod on Apache).
[   Low] X-Powered-By disclosure: Technology disclosed: 'PHP/7.4.3'
         -> Remove the X-Powered-By header; it only helps attackers fingerprint the stack.
```

## Design notes and limitations

- **Scoring** is weighted by control importance (CSP 20, HSTS 15, cookies
  15, disclosure 15, the rest smaller) and normalised to 100. It is a
  triage score, not a substitute for a full assessment.
- **Headers only.** The tool evaluates the response surface; it does not
  test TLS configuration, authentication, or application logic.
- **Cookies** are scored proportionally: each cookie contributes an equal
  share of the cookie points, deducted per missing flag.
- A response with **no cookies** scores full cookie marks with an
  informational note — there is nothing to protect.
- Sample responses in `sample_responses/` are fictional, hand-written
  captures: one hardened (`100/100`) and one weak (`10/100`).

## License

MIT — see `LICENSE`.
