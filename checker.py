#!/usr/bin/env python3
"""Web Security Posture Checker.

Evaluates the security posture of an HTTP response: security headers,
cookie flags, and server version disclosure. Scores 0-100 with
per-check findings (severity + remediation).

Usage:
    python3 checker.py --demo
    python3 checker.py --url https://example.com
    python3 checker.py --file response.txt

Standard library only. Demo mode runs fully offline against the
bundled sample responses in sample_responses/.
"""

import argparse
import re
import ssl
import sys
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent

# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------

def parse_response(text):
    """Parse raw HTTP response text into (status_line, headers dict).

    Header names are lower-cased; repeated headers (e.g. Set-Cookie)
    are collected into a list under the key 'set-cookie-list'.
    """
    lines = text.replace("\r\n", "\n").split("\n")
    status = lines[0].strip() if lines else ""
    headers = {}
    cookies = []
    current = None
    for line in lines[1:]:
        if not line.strip():
            break  # end of headers
        if line[0] in " \t" and current:  # folded continuation
            headers[current] += " " + line.strip()
            continue
        if ":" not in line:
            continue
        name, _, value = line.partition(":")
        name = name.strip().lower()
        value = value.strip()
        if name == "set-cookie":
            cookies.append(value)
        headers[name] = value
        current = name
    headers["set-cookie-list"] = cookies
    return status, headers


def fetch_url(url):
    """Fetch a URL with urllib and return raw header text."""
    ctx = ssl.create_default_context()
    req = urllib.request.Request(url, headers={"User-Agent": "posture-checker/1.0"})
    with urllib.request.urlopen(req, timeout=15, context=ctx) as resp:
        status = f"HTTP/1.1 {resp.status} {resp.reason}"
        lines = [status] + [f"{k}: {v}" for k, v in resp.headers.items()]
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Checks. Each returns (points_earned, max_points, findings)
# A finding is (severity, check, detail, remediation)
# ---------------------------------------------------------------------------

def check_hsts(h):
    v = h.get("strict-transport-security")
    if not v:
        return 0, 15, [("High", "Strict-Transport-Security", "Header missing",
                        "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains' on all HTTPS responses.")]
    m = re.search(r"max-age=(\d+)", v)
    age = int(m.group(1)) if m else 0
    if age >= 31536000:
        pts, f = 15, []
        if "includesubdomains" not in v.lower():
            pts, f = 12, [("Low", "Strict-Transport-Security", "includeSubDomains not set",
                           "Add includeSubDomains so subdomains are covered by HSTS.")]
        return pts, 15, f
    return 7, 15, [("Medium", "Strict-Transport-Security", f"max-age too low ({age}s)",
                    "Raise max-age to at least 31536000 (one year).")]


def check_csp(h):
    v = h.get("content-security-policy")
    if not v:
        return 0, 20, [("High", "Content-Security-Policy", "Header missing",
                        "Deploy a Content-Security-Policy starting from default-src 'self' and loosening only as needed.")]
    findings, pts = [], 20
    low = v.lower()
    if "unsafe-inline" in low:
        pts -= 6
        findings.append(("Medium", "Content-Security-Policy", "'unsafe-inline' present",
                         "Remove 'unsafe-inline'; use nonces or hashes for inline scripts/styles."))
    if "unsafe-eval" in low:
        pts -= 4
        findings.append(("Medium", "Content-Security-Policy", "'unsafe-eval' present",
                         "Remove 'unsafe-eval' to block eval()-based code execution."))
    if "default-src" not in low and "script-src" not in low:
        pts -= 5
        findings.append(("Low", "Content-Security-Policy", "No default-src / script-src directive",
                         "Set an explicit default-src as a fallback for resource types."))
    return max(pts, 0), 20, findings


def check_content_type(h):
    v = h.get("x-content-type-options", "").lower()
    if v == "nosniff":
        return 10, 10, []
    if not v:
        return 0, 10, [("Medium", "X-Content-Type-Options", "Header missing",
                        "Add 'X-Content-Type-Options: nosniff' to prevent MIME sniffing.")]
    return 3, 10, [("Low", "X-Content-Type-Options", f"Unexpected value '{v}'",
                    "Set the header value to exactly 'nosniff'.")]


def check_framing(h):
    csp = h.get("content-security-policy", "").lower()
    if "frame-ancestors" in csp:
        return 10, 10, []
    v = h.get("x-frame-options", "").upper()
    if v in ("DENY", "SAMEORIGIN"):
        return 10, 10, []
    return 0, 10, [("Medium", "Clickjacking protection", "No frame-ancestors in CSP and no X-Frame-Options",
                    "Add CSP frame-ancestors 'self' (preferred) or 'X-Frame-Options: SAMEORIGIN'.")]


def check_referrer(h):
    v = h.get("referrer-policy", "").lower()
    good = ("no-referrer", "same-origin", "strict-origin", "strict-origin-when-cross-origin")
    if any(g in v for g in good):
        return 8, 8, []
    if not v:
        return 0, 8, [("Low", "Referrer-Policy", "Header missing",
                       "Add 'Referrer-Policy: strict-origin-when-cross-origin' (or stricter).")]
    return 4, 8, [("Low", "Referrer-Policy", f"Weak value '{v}'",
                   "Use strict-origin-when-cross-origin, same-origin, or no-referrer.")]


def check_permissions(h):
    if h.get("permissions-policy"):
        return 7, 7, []
    return 0, 7, [("Low", "Permissions-Policy", "Header missing",
                   "Add a Permissions-Policy disabling unused features, e.g. camera=(), microphone=(), geolocation=().")]


def check_cookies(h):
    cookies = h.get("set-cookie-list", [])
    if not cookies:
        return 15, 15, [("Info", "Cookies", "No Set-Cookie headers present (full marks; nothing to flag)", "")]
    findings, total = [], 0.0
    per = 15 / len(cookies)
    for raw in cookies:
        name = raw.split("=", 1)[0].strip()
        low = raw.lower()
        pts = per
        if "secure" not in low:
            pts -= per * 0.4
            findings.append(("High", f"Cookie '{name}'", "Missing Secure flag",
                             "Set the Secure attribute so the cookie is only sent over HTTPS."))
        if "httponly" not in low:
            pts -= per * 0.3
            findings.append(("Medium", f"Cookie '{name}'", "Missing HttpOnly flag",
                             "Set HttpOnly on session cookies to limit XSS cookie theft."))
        if "samesite" not in low:
            pts -= per * 0.3
            findings.append(("Medium", f"Cookie '{name}'", "Missing SameSite attribute",
                             "Set SameSite=Lax (or Strict) to reduce CSRF exposure."))
        elif "samesite=none" in low and "secure" not in low:
            findings.append(("High", f"Cookie '{name}'", "SameSite=None without Secure (browsers will reject)",
                             "Pair SameSite=None with Secure, or use Lax/Strict."))
        total += max(pts, 0)
    return round(total), 15, findings


def check_server_disclosure(h):
    findings, pts = [], 15
    server = h.get("server", "")
    powered = h.get("x-powered-by", "")
    if re.search(r"\d+\.\d+", server):
        pts -= 8
        findings.append(("Low", "Server disclosure", f"Server header reveals version: '{server}'",
                         "Suppress version numbers in the Server header (e.g. ServerTokens Prod on Apache)."))
    if powered:
        pts -= 7
        findings.append(("Low", "X-Powered-By disclosure", f"Technology disclosed: '{powered}'",
                         "Remove the X-Powered-By header; it only helps attackers fingerprint the stack."))
    return max(pts, 0), 15, findings


CHECKS = [check_hsts, check_csp, check_content_type, check_framing,
          check_referrer, check_permissions, check_cookies, check_server_disclosure]


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

def grade(score):
    return "A" if score >= 90 else "B" if score >= 75 else "C" if score >= 60 else "D" if score >= 40 else "F"


def analyse(label, text):
    status, headers = parse_response(text)
    total, maximum, findings = 0, 0, []
    for fn in CHECKS:
        pts, mx, f = fn(headers)
        total += pts
        maximum += mx
        findings.extend(f)
    score = round(100 * total / maximum) if maximum else 0
    print(f"\n{'=' * 72}")
    print(f"Target: {label}")
    print(f"Status line: {status or '(none)'}")
    print(f"Score: {score}/100  Grade: {grade(score)}")
    print(f"{'-' * 72}")
    if findings:
        order = {"High": 0, "Medium": 1, "Low": 2, "Info": 3}
        for sev, check, detail, fix in sorted(findings, key=lambda x: order[x[0]]):
            print(f"[{sev:>6}] {check}: {detail}")
            if fix:
                print(f"         -> {fix}")
    else:
        print("No findings. All checks passed.")
    return score


def main():
    ap = argparse.ArgumentParser(description="Web Security Posture Checker")
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--demo", action="store_true", help="Analyse the bundled sample responses (offline)")
    g.add_argument("--url", help="Fetch and analyse a live URL")
    g.add_argument("--file", help="Analyse a saved raw HTTP response file")
    args = ap.parse_args()

    if args.demo:
        for name in ("hardened.txt", "weak.txt"):
            path = HERE / "sample_responses" / name
            analyse(f"sample: {name}", path.read_text())
    elif args.url:
        analyse(args.url, fetch_url(args.url))
    else:
        analyse(args.file, Path(args.file).read_text())
    return 0


if __name__ == "__main__":
    sys.exit(main())
