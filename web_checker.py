"""Light, read-only web checks (GET requests only). Detects issues, never exploits them."""
import re
import ssl
import urllib.error
import urllib.request

HTTP_PORTS = {80, 8000, 8008, 8080, 8888}
HTTPS_PORTS = {443, 8443}

# header -> (severity, why it matters, fix)
SECURITY_HEADERS = {
    "Content-Security-Policy": ("MEDIUM", "No CSP, so injected scripts are not restricted by the browser.", "Add a Content-Security-Policy header."),
    "X-Frame-Options": ("LOW", "The page can be embedded in other sites (clickjacking).", "Add X-Frame-Options: DENY or SAMEORIGIN."),
    "X-Content-Type-Options": ("LOW", "Browsers may guess content types (MIME sniffing).", "Add X-Content-Type-Options: nosniff."),
    "Referrer-Policy": ("LOW", "Full URLs may leak to other sites in the Referer header.", "Add a Referrer-Policy header."),
    "Strict-Transport-Security": ("MEDIUM", "Browsers are not told to always use HTTPS for this site.", "Add Strict-Transport-Security (HSTS)."),
}

# path, severity, title, why, signature check on the response body
SENSITIVE_PATHS = [
    ("/.env", "HIGH", ".env file exposed", "Environment files usually contain passwords and API keys.",
     lambda b: re.search(rb"^[A-Za-z_][A-Za-z0-9_]*\s*=", b, re.M) is not None and b"<html" not in b.lower()),
    ("/.git/HEAD", "HIGH", "Git repository exposed", "Source code and history may be downloadable.",
     lambda b: b.strip().startswith(b"ref:")),
    ("/server-status", "MEDIUM", "Apache server-status exposed", "Reveals live requests and server internals.",
     lambda b: b"Apache Server Status" in b),
    ("/phpinfo.php", "MEDIUM", "phpinfo() page exposed", "Reveals PHP configuration and paths.",
     lambda b: b"phpinfo()" in b or b"PHP Version" in b),
]


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None          # we want to see the redirect, not follow it


def _finding(severity, port, title, description, fix=None):
    return {"severity": severity, "port": port, "title": title,
            "description": description + (f" Fix: {fix}" if fix else "")}


def _host(target):
    host = target.replace("http://", "").replace("https://", "")
    return host.split("/")[0].split(":")[0].strip()


def _fetch(url, timeout):
    """GET url without following redirects. Returns (status, headers, body) or None."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False              # scanners must cope with self-signed certs
    ctx.verify_mode = ssl.CERT_NONE
    opener = urllib.request.build_opener(_NoRedirect, urllib.request.HTTPSHandler(context=ctx))
    request = urllib.request.Request(url, headers={"User-Agent": "VulnScan-edu/1.0"})
    try:
        with opener.open(request, timeout=timeout) as resp:
            return resp.status, resp.headers, resp.read(8192)
    except urllib.error.HTTPError as err:   # 3xx / 4xx / 5xx still carry useful headers
        try:
            body = err.read(8192)
        except OSError:
            body = b""
        return err.code, err.headers, body
    except (OSError, ValueError):
        return None


def _check_one(host, port, https, timeout, open_numbers):
    scheme = "https" if https else "http"
    base = f"{scheme}://{host}:{port}"
    findings = []

    reply = _fetch(base + "/", timeout)
    if reply is None:
        return findings
    status, headers, body = reply

    # 1. Security headers (HSTS only makes sense over HTTPS)
    csp = headers.get("Content-Security-Policy", "")
    for name, (sev, why, fix) in SECURITY_HEADERS.items():
        if name == "Strict-Transport-Security" and not https:
            continue
        if name in headers:
            continue
        if name == "X-Frame-Options" and "frame-ancestors" in csp.lower():
            continue
        findings.append(_finding(sev, port, f"Missing header: {name}", why, fix))

    # 2. Technology disclosure
    if headers.get("X-Powered-By"):
        findings.append(_finding("INFO", port, "X-Powered-By header discloses technology",
                                 f"The server announces: {headers.get('X-Powered-By')[:80]}.",
                                 "Remove the X-Powered-By header."))

    # 3. Cookie flags
    for cookie in headers.get_all("Set-Cookie") or []:
        name = cookie.split("=", 1)[0].strip()[:40]
        flags = cookie.lower()
        missing = []
        if "httponly" not in flags:
            missing.append("HttpOnly")
        if https and "secure" not in flags:
            missing.append("Secure")
        if "samesite" not in flags:
            missing.append("SameSite")
        if missing:
            sev = "MEDIUM" if ("HttpOnly" in missing or "Secure" in missing) else "LOW"
            findings.append(_finding(sev, port, f"Insecure cookie: {name}",
                                     f"The cookie is missing: {', '.join(missing)}.",
                                     "Set HttpOnly, Secure (HTTPS) and SameSite on cookies."))

    # 4. HTTP should redirect to HTTPS when HTTPS is available
    if not https and 443 in open_numbers:
        location = headers.get("Location", "")
        if not (300 <= status < 400 and location.lower().startswith("https://")):
            findings.append(_finding("MEDIUM", port, "HTTP does not redirect to HTTPS",
                                     "HTTPS is available but plain HTTP is still served without redirecting.",
                                     "Redirect all HTTP requests to HTTPS."))

    # 5. Directory listing
    if status == 200 and (b"<title>Index of /" in body or b"Directory listing for /" in body):
        findings.append(_finding("MEDIUM", port, "Directory listing enabled",
                                 "The server lists the files in a directory.",
                                 "Disable directory indexing."))

    # 6. Sensitive files (content signatures avoid false positives on catch-all servers)
    for path, sev, title, why, looks_real in SENSITIVE_PATHS:
        found = _fetch(base + path, timeout)
        if found and found[0] == 200 and looks_real(found[2]):
            findings.append(_finding(sev, port, f"{title}: {path}", why,
                                     "Remove the file or block access to it."))

    return findings


def check_web(target, open_ports, timeout=3.0):
    """Run the web checks on every open HTTP/HTTPS port. Returns a list of findings."""
    host = _host(target)
    open_numbers = {p["port"] for p in open_ports}
    findings = []

    for item in open_ports:
        port = item["port"]
        if port in HTTPS_PORTS:
            findings += _check_one(host, port, True, timeout, open_numbers)
        elif port in HTTP_PORTS:
            findings += _check_one(host, port, False, timeout, open_numbers)

    if not any(p["port"] in HTTP_PORTS | HTTPS_PORTS for p in open_ports):
        findings.append(_finding("INFO", None, "No web server found",
                                 "No standard web ports (80, 443, 8000, 8008, 8080, 8443, 8888) were open, so no web checks ran."))
    return findings