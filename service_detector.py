"""Identify the service and (where possible) the version on an open port."""
import re
import socket

TIMEOUT = 1.5

COMMON_SERVICES = {
    20: "FTP-Data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 111: "RPCbind", 135: "MS-RPC (EPMAP)", 139: "NetBIOS",
    143: "IMAP", 443: "HTTPS", 445: "SMB (Microsoft-DS)", 465: "SMTPS",
    587: "SMTP", 902: "VMware Authentication", 912: "VMware Authentication",
    993: "IMAPS", 995: "POP3S", 1433: "MS SQL", 1521: "Oracle DB",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5900: "VNC",
    6379: "Redis", 8000: "HTTP (alt)", 8080: "HTTP (alt)", 8443: "HTTPS (alt)",
    27017: "MongoDB",
}

HTTP_PORTS = {80, 8000, 8008, 8080, 8888}


def _clean(text, limit=120):
    """Keep printable ASCII only and cap the length (banners are untrusted)."""
    text = re.sub(r"[^\x20-\x7e]", "", text)
    text = re.sub(r"(\s*,){2,}", ",", text).strip(" ,")   # tidy stray commas left by control bytes
    return text[:limit]


def _host(target):
    host = target.replace("http://", "").replace("https://", "")
    return host.split("/")[0].split(":")[0].strip()


def _grab_banner(host, port):
    """Connect and read whatever the service says first (or answer a HEAD for HTTP)."""
    try:
        with socket.create_connection((host, port), timeout=TIMEOUT) as sock:
            sock.settimeout(TIMEOUT)
            if port in HTTP_PORTS:
                sock.sendall(b"HEAD / HTTP/1.0\r\nHost: " + host.encode() + b"\r\n\r\n")
            return sock.recv(1024).decode("utf-8", errors="ignore")
    except (OSError, UnicodeError):
        return ""


def _parse_version(banner):
    if not banner:
        return None
    ssh = re.search(r"SSH-\d\.\d-(\S+)", banner)
    if ssh:
        return _clean(ssh.group(1).replace("_", " ", 1))
    server = re.search(r"^Server:\s*(.+)$", banner, re.I | re.M)
    if server:
        return _clean(server.group(1))
    first = banner.splitlines()[0] if banner.splitlines() else ""
    if re.match(r"(220|\+OK|\* OK)", first):          # FTP / SMTP / POP3 / IMAP greeting
        return _clean(re.sub(r"^(220|\+OK|\* OK)[ -]*", "", first))   # drop the status code
    return None


def detect_service(target, port):
    """Return (service_name, version_or_None)."""
    name = COMMON_SERVICES.get(port)
    if name is None:
        try:
            name = socket.getservbyport(port, "tcp").upper()
        except OSError:
            name = "Unknown"
    version = _parse_version(_grab_banner(_host(target), port))
    return name, version