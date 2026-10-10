"""Fast multi-threaded TCP connect scanner (standard library only)."""
import socket
from concurrent.futures import ThreadPoolExecutor

TIMEOUT = 0.6      # seconds to wait per port
MAX_WORKERS = 200  # ports checked at the same time


def _check_port(ip, port, timeout):
    """Return the port number if a TCP connection succeeds, else None."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            if sock.connect_ex((ip, port)) == 0:
                return port
    except OSError:
        pass
    return None


def scan_ports(target, start_port, end_port, timeout=TIMEOUT):
    """Scan start_port..end_port on target. Returns [{"port": N}, ...]."""
    # Accept "http://host:5000/path" as well as plain hosts
    host = target.replace("http://", "").replace("https://", "")
    host = host.split("/")[0].split(":")[0].strip()

    try:
        ip = socket.gethostbyname(host)
    except socket.gaierror:
        raise RuntimeError(f"Could not resolve target: {host}")

    ports = range(start_port, end_port + 1)
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        results = pool.map(lambda p: _check_port(ip, p, timeout), ports)

    return [{"port": p} for p in results if p is not None]