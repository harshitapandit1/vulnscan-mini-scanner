from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from urllib.parse import urlparse
from port_scanner import scan_ports
from service_detector import detect_service
from vulnerability_checker import check_vulnerabilities
from web_checker import check_web

HOST = "127.0.0.1"
PORT = 5000

MAX_PORT_RANGE = 2048          # keep in sync with app.js
DEFAULT_TIMEOUT = 0.6          # seconds per port
MIN_TIMEOUT, MAX_TIMEOUT = 0.3, 5.0
# Only the dashboard (served by Live Server or this backend) may talk to the API.
# Without this, ANY website open in your browser could trigger scans from your computer.
ALLOWED_ORIGINS = {
    "http://127.0.0.1:5500", "http://localhost:5500",     # VS Code Live Server (default port)
    f"http://{HOST}:{PORT}", f"http://localhost:{PORT}",
}
ALLOWED_HOSTS = {f"{HOST}:{PORT}", f"localhost:{PORT}"}   # blocks DNS-rebinding tricks

WEB_TIMEOUT = 3.0              # seconds per web request (web pages are slower than a port check)

SEVERITY_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3}


def pick_mode(scan_type):
    """Map the label sent by the page to 'network', 'web' or 'full'."""
    label = str(scan_type or "").lower()
    if "full" in label:
        return "full"
    if "web" in label:
        return "web"
    return "network"


class ScanHandler(BaseHTTPRequestHandler):
    def _send_json(self, status_code, data):
        body = json.dumps(data).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json")
        origin = self.headers.get("Origin")
        if origin in ALLOWED_ORIGINS:
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Vary", "Origin")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _request_allowed(self):
        """Reject requests from other websites or with a foreign Host header."""
        host_ok = self.headers.get("Host") in ALLOWED_HOSTS
        origin = self.headers.get("Origin")
        origin_ok = origin is None or origin in ALLOWED_ORIGINS
        if host_ok and origin_ok:
            return True
        self._send_json(403, {"error": "Request not allowed"})
        return False

    def do_OPTIONS(self):
        if not self._request_allowed():
            return
        self._send_json(200, {"ok": True})

    def do_GET(self):
        if not self._request_allowed():
            return
        if urlparse(self.path).path == "/api/health":
            self._send_json(200, {"status": "ok", "service": "VulnScan backend"})
        else:
            self._send_json(404, {"error": "Endpoint not found"})

    def do_POST(self):
        if not self._request_allowed():
            return
        if urlparse(self.path).path != "/api/scan":
            self._send_json(404, {"error": "Endpoint not found"})
            return

        try:
            length = int(self.headers.get("Content-Length", "0"))
            payload = json.loads(self.rfile.read(length).decode("utf-8") or "{}")

            target = str(payload.get("target", "")).strip()
            mode = pick_mode(payload.get("scan_type"))
            start_port = int(payload.get("start_port", 1))
            end_port = int(payload.get("end_port", 1024))

            # Optional connection timeout from the Settings page (clamped to a safe range)
            try:
                timeout = float(payload.get("timeout", DEFAULT_TIMEOUT))
            except (TypeError, ValueError):
                timeout = DEFAULT_TIMEOUT
            timeout = max(MIN_TIMEOUT, min(timeout, MAX_TIMEOUT))

            if not target:
                self._send_json(400, {"error": "Target is required"})
                return
            if not (1 <= start_port <= 65535 and 1 <= end_port <= 65535):
                self._send_json(400, {"error": "Ports must be between 1 and 65535"})
                return
            if start_port > end_port:
                self._send_json(400, {"error": "start_port must be <= end_port"})
                return
            if end_port - start_port > MAX_PORT_RANGE:
                self._send_json(400, {"error": f"The port range cannot exceed {MAX_PORT_RANGE} ports."})
                return

            open_ports = scan_ports(target, start_port, end_port, timeout)

            for item in open_ports:
                item["service_name"], item["version"] = detect_service(target, item["port"])

            findings = []
            if mode in ("network", "full"):
                findings += check_vulnerabilities(target, open_ports)
            if mode in ("web", "full"):
                findings += check_web(target, open_ports, max(WEB_TIMEOUT, timeout))
            findings.sort(key=lambda f: SEVERITY_ORDER.get(str(f.get("severity", "INFO")).upper(), 4))

            severity_counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}

            for finding in findings:
                severity = finding.get("severity", "INFO").upper()
                severity_counts[severity] = severity_counts.get(severity, 0) + 1

            self._send_json(200, {
                "target": target,
                "scan_type": {"network": "Network Scan", "web": "Web Application Scan",
                              "full": "Full Scan (Network + Web)"}[mode],
                "ports_scanned": end_port - start_port + 1,
                "open_ports": open_ports,
                "findings": findings,
                "summary": {"severity_counts": severity_counts}
            })

        # JSONDecodeError is a subclass of ValueError, so it must be caught first
        except json.JSONDecodeError:
            self._send_json(400, {"error": "Request body must contain valid JSON"})
        except (ValueError, TypeError):
            self._send_json(400, {"error": "Invalid port values"})
        except RuntimeError as exc:                  # e.g. target could not be resolved
            self._send_json(400, {"error": str(exc)})
        except Exception as exc:
            self._send_json(500, {"error": "Scanner error", "details": str(exc)})

    def log_message(self, format, *args):
        print("[VulnScan]", format % args)


if __name__ == "__main__":
    print(f"VulnScan backend running at http://{HOST}:{PORT}")
    print(f"Health check: http://{HOST}:{PORT}/api/health")
    print(f"Scan endpoint: POST http://{HOST}:{PORT}/api/scan")
    # Threading server: the health check still answers while a scan is running
    server = ThreadingHTTPServer((HOST, PORT), ScanHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping VulnScan backend...")
    finally:
        server.server_close()