# VulnScan - Mini Vulnerability Scanner

A small, educational vulnerability scanner with a web dashboard. It scans a target for open TCP ports, identifies the services running on them, checks a set of common web security weaknesses, and produces a report. It **detects** problems only - it never tries to exploit them.

> **Use only on systems you own or have written permission to test.** Scanning other people's systems without permission may be illegal.

Author: _your name_  |  Course / Task: Vulnerability Scanner (Mini Project)

---

## What it does

| Feature | How it works |
|---|---|
| **Open port scanning** | Multi-threaded TCP connect scan (200 ports at a time) using Python's `socket` module |
| **Service and version detection** | Reads the banner a service sends (SSH, FTP, SMTP, HTTP `Server` header, etc.) and falls back to well-known port names |
| **Outdated software detection** | Matches detected versions against a built-in list of known-old or known-vulnerable releases (e.g. Apache 2.4.7, OpenSSH 6.x, vsftpd 2.3.4) |
| **Exposed-service findings** | Flags risky open ports such as SMB (445), RPC (135), Telnet, RDP, VNC and databases, each with a severity and a recommended fix |
| **Web application checks** | Missing security headers, insecure cookies, directory listing, HTTP not redirecting to HTTPS, and exposed files (`/.env`, `/.git/HEAD`, `/server-status`, `/phpinfo.php`) |
| **Vulnerability report** | Results page with severity colours, plus downloadable **HTML** and **JSON** reports |

### Scan types

- **Network Scan** - ports, services, versions, exposed-service and outdated-version findings
- **Web Application Scan** - finds web servers on open ports, then runs the web checks
- **Full Scan (Network + Web)** - both

### Severity levels

| Level | Meaning |
|---|---|
| HIGH | Needs prompt attention (e.g. exposed `.env`, exposed SMB or database) |
| MEDIUM | A weakness that should be reviewed and fixed |
| LOW | Lower-risk exposure that should still be documented |
| INFO | Informational (e.g. version banner disclosed) |

---

## Project structure

```
VulnScan_Modular/
├── index.html                  # Dashboard (all pages)
├── css/style.css               # Styling
├── js/app.js                   # Front end: calls the backend, renders results, downloads reports
└── backend/
    ├── main.py                 # HTTP API server (POST /api/scan, GET /api/health)
    ├── port_scanner.py         # Threaded TCP connect scanner
    ├── service_detector.py     # Banner grabbing and version parsing
    ├── vulnerability_checker.py# Rules for risky ports and outdated versions
    └── web_checker.py          # Header, cookie, path and redirect checks
```

---

## How to run

**Requirements:** Python 3.7 or newer. No packages to install - everything uses the standard library.

1. **Start the backend** (keep this terminal open):
   ```
   cd backend
   python main.py
   ```
   You should see `VulnScan backend running at http://127.0.0.1:5000`. Health check: <http://127.0.0.1:5000/api/health>

2. **Open the dashboard with Live Server.** In VS Code, right-click `index.html` and choose **Open with Live Server**. It opens at `http://127.0.0.1:5500`. Opening the file by double-clicking it will **not** work, because the backend only accepts requests from the dashboard's own address (see Security notes).

3. **Run a scan.** Go to **Scan Target**, enter a target, choose a scan type, tick the permission box and click **Start Scan**. Results open on the **Scan Results** page.

**After changing any `.py` file, restart `main.py`.** After changing `index.html`, `app.js` or `style.css`, just refresh the browser (`Ctrl+Shift+R`).

### Settings

On the **Settings** page you can set the default port range and the **Connection Timeout** (seconds per port). The backend limits the timeout to 0.3 - 5 seconds. Use 0.6 or higher for remote targets - a very short timeout can make a scan miss open ports.

---

## API (for reference)

`POST /api/scan` with JSON:

```json
{
  "target": "127.0.0.1",
  "start_port": 1,
  "end_port": 1024,
  "timeout": 0.6,
  "scan_type": "Full Scan (Network + Web)"
}
```

Returns `target`, `scan_type`, `ports_scanned`, `open_ports` (port, service_name, version), `findings` (severity, port, title, description) and `summary.severity_counts`. Findings are sorted most severe first.

---

## Safe ways to test it

1. **Your own machine** - scan `127.0.0.1`, ports 1 - 1024.
2. **A local test web server with a fake secret** (to see the web checks work):
   ```
   mkdir webtest
   cd webtest
   Set-Content -Path .env -Value "DB_PASSWORD=hunter2" -Encoding ascii
   python -m http.server 8000 --bind 127.0.0.1
   ```
   Then run a **Web Application Scan** on `127.0.0.1`, ports 7990 - 8010. Expect `.env file exposed` (HIGH), directory listing (MEDIUM) and missing-header findings.
3. **`scanme.nmap.org`** - a host the Nmap project provides for testing. Scan it lightly (ports 1 - 1024, once) and not repeatedly.


---

## Limitations (please read)

This is a learning tool, not a replacement for professional scanners such as Nmap, Nessus or OpenVAS.

- **TCP only.** No UDP scanning, and no raw-packet (SYN) scanning - it uses full connect scans.
- **One host at a time.** IP ranges and CIDR blocks (e.g. `192.168.1.0/24`) are not supported.
- **At most 2048 ports per scan.**
- **Version-based findings are heuristic.** A server can hide or fake its banner, and distributions such as Ubuntu often backport security fixes without changing the version number. "Outdated" means "worth checking", not "proven vulnerable".
- **The rule list is small.** It covers well-known risky ports and a handful of known-bad versions. It does not query a CVE database.
- **Web checks run only on standard web ports** (80, 443, 8000, 8008, 8080, 8443, 8888) and use plain `GET` requests. They do not crawl the site, test forms or inputs, or log in.
- **HTTPS certificates are not validated.** Self-signed certificates are accepted so the headers can be read; expired or invalid certificates are not reported.
- **Nothing is exploited.** The tool only observes what a server openly returns.
- **Local use only.** The backend listens on `127.0.0.1` and is not meant to be exposed to a network.

---

## Security notes

- Text received from a scanned target (banners, headers, cookie names) is treated as untrusted: it is stripped of control characters and length-limited on the backend, and HTML-escaped before it is shown in the dashboard.
- The dashboard requires a permission checkbox before every scan.
- **The backend only accepts requests from the dashboard itself.** It allows the origins `http://127.0.0.1:5500` and `http://localhost:5500` (the VS Code Live Server default) and refuses requests from any other website or with a foreign `Host` header. This stops a web page open in your browser from using your computer as a scanner. If your Live Server runs on a different port, add that address to `ALLOWED_ORIGINS` in `backend/main.py`.
- The backend listens on `127.0.0.1` only. Do not change `HOST` to `0.0.0.0`, which would expose the scanner to your whole network.

## Troubleshooting

| Problem | Likely cause and fix |
|---|---|
| "Scan failed - make sure the Python backend is running" | `main.py` is not running, or was not restarted after a change. Run `cd backend` then `python main.py`. |
| Progress stays at 20% | The backend is still working, or has stopped. Check the terminal running `main.py`. |
| "No open ports found" on a remote target | The connection timeout is probably too short. Raise it in **Settings** (try 1.0 - 2.0). |
| Open ports show but no web findings | Web checks only run on the standard web ports listed above. |
| "Scan failed" although `main.py` is running | The page was opened from an address the backend does not allow. Open it through Live Server at `http://127.0.0.1:5500`, or add your address to `ALLOWED_ORIGINS` in `backend/main.py` and restart. |
| Page shows old behaviour | Hard refresh with `Ctrl+Shift+R`. |