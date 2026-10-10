// ============================================================
// VulnScan - app.js
// Talks to the Python backend at http://127.0.0.1:5000
// ============================================================

const API_URL = 'http://127.0.0.1:5000/api/scan';
const MAX_PORT_RANGE = 2048;           // must match main.py

const $ = id => document.getElementById(id);

// Escape anything that came from the target (banners, versions, titles).
// Without this, a hostile server could inject HTML/JS into the page.
function esc(value) {
    return String(value === null || value === undefined ? '' : value)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

function setText(id, value) {
    const el = $(id);
    if (el) el.textContent = value;
}

function on(id, eventName, handler) {
    const el = $(id);
    if (el) el.addEventListener(eventName, handler);
}


// ------------------------------------------------------------
// Navigation
// ------------------------------------------------------------

const PAGE_TITLES = {
    dashboard: 'Dashboard',
    scan: 'Scan Target',
    results: 'Scan Results',
    reports: 'Reports',
    settings: 'Settings',
    about: 'About'
};

function goToPage(tab) {
    document.querySelectorAll('.nav-item').forEach(button => {
        button.classList.toggle('active', button.dataset.tab === tab);
    });

    document.querySelectorAll('.page').forEach(page => {
        page.classList.toggle('active', page.dataset.page === tab);
    });

    setText('topbarTitle', PAGE_TITLES[tab] || 'Dashboard');
    window.scrollTo({ top: 0, behavior: 'smooth' });
}

document.querySelectorAll('.nav-item').forEach(button => {
    button.addEventListener('click', () => goToPage(button.dataset.tab));
});


// ------------------------------------------------------------
// Severity helpers
// ------------------------------------------------------------

function badgeClass(severity) {
    const s = (severity || '').toUpperCase();
    if (s === 'HIGH') return 'high';
    if (s === 'MEDIUM') return 'medium';
    if (s === 'LOW') return 'low';
    return 'info';
}

// Risk of a port = the worst finding raised for that port.
function portRisk(portNumber, findings) {
    const rank = { HIGH: 3, MEDIUM: 2, LOW: 1 };
    let level = 0;

    findings.forEach(f => {
        if (Number(f.port) === Number(portNumber)) {
            level = Math.max(level, rank[(f.severity || '').toUpperCase()] || 0);
        }
    });

    return level === 3 ? 'high' : level === 2 ? 'medium' : 'low';
}


// ------------------------------------------------------------
// Render a report on every page
// ------------------------------------------------------------

function renderReport(report) {
    const target = report.target || '-';
    const scanType = report.scan_type || '-';
    const openPorts = report.open_ports || [];
    const findings = report.findings || [];
    const counts = (report.summary && report.summary.severity_counts) || {};
    const portsScanned = report.ports_scanned || 0;

    // Dashboard summary
    setText('metaTarget', target);
    setText('metaDate', 'Scan Date: ' + (report.scan_date || '-'));
    setText('metaType', scanType);
    setText('statPorts', portsScanned);
    setText('statOpen', openPorts.length);
    setText('statFindings', findings.length);
    setText('statInfo', counts.INFO || 0);

    // Results + Reports pages
    setText('resultsTarget', target);
    setText('resultsType', scanType);
    setText('resultsPorts', portsScanned);
    setText('resultsFindings', findings.length);
    setText('reportsTarget1', target);
    setText('reportsTarget2', target);
    setText('infoTarget', target);
    setText('infoType', scanType);
    setText('infoPorts', portsScanned);
    setText('infoFindings', findings.length);

    // Open ports table
    const portsHtml = openPorts.length
        ? openPorts.map(p => {
            const risk = portRisk(p.port, findings);
            return `
                <tr>
                    <td>${esc(p.port)}/tcp</td>
                    <td><span class="badge open">Open</span></td>
                    <td>${esc(p.service_name || 'Unknown')}</td>
                    <td>${esc(p.version || 'Version not detected')}</td>
                    <td><span class="badge ${risk}">${risk.charAt(0).toUpperCase() + risk.slice(1)}</span></td>
                </tr>`;
        }).join('')
        : `<tr class="empty-row"><td colspan="5">No open ports found.</td></tr>`;

    // Findings table
    const findingsHtml = findings.length
        ? findings.map(f => `
                <tr>
                    <td><span class="badge ${badgeClass(f.severity)}">${esc(f.severity || 'INFO')}</span></td>
                    <td>${esc(f.port || '-')}</td>
                    <td>${esc(f.title || '-')}</td>
                    <td>${esc(f.description || '-')}</td>
                </tr>`).join('')
        : `<tr class="empty-row"><td colspan="4">No findings raised.</td></tr>`;

    ['portsTable', 'portsTable2'].forEach(id => {
        const el = $(id);
        if (el) el.innerHTML = portsHtml;
    });

    ['findingsTable', 'findingsTable2'].forEach(id => {
        const el = $(id);
        if (el) el.innerHTML = findingsHtml;
    });

    window.currentReport = report;
}


// Empty every results area so old results are never shown next to a new or failed scan
function clearResults(message) {
    renderReport({
        target: '-', scan_type: '-', scan_date: '-',
        open_ports: [], findings: [], summary: {}
    });

    const row = cols =>
        `<tr class="empty-row"><td colspan="${cols}">${esc(message)}</td></tr>`;

    ['portsTable', 'portsTable2'].forEach(id => {
        const el = $(id);
        if (el) el.innerHTML = row(5);
    });

    ['findingsTable', 'findingsTable2'].forEach(id => {
        const el = $(id);
        if (el) el.innerHTML = row(4);
    });

    window.currentReport = null;
}


// ------------------------------------------------------------
// Progress (estimated while the backend works)
// ------------------------------------------------------------

const startBtn = $('startBtn');
const steps = document.querySelectorAll('#progressList li');
const fill = $('progressFill');
const pct = $('progressPct');

let progressTimer = null;

function stepDot(step) {
    return step.querySelector('.progress-dot, .step-dot');
}

function setProgress(percent) {
    if (fill) fill.style.width = percent + '%';
    if (pct) pct.textContent = percent + '%';
}

function markStep(index, state) {
    const step = steps[index];
    if (!step) return;

    const dot = stepDot(step);
    step.classList.toggle('done', state === 'done');

    if (dot) {
        dot.classList.toggle('done', state === 'done');
        dot.classList.toggle('active', state === 'active');
        dot.textContent = state === 'done' ? '✓' : '';
    }
}

function stopProgress() {
    if (progressTimer) {
        clearInterval(progressTimer);
        progressTimer = null;
    }
}

function resetProgress() {
    stopProgress();
    steps.forEach((_, i) => markStep(i, 'idle'));
    setProgress(0);
}

// Advances through the first four steps while waiting; the last step
// ("Generating report") is only completed when the backend answers.
function startProgress() {
    resetProgress();

    let current = 0;
    markStep(0, 'active');
    setProgress(10);

    progressTimer = setInterval(() => {
        if (current >= steps.length - 2) return;   // hold on the 4th step
        markStep(current, 'done');
        current++;
        markStep(current, 'active');
        setProgress(Math.round(((current + 1) / steps.length) * 90));
    }, 1200);
}

function completeProgress() {
    stopProgress();
    steps.forEach((_, i) => markStep(i, 'done'));
    setProgress(100);
}


// ------------------------------------------------------------
// Run a real scan
// ------------------------------------------------------------

async function runScan() {
    if (!startBtn || startBtn.disabled) return;

    const permission = $('permissionCheck');
    if (permission && !permission.checked) {
        alert('Please confirm you own this target or have explicit permission to test it.\n\n' +
              'Tick the box on the Scan Target page.');
        goToPage('scan');
        return;
    }

    const targetInput = $('targetInput');
    const target = targetInput && targetInput.value.trim()
        ? targetInput.value.trim()
        : '127.0.0.1';

    const scanTypeInput = $('scanType');
    const scanType = scanTypeInput ? scanTypeInput.value : 'Network Scan';

    const startPort = $('startPort') ? parseInt($('startPort').value, 10) : 1;
    const endPort = $('endPort') ? parseInt($('endPort').value, 10) : 1024;

    // Only a single host is supported (no ranges like 192.168.1.1-50 or 192.168.1.0/24)
    if (/^\d+\.\d+\.\d+\.\d+\s*-\s*\d+$/.test(target) ||
        /^\d+\.\d+\.\d+\.\d+\/\d+$/.test(target)) {
        alert('Enter a single IP address or domain, not a range.\n\nExample: 127.0.0.1');
        return;
    }

    if (isNaN(startPort) || isNaN(endPort) ||
        startPort < 1 || endPort > 65535 || startPort > endPort) {
        alert('Please enter a valid port range (1 - 65535).');
        return;
    }

    if (endPort - startPort > MAX_PORT_RANGE) {
        alert('The port range is limited to ' + MAX_PORT_RANGE + ' ports per scan.');
        return;
    }

    startBtn.disabled = true;
    clearResults('Scan in progress...');
    startProgress();

    try {
        const response = await fetch(API_URL, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                target: target,
                start_port: startPort,
                end_port: endPort,
                scan_type: scanType,
                timeout: parseFloat($('settingTimeout') ? $('settingTimeout').value : '0.6') || 0.6
            })
        });

        const report = await response.json();

        if (!response.ok) {
            throw new Error(
                (report.error || 'Scanner backend returned an error.') +
                (report.details ? '\n' + report.details : '')
            );
        }

        report.scan_type = scanType;
        report.scan_date = new Date().toLocaleString('en-GB', {
            day: 'numeric', month: 'short', year: 'numeric',
            hour: '2-digit', minute: '2-digit'
        });

        completeProgress();
        renderReport(report);
        goToPage('results');

    } catch (error) {
        console.error('Scan error:', error);
        resetProgress();
        clearResults('Scan failed - no results.');

        // A TypeError means the browser could not reach the backend at all
        const unreachable = error instanceof TypeError;
        alert('Scan failed.\n\n' + error.message +
              (unreachable
                  ? '\n\nCould not reach the backend. Make sure it is running (python main.py) and that this page is opened from http://127.0.0.1:5500.'
                  : ''));

    } finally {
        startBtn.disabled = false;
    }
}

on('startBtn', 'click', runScan);


// ------------------------------------------------------------
// Scan Target page
// ------------------------------------------------------------

on('startBtn2', 'click', async () => {
    const permission = $('permissionCheck');

    if (permission && !permission.checked) {
        alert('Please confirm you own this target or have explicit permission to test it.');
        return;
    }

    const targetInput2 = $('targetInput2');
    const target = targetInput2 && targetInput2.value.trim()
        ? targetInput2.value.trim()
        : '127.0.0.1';

    if ($('targetInput')) $('targetInput').value = target;
    if ($('scanType') && $('scanType2')) $('scanType').value = $('scanType2').value;

    goToPage('dashboard');
    await runScan();
});


// ------------------------------------------------------------
// Quick actions
// ------------------------------------------------------------

on('newScanBtn', 'click', () => goToPage('scan'));

on('viewReportBtn', 'click', () => goToPage('results'));

on('loadJsonBtn', 'click', () => {
    const input = $('fileInput');
    if (input) input.click();
});

on('fileInput', 'change', event => {
    const file = event.target.files[0];
    if (!file) return;

    const reader = new FileReader();

    reader.onload = e => {
        try {
            const report = JSON.parse(e.target.result);
            renderReport(report);
            goToPage('results');
        } catch (error) {
            alert('Could not parse this file as a valid scan_report.json.');
        }
    };

    reader.readAsText(file);
    event.target.value = '';      // allow loading the same file again
});


// ------------------------------------------------------------
// Report downloads
// ------------------------------------------------------------

function downloadFile(filename, content, type) {
    const blob = new Blob([content], { type: type });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');

    link.href = url;
    link.download = filename;
    document.body.appendChild(link);
    link.click();
    link.remove();

    setTimeout(() => URL.revokeObjectURL(url), 1000);
}

function downloadJsonReport() {
    if (!window.currentReport) {
        alert('Run a scan first.');
        return;
    }
    downloadFile('scan_report.json', JSON.stringify(window.currentReport, null, 4), 'application/json');
}

// A clean standalone report (not a copy of the app page)
function buildHtmlReport(report) {
    const ports = report.open_ports || [];
    const findings = report.findings || [];

    const portRows = ports.map(p => `
        <tr><td>${esc(p.port)}/tcp</td><td>${esc(p.service_name || 'Unknown')}</td>
        <td>${esc(p.version || 'Version not detected')}</td>
        <td class="${portRisk(p.port, findings)}">${esc(portRisk(p.port, findings).toUpperCase())}</td></tr>`).join('')
        || '<tr><td colspan="4">No open ports found.</td></tr>';

    const findingRows = findings.map(f => `
        <tr><td class="${badgeClass(f.severity)}">${esc((f.severity || 'INFO').toUpperCase())}</td>
        <td>${esc(f.port || '-')}</td><td>${esc(f.title || '-')}</td><td>${esc(f.description || '-')}</td></tr>`).join('')
        || '<tr><td colspan="4">No findings raised.</td></tr>';

    return `<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8">
<title>VulnScan Report - ${esc(report.target)}</title>
<style>
body{font-family:Arial,sans-serif;max-width:960px;margin:30px auto;padding:0 16px;color:#1a1a2e}
h1{margin-bottom:4px} h2{margin-top:32px}
.meta{color:#555;margin-bottom:20px}
table{width:100%;border-collapse:collapse;margin-top:8px}
th,td{border:1px solid #ccc;padding:8px;text-align:left;vertical-align:top;font-size:14px}
th{background:#f0f0f7}
.high{color:#c0182d;font-weight:bold}.medium{color:#b86e00;font-weight:bold}
.low{color:#1c7c3a;font-weight:bold}.info{color:#3552c9;font-weight:bold}
.note{margin-top:30px;font-size:12px;color:#777}
</style></head><body>
<h1>VulnScan Report</h1>
<div class="meta">Target: <b>${esc(report.target)}</b> &nbsp;|&nbsp; Scan type: ${esc(report.scan_type)}
 &nbsp;|&nbsp; Date: ${esc(report.scan_date)} &nbsp;|&nbsp; Ports scanned: ${esc(report.ports_scanned)}</div>
<h2>Open Ports &amp; Services</h2>
<table><tr><th>Port</th><th>Service</th><th>Version</th><th>Risk</th></tr>${portRows}</table>
<h2>Vulnerability Findings</h2>
<table><tr><th>Severity</th><th>Port</th><th>Issue</th><th>Description</th></tr>${findingRows}</table>
<div class="note">Generated by VulnScan - educational use only. Only scan systems you own or have permission to test.</div>
</body></html>`;
}

function downloadHtmlReport() {
    if (!window.currentReport) {
        alert('Run a scan first.');
        return;
    }
    downloadFile('scan_report.html', buildHtmlReport(window.currentReport), 'text/html');
}

on('downloadHtmlBtn', 'click', downloadHtmlReport);
on('dlHtmlRow', 'click', e => { e.preventDefault(); downloadHtmlReport(); });
on('dlJsonRow', 'click', e => { e.preventDefault(); downloadJsonReport(); });


// ------------------------------------------------------------
// Settings
// ------------------------------------------------------------

(function loadSettings() {
    try {
        const saved = JSON.parse(localStorage.getItem('vulnscanSettings') || 'null');
        if (!saved) return;

        if ($('settingStartPort')) $('settingStartPort').value = saved.startPort;
        if ($('settingEndPort')) $('settingEndPort').value = saved.endPort;
        if ($('settingTimeout')) $('settingTimeout').value = saved.timeout;
        if ($('startPort')) $('startPort').value = saved.startPort;
        if ($('endPort')) $('endPort').value = saved.endPort;
    } catch (error) {
        console.log('No saved settings.');
    }
})();

on('saveSettingsBtn', 'click', () => {
    const settings = {
        startPort: $('settingStartPort').value,
        endPort: $('settingEndPort').value,
        timeout: $('settingTimeout').value
    };

    try {
        localStorage.setItem('vulnscanSettings', JSON.stringify(settings));
    } catch (error) {
        console.log('Local storage unavailable.');
    }

    $('startPort').value = settings.startPort;
    $('endPort').value = settings.endPort;

    const note = $('settingsSavedNote');
    if (note) {
        note.classList.add('show');
        note.style.display = 'block';

        setTimeout(() => {
            note.classList.remove('show');
            note.style.display = 'none';
        }, 2000);
    }
});