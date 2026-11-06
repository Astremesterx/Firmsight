"""Executive HTML Security Audit Report Generator for FirmSight.

Aggregates findings from Firmware Extraction (Track 1), Binary & Memory
Audit (Track 2), and PCAP Network Threat Forensics (Track 3) into a
responsive, standalone, executive-ready HTML report.
"""

from dataclasses import dataclass
import datetime
import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Union


class ReportGenerator:
    """Generates self-contained, interactive HTML audit reports."""

    def __init__(self, workspace_dir: Optional[Union[str, Path]] = None) -> None:
        self.workspace_dir = Path(workspace_dir) if workspace_dir else Path.cwd()
        self.reports_dir = self.workspace_dir / "sandbox_workspace" / "reports"
        self.reports_dir.mkdir(parents=True, exist_ok=True)

    def generate(
        self,
        target_name: str = "vulnerable_router_arm.bin",
        architecture: str = "arm (little-endian)",
        emulation_verdict: str = "SUCCESS",
        duration: float = 1.82,
        credentials: Optional[List[Dict[str, Any]]] = None,
        vulnerabilities: Optional[List[Dict[str, Any]]] = None,
        memory_segments: Optional[List[Dict[str, Any]]] = None,
        exploit_info: Optional[Dict[str, Any]] = None,
        pcap_info: Optional[Dict[str, Any]] = None,
        output_file: Optional[Union[str, Path]] = None,
    ) -> Path:
        """Synthesizes all analysis results into a responsive HTML report."""
        out_path = Path(output_file) if output_file else self.reports_dir / "firmware_audit_report.html"

        creds = credentials or [
            {"rule_name": "Default Router Credential", "category": "DEFAULT_LOGIN", "severity": "HIGH", "snippet": "admin:password", "offset": 1024, "description": "Factory default router login detected"},
            {"rule_name": "RSA Private Key", "category": "PRIVATE_KEY", "severity": "CRITICAL", "snippet": "-----B...EY-----", "offset": 45020, "description": "Unencrypted TLS private key embedded in rootfs"},
            {"rule_name": "Hardcoded Password", "category": "PASSWORD", "severity": "HIGH", "snippet": "pass...1234", "offset": 18204, "description": "Cleartext password assignment found in rcS"},
        ]

        vulns = vulnerabilities or [
            {"function_name": "system", "vulnerability_type": "COMMAND_INJECTION", "severity": "CRITICAL", "cwe_id": "CWE-78", "description": "Direct shell command execution via /bin/sh without sanitization."},
            {"function_name": "strcpy", "vulnerability_type": "BUFFER_OVERFLOW", "severity": "HIGH", "cwe_id": "CWE-120", "description": "Unbounded string copy into 64-byte stack buffer."},
            {"function_name": "sprintf", "vulnerability_type": "BUFFER_OVERFLOW", "severity": "HIGH", "cwe_id": "CWE-134", "description": "Unbounded format string parsing in HTTP daemon."},
        ]

        segments = memory_segments or [
            {"vaddr_start": "0x00010000", "vaddr_end": "0x00028000", "size_bytes": 98304, "permissions": "r-x", "is_rwx": False, "risk": "LOW"},
            {"vaddr_start": "0x0002a000", "vaddr_end": "0x0004c000", "size_bytes": 139264, "permissions": "rwx", "is_rwx": True, "risk": "CRITICAL"},
            {"vaddr_start": "0x7efdf000", "vaddr_end": "0x7f000000", "size_bytes": 135168, "permissions": "rw-", "is_rwx": False, "risk": "LOW"},
        ]

        exploit = exploit_info or {
            "vulnerability": "Stack Buffer Overflow in Web Server (CWE-120 / CWE-121)",
            "status": "CRASH_VERIFIED",
            "payload_size": 512,
            "details": "Oversized HTTP URI parameter hijacked Instruction Pointer (PC) to 0x41326141.",
            "crashed_registers": {"pc": "0x41326141", "sp": "0x7efff8c0", "lr": "0x41326141", "r0": "0x00000000"},
        }

        pcap = pcap_info or {
            "total_packets": 6,
            "threat_score": 75,
            "threat_level": "CRITICAL",
            "alerts": [
                {"threat_name": "IoT Botnet C2 Beaconing", "severity": "CRITICAL", "description": "Mirai botnet heartbeat POST transmitted to 198.51.100.42:4444."},
                {"threat_name": "Unsanctioned Outbound WAN Traffic", "severity": "HIGH", "description": "Direct WAN socket connection attempted outside 192.168.1.0/24 subnet."},
            ],
        }

        # Calculate Overall Risk Score
        total_vulns = len(vulns) + len(creds) + len(pcap.get("alerts", []))
        risk_grade = "CRITICAL RISK" if total_vulns >= 5 else ("HIGH RISK" if total_vulns >= 3 else "MODERATE RISK")
        risk_badge_class = "danger" if "CRITICAL" in risk_grade else "warning"

        now_str = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

        # Build Credential rows
        cred_rows = "".join(
            f"<tr><td><span class='badge badge-{c['severity'].lower()}'>{c['severity']}</span></td>"
            f"<td><strong>{c['rule_name']}</strong></td>"
            f"<td><code>{c['snippet']}</code></td>"
            f"<td>0x{c['offset']:06x}</td>"
            f"<td>{c['description']}</td></tr>"
            for c in creds
        )

        # Build Vulnerability rows
        vuln_rows = "".join(
            f"<tr><td><span class='badge badge-{v['severity'].lower()}'>{v['severity']}</span></td>"
            f"<td><code>{v['function_name']}()</code></td>"
            f"<td>{v['cwe_id']}</td>"
            f"<td>{v['vulnerability_type']}</td>"
            f"<td>{v['description']}</td></tr>"
            for v in vulns
        )

        # Build Memory Segment rows
        mem_rows = "".join(
            f"<tr><td><code>{s['vaddr_start']} - {s['vaddr_end']}</code></td>"
            f"<td>{s['size_bytes']:,} bytes</td>"
            f"<td><code>{s['permissions']}</code></td>"
            f"<td><span class='badge badge-{'danger' if s['is_rwx'] else 'success'}'>{'RWX (VULNERABLE)' if s['is_rwx'] else 'SECURE'}</span></td></tr>"
            for s in segments
        )

        # Build Network Alert rows
        net_rows = "".join(
            f"<tr><td><span class='badge badge-{a['severity'].lower()}'>{a['severity']}</span></td>"
            f"<td><strong>{a['threat_name']}</strong></td>"
            f"<td>{a['description']}</td></tr>"
            for a in pcap.get("alerts", [])
        )

        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>FirmSight — Executive Firmware Security Audit Report</title>
    <style>
        :root {{
            --bg-primary: #0f172a;
            --bg-card: #1e293b;
            --border-color: #334155;
            --text-primary: #f8fafc;
            --text-secondary: #94a3b8;
            --accent-blue: #38bdf8;
            --accent-green: #22c55e;
            --accent-red: #ef4444;
            --accent-orange: #f97316;
            --accent-purple: #a855f7;
        }}
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            background-color: var(--bg-primary);
            color: var(--text-primary);
            line-height: 1.6;
            padding: 30px;
        }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        header {{
            background: linear-gradient(135deg, #1e293b 0%, #0f172a 100%);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            padding: 30px;
            margin-bottom: 25px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}
        .brand h1 {{ font-size: 28px; color: var(--accent-blue); letter-spacing: -0.5px; }}
        .brand p {{ color: var(--text-secondary); font-size: 14px; margin-top: 4px; }}
        .risk-banner {{
            padding: 12px 24px;
            border-radius: 8px;
            font-weight: 700;
            font-size: 16px;
            letter-spacing: 0.5px;
            text-align: center;
        }}
        .risk-banner.danger {{ background: rgba(239, 68, 68, 0.2); border: 1px solid var(--accent-red); color: var(--accent-red); }}
        .risk-banner.warning {{ background: rgba(249, 115, 22, 0.2); border: 1px solid var(--accent-orange); color: var(--accent-orange); }}
        .grid-stats {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 20px;
            margin-bottom: 25px;
        }}
        .card {{
            background-color: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: 10px;
            padding: 20px;
        }}
        .card h4 {{ color: var(--text-secondary); font-size: 12px; text-transform: uppercase; margin-bottom: 8px; }}
        .card .value {{ font-size: 24px; font-weight: 700; color: var(--text-primary); }}
        .card .subtext {{ font-size: 12px; color: var(--text-secondary); margin-top: 4px; }}
        section {{
            background-color: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: 10px;
            padding: 25px;
            margin-bottom: 25px;
        }}
        section h2 {{
            font-size: 18px;
            margin-bottom: 15px;
            padding-bottom: 8px;
            border-bottom: 1px solid var(--border-color);
            color: var(--accent-blue);
            display: flex;
            align-items: center;
            gap: 8px;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            font-size: 14px;
            margin-top: 10px;
        }}
        th, td {{
            text-align: left;
            padding: 12px;
            border-bottom: 1px solid var(--border-color);
        }}
        th {{ color: var(--text-secondary); font-weight: 600; font-size: 12px; text-transform: uppercase; }}
        tr:hover td {{ background-color: rgba(255, 255, 255, 0.02); }}
        code {{
            background-color: rgba(0, 0, 0, 0.4);
            padding: 2px 6px;
            border-radius: 4px;
            font-family: monospace;
            color: var(--accent-blue);
            font-size: 13px;
        }}
        .badge {{
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 11px;
            font-weight: 700;
            text-transform: uppercase;
        }}
        .badge-critical, .badge-danger {{ background: rgba(239, 68, 68, 0.2); color: var(--accent-red); border: 1px solid var(--accent-red); }}
        .badge-high {{ background: rgba(249, 115, 22, 0.2); color: var(--accent-orange); border: 1px solid var(--accent-orange); }}
        .badge-medium {{ background: rgba(234, 179, 8, 0.2); color: #eab308; border: 1px solid #eab308; }}
        .badge-success, .badge-low {{ background: rgba(34, 197, 94, 0.2); color: var(--accent-green); border: 1px solid var(--accent-green); }}
        .exploit-box {{
            background: rgba(239, 68, 68, 0.05);
            border: 1px solid rgba(239, 68, 68, 0.3);
            border-radius: 8px;
            padding: 15px;
            margin-top: 10px;
        }}
        .register-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 10px;
            margin-top: 12px;
        }}
        .reg-card {{
            background: rgba(0, 0, 0, 0.3);
            border: 1px solid var(--border-color);
            padding: 8px 12px;
            border-radius: 6px;
            font-family: monospace;
            font-size: 13px;
        }}
        footer {{
            text-align: center;
            font-size: 12px;
            color: var(--text-secondary);
            margin-top: 30px;
            padding-top: 15px;
            border-top: 1px solid var(--border-color);
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div class="brand">
                <h1>🛡️ FirmSight Security Audit</h1>
                <p>Automated IoT Firmware Emulation & Dynamic Analysis Sandbox</p>
            </div>
            <div class="risk-banner {risk_badge_class}">
                {risk_grade}
            </div>
        </header>

        <div class="grid-stats">
            <div class="card">
                <h4>Firmware Target</h4>
                <div class="value" style="font-size: 18px; word-break: break-all;">{target_name}</div>
                <div class="subtext">Arch: {architecture}</div>
            </div>
            <div class="card">
                <h4>Emulation Status</h4>
                <div class="value" style="color: var(--accent-green);">{emulation_verdict}</div>
                <div class="subtext">Completed in {duration}s</div>
            </div>
            <div class="card">
                <h4>Static Secrets</h4>
                <div class="value" style="color: var(--accent-orange);">{len(creds)} Leaked</div>
                <div class="subtext">Credentials & Private Keys</div>
            </div>
            <div class="card">
                <h4>Threat Forensics</h4>
                <div class="value" style="color: var(--accent-red);">{pcap.get('threat_level', 'NORMAL')}</div>
                <div class="subtext">{len(pcap.get('alerts', []))} Active Alerts Flagged</div>
            </div>
        </div>

        <section>
            <h2>🔑 Track 2: Leaked Credentials & Private Keys</h2>
            <p style="color: var(--text-secondary); font-size: 13px; margin-bottom: 10px;">
                Identified hardcoded secrets, cryptographic private keys, and default router credentials embedded inside rootfs binaries.
            </p>
            <table>
                <thead>
                    <tr><th>Severity</th><th>Rule Type</th><th>Snippet</th><th>Offset</th><th>Description</th></tr>
                </thead>
                <tbody>
                    {cred_rows}
                </tbody>
            </table>
        </section>

        <section>
            <h2>⚡ Track 2: Dangerous APIs & Memory Layout Audit</h2>
            <p style="color: var(--text-secondary); font-size: 13px; margin-bottom: 10px;">
                Identified banned C library calls susceptible to buffer overflows (CWE-120) and command injections (CWE-78).
            </p>
            <table>
                <thead>
                    <tr><th>Severity</th><th>Function</th><th>CWE ID</th><th>Type</th><th>Description</th></tr>
                </thead>
                <tbody>
                    {vuln_rows}
                </tbody>
            </table>

            <h3 style="font-size: 15px; margin: 20px 0 10px 0; color: var(--accent-blue);">Memory Segment Permissions (DEP / NX Audit)</h3>
            <table>
                <thead>
                    <tr><th>Address Range</th><th>Memory Size</th><th>Flags</th><th>Security Assessment</th></tr>
                </thead>
                <tbody>
                    {mem_rows}
                </tbody>
            </table>
        </section>

        <section>
            <h2>💥 Track 2: Buffer Overflow Exploit Proof-of-Concept</h2>
            <div class="exploit-box">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
                    <strong>{exploit['vulnerability']}</strong>
                    <span class="badge badge-critical">{exploit['status']}</span>
                </div>
                <p style="color: var(--text-secondary); font-size: 13px;">{exploit['details']}</p>
                <div class="register-grid">
                    <div class="reg-card"><span style="color: var(--accent-red);">PC:</span> {exploit.get('crashed_registers', {}).get('pc', '0x41326141')}</div>
                    <div class="reg-card"><span style="color: var(--accent-blue);">LR:</span> {exploit.get('crashed_registers', {}).get('lr', '0x41326141')}</div>
                    <div class="reg-card"><span style="color: var(--accent-green);">SP:</span> {exploit.get('crashed_registers', {}).get('sp', '0x7efff8c0')}</div>
                    <div class="reg-card"><span style="color: var(--accent-orange);">R0:</span> {exploit.get('crashed_registers', {}).get('r0', '0x00000000')}</div>
                </div>
            </div>
        </section>

        <section>
            <h2>🌐 Track 3: Network Traffic Forensics & C2 Threat Alerts</h2>
            <p style="color: var(--text-secondary); font-size: 13px; margin-bottom: 10px;">
                Deep packet inspection (DPI) of synthetic and mirrored PCAP network frames traversing virtual bridge <code>fs-br0</code>.
            </p>
            <table>
                <thead>
                    <tr><th>Severity</th><th>Threat Name</th><th>Detection Heuristic Details</th></tr>
                </thead>
                <tbody>
                    {net_rows}
                </tbody>
            </table>
        </section>

        <section>
            <h2>🛠️ Actionable Remediation Guidance</h2>
            <ul style="padding-left: 20px; font-size: 14px; color: var(--text-secondary);">
                <li style="margin-bottom: 8px;"><strong style="color: var(--text-primary);">Compile with Stack Protectors:</strong> Recompile all firmware user binaries with <code>-fstack-protector-strong</code> and enable full RELRO.</li>
                <li style="margin-bottom: 8px;"><strong style="color: var(--text-primary);">Enforce Non-Executable Stacks (NX):</strong> Ensure the kernel memory manager enforces DEP so heap and stack segments cannot execute injected shellcode.</li>
                <li style="margin-bottom: 8px;"><strong style="color: var(--text-primary);">Replace Insecure APIs:</strong> Refactor <code>strcpy()</code> to <code>strlcpy()</code>, and eliminate <code>system()</code> calls by switching to parameterized <code>execve()</code>.</li>
                <li style="margin-bottom: 8px;"><strong style="color: var(--text-primary);">Eliminate Hardcoded Secrets:</strong> Remove unencrypted RSA keys and default passwords from the root filesystem prior to flashing.</li>
            </ul>
        </section>

        <footer>
            Generated automatically by <strong>FirmSight v1.0</strong> on {now_str} &bull; Project Lead: Salif &bull; Infotact Solutions
        </footer>
    </div>
</body>
</html>
"""
        out_path.write_text(html_content, encoding="utf-8")
        return out_path
