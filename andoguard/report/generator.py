"""Multi-format report generation: Markdown, JSON, and self-contained HTML."""

import html
import json
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from andoguard.api import AndoGuard


def build_report_data(ag: "AndoGuard") -> dict[str, Any]:
    """Collect comprehensive assessment data across all analysis modules."""
    t_info = ag.target_info
    sec_flags = ag.manifest.security_flags()
    perms = ag.manifest.permissions()
    comps = ag.manifest.components()
    exported = ag.manifest.exported_components()
    cert_report = ag.certs()
    vuln_report = ag.vulns()
    secrets_findings = ag.secrets()
    native_libs = ag.native()
    recorded_findings = ag.session_store.get_findings(ag.session_record.session_id)
    trace_events = ag.trace_events()
    installed_hooks = ag.hooks()

    # Consolidate findings
    all_findings: list[dict[str, Any]] = []
    # From static vulns engine
    for vf in vuln_report.findings:
        all_findings.append(
            {
                "id": vf.vuln_id,
                "title": vf.title,
                "severity": vf.severity.value,
                "masvs_id": vf.masvs_id,
                "evidence": vf.description,
                "remediation": vf.remediation,
                "location": vf.location,
                "source": "static_vulns",
            }
        )
    # From session store (e.g. autonomous agent findings)
    for rf in recorded_findings:
        all_findings.append(
            {
                "id": rf.id,
                "title": rf.title,
                "severity": rf.severity.value,
                "masvs_id": rf.masvs_id or "N/A",
                "evidence": rf.evidence,
                "remediation": rf.remediation,
                "location": rf.provenance,
                "source": "autonomous_or_manual",
            }
        )

    # Calculate severity summary
    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for finding_item in all_findings:
        sev = finding_item["severity"].upper()
        if sev in severity_counts:
            severity_counts[sev] += 1
        else:
            severity_counts[sev] = 1

    return {
        "metadata": {
            "session_id": ag.session_record.session_id,
            "session_name": ag.session_record.name,
            "generated_at": datetime.now(UTC).isoformat(),
            "target_path": t_info.target_path,
            "target_type": t_info.target_type.value,
            "file_size": t_info.file_size,
            "md5": t_info.md5,
            "sha1": t_info.sha1,
            "sha256": t_info.sha256,
            "package_name": t_info.package_name,
            "version_name": t_info.version_name,
            "version_code": t_info.version_code,
            "min_sdk": t_info.min_sdk_version,
            "target_sdk": t_info.target_sdk_version,
            "architect": "DarkPulseX (Muhammad Haris)",
        },
        "security_flags": {
            "debuggable": sec_flags.debuggable,
            "allow_backup": sec_flags.allow_backup,
            "uses_cleartext_traffic": sec_flags.uses_cleartext_traffic,
            "network_security_config": sec_flags.network_security_config,
        },
        "certificates": {
            "v1_signature": cert_report.v1_signature,
            "v2_signature": cert_report.v2_signature,
            "v3_signature": cert_report.v3_signature,
            "certificates_count": len(cert_report.certificates),
            "certificates": [
                {
                    "subject": c.subject,
                    "issuer": c.issuer,
                    "sha256": getattr(c, "sha256_fingerprint", getattr(c, "sha256", "")),
                    "serial_number": c.serial_number,
                }
                for c in cert_report.certificates
            ],
        },
        "components": {
            "total": len(comps),
            "exported_count": len(exported),
            "exported": [
                {
                    "type": str(getattr(c.component_type, "value", c.component_type)),
                    "name": c.name,
                    "permission": c.permission,
                }
                for c in exported
            ],
        },
        "permissions": perms,
        "severity_summary": severity_counts,
        "findings": all_findings,
        "secrets": [
            {
                "type": s.secret_type,
                "value": s.value,
                "entropy": s.entropy,
                "source": s.source_file,
            }
            for s in secrets_findings
        ],
        "native_libraries": [
            {
                "path": lib.path,
                "arch": lib.arch,
                "jni_exports": lib.jni_exports,
            }
            for lib in native_libs
        ],
        "dynamic_instrumentation": {
            "trace_events_count": len(trace_events),
            "installed_hooks_count": len(installed_hooks),
        },
    }


def generate_json_report(ag: "AndoGuard") -> str:
    """Generate structured JSON security assessment report."""
    data = build_report_data(ag)
    return json.dumps(data, indent=2)


def generate_markdown_report(ag: "AndoGuard") -> str:
    """Generate professional GitHub-Flavored Markdown assessment report."""
    data = build_report_data(ag)
    meta = data["metadata"]
    flags = data["security_flags"]
    sev = data["severity_summary"]
    certs = data["certificates"]

    lines: list[str] = [
        f"# AndoGuard Security Assessment Report: {meta.get('package_name') or 'Target'}",
        "",
        "> **Notice**: Generated for authorized reverse engineering and penetration testing.",
        "",
        "- **Project Architect**: **DarkPulseX (Muhammad Haris)**",
        f"- **Session ID**: `{meta['session_id']}`",
        f"- **Assessment Date**: `{meta['generated_at'][:19]} UTC`",
        f"- **Target File**: `{meta['target_path']}`",
        f"- **SHA-256**: `{meta['sha256']}`",
        f"- **Package / Version**: `{meta.get('package_name', 'N/A')}` ({meta.get('version_name', 'N/A')})",
        f"- **SDK Range**: Min SDK `{meta.get('min_sdk') or 'N/A'}` -> Target SDK `{meta.get('target_sdk') or 'N/A'}`",
        "",
        "## Executive Vulnerability Summary",
        "",
        "| Severity | Findings Count |",
        "|:---|:---:|",
        f"| **CRITICAL** | `{sev['CRITICAL']}` |",
        f"| **HIGH** | `{sev['HIGH']}` |",
        f"| **MEDIUM** | `{sev['MEDIUM']}` |",
        f"| **LOW** | `{sev['LOW']}` |",
        f"| **INFO** | `{sev['INFO']}` |",
        "",
        "## Security Manifest Flags",
        "",
        f"- **Debuggable**: `{'YES (VULNERABLE)' if flags['debuggable'] else 'NO'}`",
        f"- **Allow Backup**: `{'YES (RISK)' if flags['allow_backup'] else 'NO'}`",
        f"- **Uses Cleartext Traffic**: `{'YES (HTTP ALLOWED)' if flags['uses_cleartext_traffic'] else 'NO'}`",
        f"- **Custom Network Security Config**: `{'Configured' if flags['network_security_config'] else 'None'}`",
        "",
        "## Signature & Certificate Audit",
        "",
        f"- **Signatures Verified**: v1={certs['v1_signature']}, v2={certs['v2_signature']}, v3={certs['v3_signature']}",
        f"- **Certificates**: {certs['certificates_count']} embedded signing certificates.",
        "",
        "## Exported Android Components",
        "",
        f"Found **{data['components']['exported_count']}** exported components accessible to other applications:",
        "",
    ]

    for comp in data["components"]["exported"]:
        perm_str = f" (permission: `{comp['permission']}`)" if comp.get("permission") else " (UNPROTECTED)"
        lines.append(f"- `[{comp['type'].upper()}]` **{comp['name']}**{perm_str}")

    lines.extend([
        "",
        "## Vulnerability Findings & Remediation",
        "",
    ])

    if not data["findings"]:
        lines.append("_No vulnerabilities detected._\n")
    else:
        for idx, f in enumerate(data["findings"], 1):
            lines.extend([
                f"### {idx}. [{f['severity']}] {f['title']}",
                "",
                f"- **MASVS Identifier**: `{f['masvs_id']}`",
                f"- **Location / Source**: `{f.get('location') or 'APK'}`",
                f"- **Evidence**: {f['evidence']}",
                f"- **Remediation**: {f['remediation']}",
                "",
            ])

    # Discovered secrets
    if data["secrets"]:
        lines.extend([
            "## Discovered Secrets & API Keys",
            "",
            "| Secret Type | Discovered Value / Key | Entropy |",
            "|:---|:---|:---:|",
        ])
        for s in data["secrets"]:
            lines.append(f"| **{s['type']}** | `{s['value']}` | `{s['entropy']:.2f}` |")
        lines.append("")

    # Native libraries
    if data["native_libraries"]:
        lines.extend([
            "## Native Libraries & JNI Exports",
            "",
        ])
        for lib in data["native_libraries"]:
            jni_count = len(lib.get("jni_exports", []))
            lines.append(f"- **{lib['path']}** ({lib['arch']}) — `{jni_count}` JNI functions exported.")
        lines.append("")

    return "\n".join(lines)


def generate_html_report(ag: "AndoGuard") -> str:
    """Generate self-contained, offline-first modern dark-mode HTML assessment report."""
    data = build_report_data(ag)
    meta = data["metadata"]
    flags = data["security_flags"]
    sev = data["severity_summary"]
    certs = data["certificates"]

    findings_html: list[str] = []
    for f in data["findings"]:
        sev_color = {
            "CRITICAL": "#ef4444",
            "HIGH": "#f97316",
            "MEDIUM": "#eab308",
            "LOW": "#3b82f6",
            "INFO": "#6b7280",
        }.get(f["severity"], "#9ca3af")

        findings_html.append(
            f"""
            <div class="card finding-card" style="border-left: 4px solid {sev_color};">
                <div class="finding-header">
                    <span class="badge" style="background-color: {sev_color};">{html.escape(f['severity'])}</span>
                    <h3 class="finding-title">{html.escape(f['title'])}</h3>
                    <span class="masvs-tag">{html.escape(f['masvs_id'])}</span>
                </div>
                <div class="finding-body">
                    <p><strong>Evidence:</strong> <code>{html.escape(f['evidence'])}</code></p>
                    <p><strong>Remediation:</strong> {html.escape(f['remediation'])}</p>
                </div>
            </div>
            """
        )

    secrets_rows: list[str] = []
    for s in data["secrets"]:
        secrets_rows.append(
            f"<tr><td>{html.escape(s['type'])}</td><td><code>{html.escape(s['value'])}</code></td><td>{s['entropy']:.2f}</td></tr>"
        )

    exported_comps: list[str] = []
    for c in data["components"]["exported"]:
        perm_desc = f'<span class="badge badge-warning">Required: {html.escape(c["permission"])}</span>' if c.get("permission") else '<span class="badge badge-danger">UNPROTECTED</span>'
        exported_comps.append(
            f"<li><strong>[{html.escape(c['type'].upper())}]</strong> <code>{html.escape(c['name'])}</code> {perm_desc}</li>"
        )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AndoGuard Security Assessment: {html.escape(meta.get('package_name') or 'Target')}</title>
    <style>
        :root {{
            --bg-primary: #0f172a;
            --bg-secondary: #1e293b;
            --bg-card: #1e293b;
            --text-primary: #f8fafc;
            --text-secondary: #94a3b8;
            --accent-cyan: #06b6d4;
            --accent-blue: #3b82f6;
            --border-color: #334155;
            --font-stack: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
        }}
        body {{
            font-family: var(--font-stack);
            background-color: var(--bg-primary);
            color: var(--text-primary);
            line-height: 1.6;
            margin: 0;
            padding: 24px;
        }}
        .container {{
            max-width: 1100px;
            margin: 0 auto;
        }}
        .header {{
            background: linear-gradient(135deg, #1e293b, #0f172a);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            padding: 32px;
            margin-bottom: 24px;
            box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.5);
        }}
        .header h1 {{
            margin: 0 0 8px 0;
            color: var(--accent-cyan);
            font-size: 2rem;
        }}
        .card {{
            background-color: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 20px;
        }}
        .grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 16px;
            margin-bottom: 24px;
        }}
        .metric-card {{
            text-align: center;
            padding: 16px;
        }}
        .metric-value {{
            font-size: 2.2rem;
            font-weight: 700;
            margin: 4px 0;
        }}
        .badge {{
            display: inline-block;
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 0.75rem;
            font-weight: 600;
            color: #fff;
        }}
        .badge-danger {{ background-color: #ef4444; }}
        .badge-warning {{ background-color: #f59e0b; }}
        .badge-success {{ background-color: #10b981; }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 12px;
        }}
        th, td {{
            padding: 10px 14px;
            text-align: left;
            border-bottom: 1px solid var(--border-color);
        }}
        th {{
            color: var(--accent-cyan);
            font-weight: 600;
        }}
        code {{
            background-color: #090d16;
            padding: 2px 6px;
            border-radius: 4px;
            color: #38bdf8;
            font-family: Consolas, monospace;
            font-size: 0.9em;
        }}
        .finding-card {{
            margin-bottom: 16px;
        }}
        .finding-header {{
            display: flex;
            align-items: center;
            gap: 12px;
            margin-bottom: 8px;
        }}
        .finding-title {{
            margin: 0;
            font-size: 1.1rem;
            flex-grow: 1;
        }}
        .masvs-tag {{
            font-size: 0.8rem;
            color: var(--text-secondary);
        }}
        .footer {{
            text-align: center;
            margin-top: 40px;
            color: var(--text-secondary);
            font-size: 0.85rem;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>AndoGuard Security Assessment Report</h1>
            <p style="color: var(--text-secondary); margin: 0;">
                Target: <strong>{html.escape(meta.get('package_name') or meta['target_path'])}</strong> &bull; Generated {meta['generated_at'][:19]} UTC
            </p>
        </div>

        <div class="grid">
            <div class="card metric-card">
                <span class="badge badge-danger">CRITICAL</span>
                <div class="metric-value" style="color: #ef4444;">{sev['CRITICAL']}</div>
                <div style="color: var(--text-secondary);">Critical Findings</div>
            </div>
            <div class="card metric-card">
                <span class="badge" style="background-color: #f97316;">HIGH</span>
                <div class="metric-value" style="color: #f97316;">{sev['HIGH']}</div>
                <div style="color: var(--text-secondary);">High Findings</div>
            </div>
            <div class="card metric-card">
                <span class="badge badge-warning">MEDIUM</span>
                <div class="metric-value" style="color: #eab308;">{sev['MEDIUM']}</div>
                <div style="color: var(--text-secondary);">Medium Findings</div>
            </div>
            <div class="card metric-card">
                <span class="badge" style="background-color: #3b82f6;">LOW</span>
                <div class="metric-value" style="color: #3b82f6;">{sev['LOW']}</div>
                <div style="color: var(--text-secondary);">Low Findings</div>
            </div>
        </div>

        <div class="card">
            <h2>Target Information</h2>
            <table>
                <tr><td><strong>Package Name</strong></td><td><code>{html.escape(meta.get('package_name') or 'N/A')}</code></td></tr>
                <tr><td><strong>Version</strong></td><td>{html.escape(meta.get('version_name') or 'N/A')} ({meta.get('version_code') or 'N/A'})</td></tr>
                <tr><td><strong>SHA-256</strong></td><td><code>{meta['sha256']}</code></td></tr>
                <tr><td><strong>SDK Range</strong></td><td>Min: {meta.get('min_sdk') or 'N/A'} &bull; Target: {meta.get('target_sdk') or 'N/A'}</td></tr>
                <tr><td><strong>Signatures</strong></td><td>v1={certs['v1_signature']}, v2={certs['v2_signature']}, v3={certs['v3_signature']}</td></tr>
                <tr><td><strong>Security Flags</strong></td><td>
                    Debuggable: {'<span class="badge badge-danger">TRUE</span>' if flags['debuggable'] else '<span class="badge badge-success">FALSE</span>'} &bull;
                    AllowBackup: {'<span class="badge badge-warning">TRUE</span>' if flags['allow_backup'] else '<span class="badge badge-success">FALSE</span>'} &bull;
                    Cleartext Traffic: {'<span class="badge badge-danger">ALLOWED</span>' if flags['uses_cleartext_traffic'] else '<span class="badge badge-success">BLOCKED</span>'}
                </td></tr>
            </table>
        </div>

        <div class="card">
            <h2>Exported Components ({data['components']['exported_count']} total)</h2>
            <ul style="padding-left: 20px;">
                {''.join(exported_comps) if exported_comps else '<li>No exported components detected.</li>'}
            </ul>
        </div>

        <div class="card">
            <h2>Vulnerability Findings ({len(data['findings'])})</h2>
            {''.join(findings_html) if findings_html else '<p>No vulnerabilities identified.</p>'}
        </div>

        {'<div class="card"><h2>Discovered Secrets</h2><table><tr><th>Type</th><th>Value</th><th>Entropy</th></tr>' + ''.join(secrets_rows) + '</table></div>' if secrets_rows else ''}

        <div class="footer">
            <p>AndoGuard &bull; Authorized Android Reverse Engineering & Security Testing Toolkit</p>
            <p style="margin-top: 6px; font-size: 0.82rem; color: #94a3b8;">Architected & Developed by <strong style="color: #06b6d4;">DarkPulseX (Muhammad Haris)</strong> &bull; OWASP MASVS Aligned</p>
        </div>
    </div>
</body>
</html>
"""


def generate_report(ag: "AndoGuard", format: str = "markdown") -> str:
    """Generate security report in requested format ('markdown', 'html', or 'json')."""
    fmt = format.lower().strip()
    if fmt in ("json", "js"):
        return generate_json_report(ag)
    elif fmt in ("html", "htm"):
        return generate_html_report(ag)
    return generate_markdown_report(ag)
