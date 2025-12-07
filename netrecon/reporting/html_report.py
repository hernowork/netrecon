from __future__ import annotations

from typing import Dict, Iterable, List

from ..models import Finding, ScanResult, Service, Severity, Target


def _severity_order(sev: Severity) -> int:
    order = {
        Severity.CRITICAL: 0,
        Severity.HIGH: 1,
        Severity.MEDIUM: 2,
        Severity.LOW: 3,
        Severity.INFO: 4,
        Severity.UNKNOWN: 5,
    }
    return order.get(sev, 99)


def _count_by_severity(findings: Iterable[Finding]) -> Dict[Severity, int]:
    counts: Dict[Severity, int] = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    return counts


def _count_by_tool(findings: Iterable[Finding]) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for f in findings:
        tool = f.source_tool or "unknown"
        counts[tool] = counts.get(tool, 0) + 1
    return counts


def _group_by_tool(findings: Iterable[Finding]) -> Dict[str, List[Finding]]:
    groups: Dict[str, List[Finding]] = {}
    for f in findings:
        tool = f.source_tool or "unknown"
        groups.setdefault(tool, []).append(f)
    return groups


def generate_html(report: ScanResult) -> str:
    started = report.started_at.strftime("%Y-%m-%d %H:%M:%S")
    finished = (
        report.finished_at.strftime("%Y-%m-%d %H:%M:%S")
        if report.finished_at
        else "N/A"
    )

    sev_counts = _count_by_severity(report.findings)
    tool_counts = _count_by_tool(report.findings)
    groups = _group_by_tool(report.findings)

    html: List[str] = [
        "<!DOCTYPE html>",
        "<html>",
        "<head>",
        "<meta charset='utf-8'>",
        "<title>NetRecon Scan Report</title>",
        "<style>",
        "body { font-family: sans-serif; margin: 2rem; }",
        "h1, h2, h3 { font-family: sans-serif; }",
        "table { border-collapse: collapse; width: 100%; margin-bottom: 1.5rem; }",
        "th, td { border: 1px solid #ccc; padding: 0.5rem; font-size: 0.9rem; }",
        "th { background: #eee; }",
        ".sev-critical { background: #ffcccc; }",
        ".sev-high { background: #ffe0cc; }",
        ".sev-medium { background: #fff0cc; }",
        ".sev-low { background: #f5ffcc; }",
        ".sev-info { background: #e6f2ff; }",
        ".sev-unknown { background: #f0f0f0; }",
        ".small { font-size: 0.8rem; color: #555; }",
        "</style>",
        "</head>",
        "<body>",
        "<h1>NetRecon Scan Report</h1>",
        f"<p><strong>Profile:</strong> {report.profile.name}</p>",
        f"<p><strong>Started:</strong> {started}</p>",
        f"<p><strong>Finished:</strong> {finished}</p>",
    ]

    # ---- Summary -----------------------------------------------------------
    html.extend(
        [
            "<h2>Summary</h2>",
            "<ul>",
            f"<li>Total targets (hosts): {len(report.targets)}</li>",
            f"<li>Total services (ports): {len(report.services)}</li>",
            f"<li>Total findings: {len(report.findings)}</li>",
            f"<li>Critical: {sev_counts.get(Severity.CRITICAL, 0)}</li>",
            f"<li>High: {sev_counts.get(Severity.HIGH, 0)}</li>",
            f"<li>Medium: {sev_counts.get(Severity.MEDIUM, 0)}</li>",
            f"<li>Low: {sev_counts.get(Severity.LOW, 0)}</li>",
            f"<li>Info: {sev_counts.get(Severity.INFO, 0)}</li>",
            "</ul>",
        ]
    )

    if tool_counts:
        html.append("<h3>Findings per tool</h3>")
        html.append("<ul>")
        for tool, count in tool_counts.items():
            html.append(f"<li>{tool}: {count}</li>")
        html.append("</ul>")

    # ---- Hosts (masscan / input) ------------------------------------------
    html.append("<h2>Hosts discovered</h2>")
    if report.targets:
        html.append("<table>")
        html.append("<tr><th>#</th><th>IP</th><th>Hostname</th></tr>")
        for idx, t in enumerate(report.targets, start=1):
            hostname = t.hostname or "-"
            html.append(
                f"<tr><td>{idx}</td><td>{t.ip}</td><td>{hostname}</td></tr>"
            )
        html.append("</table>")
    else:
        html.append("<p class='small'>No hosts recorded.</p>")

    # ---- Services (naabu) --------------------------------------------------
    html.append("<h2>Services discovered (open ports)</h2>")
    if report.services:
        html.append("<table>")
        html.append(
            "<tr>"
            "<th>#</th>"
            "<th>Target IP</th>"
            "<th>Port</th>"
            "<th>Protocol</th>"
            "<th>Service</th>"
            "<th>Product</th>"
            "<th>Version</th>"
            "</tr>"
        )
        for idx, s in enumerate(report.services, start=1):
            html.append(
                "<tr>"
                f"<td>{idx}</td>"
                f"<td>{s.target.ip}</td>"
                f"<td>{s.port}</td>"
                f"<td>{s.protocol}</td>"
                f"<td>{s.service_name or '-'}</td>"
                f"<td>{s.product or '-'}</td>"
                f"<td>{s.version or '-'}</td>"
                "</tr>"
            )
        html.append("</table>")
    else:
        html.append("<p class='small'>No open services recorded.</p>")

    # ---- Findings by tool --------------------------------------------------
    html.append("<h2>Findings by tool</h2>")
    if not report.findings:
        html.append("<p class='small'>No findings recorded.</p>")
    else:
        for tool, tool_findings in groups.items():
            html.append(f"<h3>{tool}</h3>")
            html.append("<table>")
            html.append(
                "<tr>"
                "<th>Severity</th>"
                "<th>Target</th>"
                "<th>Port</th>"
                "<th>Title</th>"
                "<th>Description</th>"
                "</tr>"
            )

            # sort within tool by severity
            for f in sorted(
                tool_findings, key=lambda x: _severity_order(x.severity)
            ):
                cls = f"sev-{f.severity.value}"
                target_ip = f.target.ip
                port = f.service.port if f.service else "-"
                desc = f.description or ""
                if len(desc) > 200:
                    desc = desc[:197] + "..."

                html.extend(
                    [
                        f"<tr class='{cls}'>",
                        f"<td>{f.severity.value.upper()}</td>",
                        f"<td>{target_ip}</td>",
                        f"<td>{port}</td>",
                        f"<td>{f.title}</td>",
                        f"<td>{desc}</td>",
                        "</tr>",
                    ]
                )

            html.append("</table>")

    html.extend(
        [
            "</body>",
            "</html>",
        ]
    )

    return "\n".join(html)
