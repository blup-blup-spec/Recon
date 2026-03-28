# utils/reporter.py

import os
from datetime import datetime

RISK_EMOJI = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}


def generate_markdown(scan_results: dict, meta: dict) -> str:
    now      = meta.get("end_time", datetime.now())
    start    = meta.get("start_time", now)
    duration = str(now - start).split(".")[0]

    lines = []
    lines.append(f"# 🔍 Recon Report — {meta.get('target', 'Unknown')}")
    lines.append(f"**Date:** {now.strftime('%Y-%m-%d %H:%M:%S')}  ")
    lines.append(f"**Duration:** {duration}  ")
    total_open = sum(len(d.get("open_ports", [])) for d in scan_results.values())
    lines.append(
        f"**Hosts Scanned:** {meta.get('total_hosts', '?')} | "
        f"**Alive:** {meta.get('alive_hosts', '?')} | "
        f"**Open Ports:** {total_open}"
    )
    lines.append("")
    lines.append("---")
    lines.append("")

    risk_totals = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}

    for ip, data in scan_results.items():
        disc  = data.get("discovery", {})
        ports = data.get("open_ports", [])
        os_g  = data.get("os", "Unknown")

        lines.append(f"## Host: `{ip}`")
        if disc.get("hostname"):
            lines.append(f"**Hostname:** {disc['hostname']}  ")
        lines.append(f"**OS:** {os_g}  ")
        lines.append(f"**Open Ports:** {len(ports)}")
        lines.append("")

        if ports:
            lines.append("| Port | Proto | Service | Version | Risk | Notes |")
            lines.append("|------|-------|---------|---------|------|-------|")
            for p in sorted(ports, key=lambda x: x["port"]):
                risk  = p.get("risk", "LOW")
                emoji = RISK_EMOJI.get(risk, "⚪")
                ver   = p.get("banner", "") or p.get("version", "") or "—"
                note  = p.get("note", "") or "—"
                proto = p.get("proto", "tcp")
                lines.append(
                    f"| {p['port']} | {proto} | {p['service']} | {ver} | {emoji} {risk} | {note} |"
                )
                risk_totals[risk] = risk_totals.get(risk, 0) + 1
            lines.append("")
        else:
            lines.append("_No open ports found._")
            lines.append("")

        whois = disc.get("whois", "")
        if whois and whois not in ("No WHOIS data", ""):
            lines.append("<details>")
            lines.append("<summary>WHOIS</summary>")
            lines.append("")
            lines.append("```")
            lines.append(whois)
            lines.append("```")
            lines.append("</details>")
            lines.append("")

        lines.append("---")
        lines.append("")

    lines.append("## 📊 Summary")
    lines.append("")
    for risk in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        lines.append(f"- {RISK_EMOJI[risk]} **{risk}:** {risk_totals.get(risk, 0)}")
    lines.append("")
    lines.append(f"Tags: #recon #scan #{now.strftime('%Y-%m-%d')}")

    return "\n".join(lines)


def save_report(markdown: str, output_dir: str, target: str) -> str:
    os.makedirs(output_dir, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe = target.replace("/", "_").replace(".", "-")
    path = os.path.join(output_dir, f"recon_{safe}_{ts}.md")
    with open(path, "w") as f:
        f.write(markdown)
    return path
