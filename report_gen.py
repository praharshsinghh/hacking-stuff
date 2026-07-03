#!/usr/bin/env python3
"""
Purpose:
  Convert recon_auto.py-style output folders into a polished HTML or Markdown report.

Usage examples:
  python3 report_gen.py -i recon_output -o report.html
  python3 report_gen.py -i recon_output -o report.md --format markdown

What it checks:
  - summary.txt ranking and aggregate severity counts
  - per-target report_*.txt files
  - findings grouped by target and severity
  - optional Markdown rendering

Output structure:
  output.html or output.md

Limitations / false-positive-prone checks:
  - Parsing depends on recon_auto.py-style text formatting.
  - If a target report is malformed, it is skipped rather than blocking the whole render.
  - The HTML is intentionally self-contained and uses inline CSS only.

WARNING:
  Only use this on reports from authorized assessments.
"""

import argparse
import os
import re
from collections import Counter
from datetime import datetime
from pathlib import Path

try:
    from jinja2 import Template
    JINJA_OK = True
except ImportError:
    Template = None
    JINJA_OK = False
    print("[!] jinja2 not found, using встроенный string templates")
    print("    pip install jinja2 --break-system-packages\n")


#  helpers

SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]


def parse_summary_text(path):
    data = {"raw": [], "targets": []}
    if not path.exists():
        return data
    current = None
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            data["raw"].append(line.rstrip("\n"))
            stripped = line.strip()
            if not stripped:
                continue
            if stripped.startswith("http"):
                current = {"target": stripped, "counts": Counter(), "findings": []}
                data["targets"].append(current)
                continue
            if current and re.search(r"CRITICAL|HIGH|MEDIUM|LOW|INFO", stripped):
                for sev in SEVERITY_ORDER:
                    m = re.search(rf"{sev}:(\d+)", stripped)
                    if m:
                        current["counts"][sev] = int(m.group(1))
    return data


def parse_report_file(path):
    target = path.parent.name
    findings = []
    with open(path, "r", encoding="utf-8") as f:
        lines = [line.rstrip("\n") for line in f]

    i = 0
    while i < len(lines):
        line = lines[i].strip()
        m = re.match(r"\[\d+\]\s+\[(CRITICAL|HIGH|MEDIUM|LOW|INFO)\]\s+(.*)", line)
        if m:
            severity = m.group(1)
            title = m.group(2).strip()
            detail = ""
            if i + 1 < len(lines):
                detail = lines[i + 1].strip()
            findings.append({"severity": severity, "title": title, "detail": detail})
        i += 1
    return {"target": target, "path": str(path), "findings": findings}


def find_input_root(root):
    root = Path(root)
    if (root / "summary.txt").exists():
        return root
    for child in root.iterdir():
        if child.is_dir() and (child / "summary.txt").exists():
            return child
    return root


def collect_reports(input_root):
    input_root = find_input_root(input_root)
    summary = parse_summary_text(input_root / "summary.txt")
    targets = []
    severity_totals = Counter()
    report_dirs = [p for p in input_root.iterdir() if p.is_dir()]
    for d in report_dirs:
        reports = sorted(d.glob("report_*.txt"))
        if not reports:
            continue
        latest = reports[-1]
        parsed = parse_report_file(latest)
        counts = Counter(f["severity"] for f in parsed["findings"])
        severity_totals.update(counts)
        targets.append(
            {
                "target": parsed["target"],
                "report_path": str(latest),
                "findings": parsed["findings"],
                "counts": counts,
                "total": len(parsed["findings"]),
            }
        )
    severity_weight = {sev: idx for idx, sev in enumerate(SEVERITY_ORDER)}
    targets.sort(
        key=lambda x: (x["total"], sum(severity_weight.get(f["severity"], 0) for f in x["findings"])),
        reverse=True,
    )
    return {
        "input_root": str(input_root),
        "generated_at": datetime.now().isoformat(),
        "targets": targets,
        "severity_totals": severity_totals,
        "summary": summary,
    }


def render_markdown(data):
    lines = []
    lines.append("# Recon Report")
    lines.append("")
    lines.append(f"- Generated: {data['generated_at']}")
    lines.append(f"- Targets: {len(data['targets'])}")
    lines.append("")
    lines.append("## Executive Summary")
    for sev in SEVERITY_ORDER:
        lines.append(f"- {sev}: {data['severity_totals'].get(sev, 0)}")
    lines.append("")
    lines.append("## Findings")
    for item in data["targets"]:
        lines.append(f"### {item['target']}")
        lines.append(f"- Total findings: {item['total']}")
        for sev in SEVERITY_ORDER:
            if item["counts"].get(sev):
                lines.append(f"- {sev}: {item['counts'][sev]}")
        lines.append("")
        for finding in item["findings"]:
            lines.append(f"- **[{finding['severity']}] {finding['title']}**")
            lines.append(f"  - {finding['detail']}")
        lines.append("")
    return "\n".join(lines).strip() + "\n"


def render_html(data):
    template = """
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Recon Report</title>
  <style>
    body { font-family: Arial, sans-serif; margin: 24px; color: #1f2937; background: #f8fafc; }
    h1, h2, h3 { margin-top: 1.2em; }
    .card { background: white; border: 1px solid #e5e7eb; border-radius: 12px; padding: 16px; margin-bottom: 16px; box-shadow: 0 1px 2px rgba(0,0,0,.04); }
    table { width: 100%; border-collapse: collapse; background: white; }
    th, td { padding: 10px; border-bottom: 1px solid #e5e7eb; text-align: left; vertical-align: top; }
    th { cursor: pointer; position: sticky; top: 0; background: #f9fafb; }
    .sev-CRITICAL { color: #b91c1c; font-weight: 700; }
    .sev-HIGH { color: #ea580c; font-weight: 700; }
    .sev-MEDIUM { color: #ca8a04; font-weight: 700; }
    .sev-LOW { color: #2563eb; font-weight: 700; }
    .sev-INFO { color: #64748b; font-weight: 700; }
    details { background: white; border: 1px solid #e5e7eb; border-radius: 10px; padding: 10px 12px; margin-bottom: 12px; }
    summary { cursor: pointer; font-weight: 700; }
    .meta { color: #6b7280; font-size: 0.95em; }
  </style>
</head>
<body>
  <h1>Recon Report</h1>
  <div class="card">
    <div class="meta">Generated {{ generated_at }}</div>
    <div class="meta">Source: {{ input_root }}</div>
  </div>
  <div class="card">
    <h2>Executive Summary</h2>
    <ul>
    {% for sev in severities %}
      <li><span class="sev-{{ sev }}">{{ sev }}</span>: {{ severity_totals.get(sev, 0) }}</li>
    {% endfor %}
    </ul>
  </div>
  <div class="card">
    <h2>Findings Table</h2>
    <table id="findings">
      <thead>
        <tr><th>Target</th><th>Total</th><th>Severity Breakdown</th></tr>
      </thead>
      <tbody>
      {% for item in targets %}
        <tr>
          <td>{{ item.target }}</td>
          <td>{{ item.total }}</td>
          <td>
            {% for sev in severities %}
              {% if item.counts.get(sev) %}<span class="sev-{{ sev }}">{{ sev }}: {{ item.counts.get(sev) }}</span>{% if not loop.last %} {% endif %}{% endif %}
            {% endfor %}
          </td>
        </tr>
      {% endfor %}
      </tbody>
    </table>
  </div>
  <div class="card">
    <h2>Per-Target Details</h2>
    {% for item in targets %}
      <details>
        <summary>{{ item.target }} ({{ item.total }} findings)</summary>
        <div class="meta">Report: {{ item.report_path }}</div>
        <ul>
        {% for finding in item.findings %}
          <li><span class="sev-{{ finding.severity }}">[{{ finding.severity }}]</span> {{ finding.title }} - {{ finding.detail }}</li>
        {% endfor %}
        </ul>
      </details>
    {% endfor %}
  </div>
</body>
    </html>
"""
    if JINJA_OK:
        return Template(template).render(**data, severities=SEVERITY_ORDER)
    summary_bits = "".join(
        f"<li><span class='sev-{sev}'>{sev}</span>: {data['severity_totals'].get(sev, 0)}</li>"
        for sev in SEVERITY_ORDER
    )
    rows = []
    details = []
    for item in data["targets"]:
        sev_bits = " ".join(
            f"<span class='sev-{sev}'>{sev}: {item['counts'].get(sev)}</span>"
            for sev in SEVERITY_ORDER
            if item["counts"].get(sev)
        )
        rows.append(f"<tr><td>{item['target']}</td><td>{item['total']}</td><td>{sev_bits}</td></tr>")
        findings = "".join(
            f"<li><span class='sev-{finding['severity']}'>[{finding['severity']}]</span> {finding['title']} - {finding['detail']}</li>"
            for finding in item["findings"]
        )
        details.append(
            f"<details><summary>{item['target']} ({item['total']} findings)</summary>"
            f"<div class='meta'>Report: {item['report_path']}</div><ul>{findings}</ul></details>"
        )
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Recon Report</title>
  <style>
    body {{ font-family: Arial, sans-serif; margin: 24px; color: #1f2937; background: #f8fafc; }}
    h1, h2, h3 {{ margin-top: 1.2em; }}
    .card {{ background: white; border: 1px solid #e5e7eb; border-radius: 12px; padding: 16px; margin-bottom: 16px; box-shadow: 0 1px 2px rgba(0,0,0,.04); }}
    table {{ width: 100%; border-collapse: collapse; background: white; }}
    th, td {{ padding: 10px; border-bottom: 1px solid #e5e7eb; text-align: left; vertical-align: top; }}
    th {{ cursor: pointer; position: sticky; top: 0; background: #f9fafb; }}
    .sev-CRITICAL {{ color: #b91c1c; font-weight: 700; }}
    .sev-HIGH {{ color: #ea580c; font-weight: 700; }}
    .sev-MEDIUM {{ color: #ca8a04; font-weight: 700; }}
    .sev-LOW {{ color: #2563eb; font-weight: 700; }}
    .sev-INFO {{ color: #64748b; font-weight: 700; }}
    details {{ background: white; border: 1px solid #e5e7eb; border-radius: 10px; padding: 10px 12px; margin-bottom: 12px; }}
    summary {{ cursor: pointer; font-weight: 700; }}
    .meta {{ color: #6b7280; font-size: 0.95em; }}
  </style>
</head>
<body>
  <h1>Recon Report</h1>
  <div class="card">
    <div class="meta">Generated {data['generated_at']}</div>
    <div class="meta">Source: {data['input_root']}</div>
  </div>
  <div class="card">
    <h2>Executive Summary</h2>
    <ul>{summary_bits}</ul>
  </div>
  <div class="card">
    <h2>Findings Table</h2>
    <table id="findings">
      <thead><tr><th>Target</th><th>Total</th><th>Severity Breakdown</th></tr></thead>
      <tbody>{''.join(rows)}</tbody>
    </table>
  </div>
  <div class="card">
    <h2>Per-Target Details</h2>
    {''.join(details)}
  </div>
</body>
</html>"""


#  checks

def run(input_root, output_path, fmt):
    data = collect_reports(input_root)
    if fmt == "markdown":
        rendered = render_markdown(data)
    else:
        if JINJA_OK:
            rendered = render_html(data)
        else:
            rendered = render_markdown(data)

    out = Path(output_path)
    with open(out, "w", encoding="utf-8") as f:
        f.write(rendered)
    print(f"[*] wrote {out}")


#  main

def main():
    parser = argparse.ArgumentParser(description="generate HTML or markdown from recon output folders")
    parser.add_argument("-i", "--input", required=True, help="recon output folder")
    parser.add_argument("-o", "--output", required=True, help="output file path")
    parser.add_argument("--format", choices=["html", "markdown"], default="html", help="output format")
    args = parser.parse_args()

    if not os.path.exists(args.input):
        print(f"[!] input folder not found: {args.input}")
        raise SystemExit(1)

    run(args.input, args.output, args.format)


if __name__ == "__main__":
    main()
