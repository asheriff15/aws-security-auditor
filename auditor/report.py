"""Output: colored console summary, JSON, and a self-contained HTML report."""
from __future__ import annotations

import html
import json
import os
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from auditor import __version__
from auditor.models import Finding, Severity

COLORS = {
    Severity.CRITICAL: "\033[1;97;41m", Severity.HIGH: "\033[1;31m", Severity.MEDIUM: "\033[33m",
    Severity.LOW: "\033[36m", Severity.INFO: "\033[37m",
}
RESET = "\033[0m"
HTML_COLORS = {
    Severity.CRITICAL: "#b42318", Severity.HIGH: "#d9480f", Severity.MEDIUM: "#b08800",
    Severity.LOW: "#1c7ed6", Severity.INFO: "#6b7280",
}


def sort_findings(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: (-f.severity, f.service, f.check_id, f.resource))


def counts(findings: list[Finding]) -> dict[str, int]:
    c = Counter(f.severity for f in findings)
    return {s.name: c.get(s, 0) for s in sorted(Severity, reverse=True)}


def print_console(findings, errors, meta, stream=sys.stdout) -> None:
    color = stream.isatty() and not os.environ.get("NO_COLOR")
    paint = (lambda s, sev: f"{COLORS[sev]}{s}{RESET}") if color else (lambda s, sev: s)

    print(f"\nAWS Security Auditor v{__version__}  |  account {meta['account']}  |  regions {', '.join(meta['regions'])}", file=stream)
    print("=" * 96, file=stream)
    for f in sort_findings(findings):
        tag = paint(f"[{f.severity.name:<8}]", f.severity)
        print(f"{tag} {f.check_id:<7} {f.title}", file=stream)
        print(f"           {f.resource}  ({f.region})", file=stream)
        print(f"           {f.detail}", file=stream)
        print(f"           Fix: {f.remediation}\n", file=stream)
    print("-" * 96, file=stream)
    summary = "  ".join(paint(f"{k}: {v}", Severity[k]) for k, v in counts(findings).items())
    print(f"Findings: {len(findings)}   {summary}", file=stream)
    if errors:
        print(f"\n{len(errors)} call(s) were skipped (usually missing permissions):", file=stream)
        for e in errors[:15]:
            print(f"  - {e}", file=stream)
        if len(errors) > 15:
            print(f"  ... and {len(errors) - 15} more (see JSON report)", file=stream)


def write_json(findings, errors, meta, path: Path) -> Path:
    payload = {
        "tool": "aws-security-auditor", "version": __version__, **meta,
        "summary": counts(findings),
        "findings": [f.to_dict() for f in sort_findings(findings)],
        "skipped_calls": errors,
    }
    path.write_text(json.dumps(payload, indent=2))
    return path


def write_html(findings, errors, meta, path: Path) -> Path:
    e = html.escape
    cards = "".join(
        f'<div class="card"><div class="n" style="color:{HTML_COLORS[Severity[k]]}">{v}</div><div class="l">{k.title()}</div></div>'
        for k, v in counts(findings).items()
    )
    rows = "".join(
        f"<tr><td><span class='sev' style='background:{HTML_COLORS[f.severity]}'>{f.severity.name}</span></td>"
        f"<td class='mono'>{e(f.check_id)}</td><td>{e(f.service.upper())}</td>"
        f"<td><b>{e(f.title)}</b><div class='sub'>{e(f.detail)}</div><div class='fix'>Fix: {e(f.remediation)}</div></td>"
        f"<td class='mono'>{e(f.resource)}<div class='sub'>{e(f.region)}</div></td></tr>"
        for f in sort_findings(findings)
    ) or "<tr><td colspan='5'>No findings. Nice.</td></tr>"
    skipped = (
        "<h2>Skipped calls</h2><ul class='mono'>" + "".join(f"<li>{e(x)}</li>" for x in errors) + "</ul>"
        if errors else ""
    )
    doc = f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>AWS Security Audit</title>
<style>
:root{{--bg:#f7f7f5;--fg:#1f2328;--muted:#656d76;--panel:#fff;--line:#e4e4e0}}
@media (prefers-color-scheme:dark){{:root{{--bg:#111315;--fg:#e6e6e3;--muted:#9aa0a6;--panel:#1a1d20;--line:#2c3034}}}}
body{{margin:0;background:var(--bg);color:var(--fg);font:14px/1.5 system-ui,-apple-system,Segoe UI,sans-serif}}
main{{max-width:1100px;margin:0 auto;padding:32px 16px}}
h1{{margin:0 0 4px;font-size:24px}} .meta{{color:var(--muted);margin-bottom:24px}}
.cards{{display:grid;grid-template-columns:repeat(auto-fit,minmax(120px,1fr));gap:12px;margin-bottom:24px}}
.card{{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:14px}}
.n{{font-size:28px;font-weight:700}} .l{{color:var(--muted)}}
.wrap{{overflow-x:auto;background:var(--panel);border:1px solid var(--line);border-radius:10px}}
table{{width:100%;border-collapse:collapse}} th,td{{text-align:left;padding:10px 12px;border-bottom:1px solid var(--line);vertical-align:top}}
th{{color:var(--muted);font-weight:600;font-size:12px;text-transform:uppercase;letter-spacing:.04em}}
.sev{{color:#fff;border-radius:4px;padding:2px 6px;font-size:11px;font-weight:700}}
.mono{{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12px;word-break:break-all}}
.sub{{color:var(--muted);font-size:12px}} .fix{{font-size:12px;margin-top:4px}}
</style></head><body><main>
<h1>AWS Security Audit</h1>
<div class="meta">Account {e(meta['account'])} · Regions {e(', '.join(meta['regions']))} · Services {e(', '.join(meta['services']))} · {e(meta['scanned_at'])}</div>
<div class="cards">{cards}</div>
<div class="wrap"><table><thead><tr><th>Severity</th><th>Check</th><th>Service</th><th>Finding</th><th>Resource</th></tr></thead>
<tbody>{rows}</tbody></table></div>
{skipped}
</main></body></html>"""
    path.write_text(doc)
    return path


def timestamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
