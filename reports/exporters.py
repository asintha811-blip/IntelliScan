from __future__ import annotations

import csv
from io import BytesIO, StringIO
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import mm
from reportlab.pdfgen import canvas


def to_txt(scan: dict) -> str:
    s = scan["summary"]
    out = []
    out.append("INTELLISCAN REPORT")
    out.append("=" * 80)
    out.append(f"Target: {s.get('target')}")
    out.append(f"Pages Scanned: {s.get('pages_scanned')}")
    out.append(f"Total Findings: {s.get('total_findings')}")
    out.append(f"Risk Score: {s.get('risk_score')}")
    out.append("Severity Counts:")
    for k, v in s.get("severity_counts", {}).items():
        out.append(f"  - {k}: {v}")
    out.append("")
    out.append("Findings")
    out.append("-" * 80)

    for i, f in enumerate(scan.get("findings", []), start=1):
        out.append(f"{i}. {f.get('type')} [{f.get('severity')}]")
        out.append(f"   Status: {f.get('status')}")
        out.append(f"   Confidence: {f.get('confidence')}")
        if f.get("scope"):
            out.append(f"   Scope: {f.get('scope')}")
        if f.get("url"):
            out.append(f"   URL: {f.get('url')}")
        if f.get("parameter"):
            out.append(f"   Parameter: {f.get('parameter')}")
        out.append(f"   Evidence: {f.get('evidence')}")
        out.append(f"   Recommendation: {f.get('recommendation')}")
        out.append("")

    out.append("Notes")
    out.append("-" * 80)
    for note in scan.get("notes", []):
        out.append(f"- {note}")

    return "\n".join(out)


def to_csv_bytes(scan: dict) -> bytes:
    buffer = StringIO()
    writer = csv.writer(buffer)
    writer.writerow(
        ["Type", "Severity", "Status", "Confidence", "Scope", "URL", "Parameter", "Evidence", "Recommendation"]
    )
    for f in scan.get("findings", []):
        writer.writerow(
            [
                f.get("type", ""),
                f.get("severity", ""),
                f.get("status", ""),
                f.get("confidence", ""),
                f.get("scope", ""),
                f.get("url", ""),
                f.get("parameter", ""),
                f.get("evidence", ""),
                f.get("recommendation", ""),
            ]
        )
    return buffer.getvalue().encode("utf-8")


def _pdf_write_wrapped(c: canvas.Canvas, text: str, x: float, y: float, max_width: float, line_height: float = 5 * mm):
    words = text.split()
    line = ""
    for word in words:
        candidate = f"{line} {word}".strip()
        if c.stringWidth(candidate, "Helvetica", 10) <= max_width:
            line = candidate
        else:
            c.drawString(x, y, line)
            y -= line_height
            line = word
    if line:
        c.drawString(x, y, line)
        y -= line_height
    return y


def to_pdf_bytes(scan: dict) -> bytes:
    buffer = BytesIO()
    c = canvas.Canvas(buffer, pagesize=A4)
    width, height = A4

    margin_x = 18 * mm
    y = height - 18 * mm

    s = scan["summary"]

    c.setFont("Helvetica-Bold", 18)
    c.drawString(margin_x, y, "IntelliScan Report")
    y -= 10 * mm

    c.setFont("Helvetica", 10)
    rows = [
        f"Target: {s.get('target')}",
        f"Pages Scanned: {s.get('pages_scanned')}",
        f"Total Findings: {s.get('total_findings')}",
        f"Risk Score: {s.get('risk_score')}",
        f"High: {s.get('severity_counts', {}).get('High', 0)} | Medium: {s.get('severity_counts', {}).get('Medium', 0)} | Low: {s.get('severity_counts', {}).get('Low', 0)}",
    ]
    for row in rows:
        c.drawString(margin_x, y, row)
        y -= 6 * mm

    y -= 2 * mm
    c.setFont("Helvetica-Bold", 12)
    c.drawString(margin_x, y, "Findings")
    y -= 8 * mm

    for idx, f in enumerate(scan.get("findings", []), start=1):
        if y < 40 * mm:
            c.showPage()
            y = height - 18 * mm

        c.setFont("Helvetica-Bold", 10)
        c.drawString(margin_x, y, f"{idx}. {f.get('type')} [{f.get('severity')}]")
        y -= 5 * mm

        c.setFont("Helvetica", 10)
        y = _pdf_write_wrapped(c, f"Status: {f.get('status')} | Confidence: {f.get('confidence')} | Scope: {f.get('scope')}", margin_x, y, width - (2 * margin_x))
        if f.get("url"):
            y = _pdf_write_wrapped(c, f"URL: {f.get('url')}", margin_x, y, width - (2 * margin_x))
        if f.get("parameter"):
            y = _pdf_write_wrapped(c, f"Parameter: {f.get('parameter')}", margin_x, y, width - (2 * margin_x))
        y = _pdf_write_wrapped(c, f"Evidence: {f.get('evidence')}", margin_x, y, width - (2 * margin_x))
        y = _pdf_write_wrapped(c, f"Recommendation: {f.get('recommendation')}", margin_x, y, width - (2 * margin_x))
        y -= 2 * mm

    if y < 35 * mm:
        c.showPage()
        y = height - 18 * mm

    c.setFont("Helvetica-Bold", 12)
    c.drawString(margin_x, y, "Notes")
    y -= 8 * mm
    c.setFont("Helvetica", 10)
    for note in scan.get("notes", []):
        y = _pdf_write_wrapped(c, f"- {note}", margin_x, y, width - (2 * margin_x))

    c.save()
    return buffer.getvalue()