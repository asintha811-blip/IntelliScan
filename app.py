from __future__ import annotations

import uuid
import datetime as dt
from io import BytesIO
from urllib.parse import urlparse

from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    send_file,
    jsonify,
    flash,
)

from engine.analyzer import run_scan
from reports.exporters import to_pdf_bytes, to_txt, to_csv_bytes

app = Flask(__name__)
app.secret_key = "intelliscan-final-key"

SCANS: dict[str, dict] = {}

DEFAULT_CFG = {
    "max_pages": 8,
    "max_depth": 1,
    "connect_timeout": 15,
    "read_timeout": 20,
    "max_retries": 1,
    "backoff_factor": 0.5,
    "verify_ssl": True,
    "allow_subdomains": False,
    "active_tests_budget": 12,
    "user_agent": "IntelliScan (Educational Security Scanner)",
}


def is_valid_url(url: str) -> bool:
    try:
        parsed = urlparse(url.strip())
        return parsed.scheme in ("http", "https") and bool(parsed.netloc)
    except Exception:
        return False


@app.get("/")
def index():
    recent = list(reversed(list(SCANS.values())[-5:]))
    return render_template("index.html", cfg=DEFAULT_CFG, recent_scans=recent)


@app.post("/scan")
def do_scan():
    target = (request.form.get("target") or "").strip()

    if not is_valid_url(target):
        flash("Please enter a valid URL starting with http:// or https://")
        return redirect(url_for("index"))

    cfg = dict(DEFAULT_CFG)
    for key in list(cfg.keys()):
        value = request.form.get(key)
        if value is None or value == "":
            continue

        try:
            if key in ("max_pages", "max_depth", "max_retries", "active_tests_budget"):
                cfg[key] = int(value)
            elif key in ("connect_timeout", "read_timeout", "backoff_factor"):
                cfg[key] = float(value)
            elif key in ("verify_ssl", "allow_subdomains"):
                cfg[key] = value.lower() == "true"
            else:
                cfg[key] = value
        except ValueError:
            flash(f"Invalid value for {key}. Default value used.")

    scan_id = uuid.uuid4().hex[:12]
    started = dt.datetime.utcnow().isoformat() + "Z"

    try:
        result = run_scan(target, cfg)
        result["summary"]["scan_id"] = scan_id
        result["summary"]["started"] = started
        SCANS[scan_id] = result
        return redirect(url_for("view_scan", scan_id=scan_id))
    except Exception as exc:
        flash(f"Scan failed: {str(exc)}")
        return redirect(url_for("index"))


@app.get("/scan/<scan_id>")
def view_scan(scan_id: str):
    scan = SCANS.get(scan_id)
    if not scan:
        return "Scan not found", 404
    return render_template("scan.html", scan=scan)


@app.get("/download/<scan_id>")
def download(scan_id: str):
    scan = SCANS.get(scan_id)
    if not scan:
        return "Scan not found", 404

    fmt = (request.args.get("fmt") or "pdf").lower()

    if fmt == "txt":
        return send_file(
            BytesIO(to_txt(scan).encode("utf-8")),
            as_attachment=True,
            download_name=f"IntelliScan_Report_{scan_id}.txt",
            mimetype="text/plain",
        )

    if fmt == "csv":
        return send_file(
            BytesIO(to_csv_bytes(scan)),
            as_attachment=True,
            download_name=f"IntelliScan_Report_{scan_id}.csv",
            mimetype="text/csv",
        )

    return send_file(
        BytesIO(to_pdf_bytes(scan)),
        as_attachment=True,
        download_name=f"IntelliScan_Report_{scan_id}.pdf",
        mimetype="application/pdf",
    )


@app.get("/api/scan/<scan_id>")
def api_scan(scan_id: str):
    scan = SCANS.get(scan_id)
    if not scan:
        return jsonify({"error": "not_found"}), 404
    return jsonify(scan)


@app.get("/api/scans")
def list_scans():
    data = [
        {
            "scan_id": s["summary"].get("scan_id"),
            "target": s["summary"].get("target"),
            "started": s["summary"].get("started"),
            "risk_score": s["summary"].get("risk_score"),
            "counts": s["summary"].get("severity_counts", {}),
        }
        for s in SCANS.values()
    ]
    return jsonify({"total": len(data), "scans": data})


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
