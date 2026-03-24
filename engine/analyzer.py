from __future__ import annotations

import re
import time
from collections import deque
from dataclasses import dataclass
from typing import Any
from urllib.parse import urljoin, urlparse, parse_qsl, urlencode, urlunparse

import requests
from bs4 import BeautifulSoup


SQL_ERROR_PATTERNS = [
    r"sql syntax",
    r"mysql_fetch",
    r"warning.*mysql",
    r"mysql_num_rows",
    r"mysql_query",
    r"supplied argument is not a valid mysql",
    r"you have an error in your sql syntax",
    r"unclosed quotation mark after the character string",
    r"quoted string not properly terminated",
    r"postgresql.*error",
    r"pg_query",
    r"sqlite.*error",
    r"sqlite_exception",
    r"odbc sql server driver",
    r"microsoft ole db provider for sql server",
    r"sqlstate",
    r"syntax error",
    r"fatal error",
    r"unknown column",
    r"unterminated quoted string",
]

SQL_TEST_PAYLOADS = [
    "'",
    '"',
    "'--",
    '"--',
    "' OR '1'='1",
    '" OR "1"="1',
    "')",
    '")',
]

REFLECTION_MARKER = "__INTELLISCAN_MARKER__"

IMPORTANT_SECURITY_HEADERS = {
    "content-security-policy": {
        "title": "Missing Content-Security-Policy",
        "severity": "High",
        "confidence": "High",
        "recommendation": "Add a restrictive Content-Security-Policy header to reduce script injection risk.",
    },
    "x-frame-options": {
        "title": "Missing X-Frame-Options",
        "severity": "Medium",
        "confidence": "High",
        "recommendation": "Add X-Frame-Options (e.g. DENY or SAMEORIGIN) to reduce clickjacking risk.",
    },
    "x-content-type-options": {
        "title": "Missing X-Content-Type-Options",
        "severity": "Medium",
        "confidence": "High",
        "recommendation": "Add X-Content-Type-Options: nosniff to reduce MIME-sniffing risk.",
    },
    "strict-transport-security": {
        "title": "Missing Strict-Transport-Security",
        "severity": "Medium",
        "confidence": "High",
        "recommendation": "Add Strict-Transport-Security on HTTPS responses.",
    },
    "referrer-policy": {
        "title": "Missing Referrer-Policy",
        "severity": "Low",
        "confidence": "High",
        "recommendation": "Add a Referrer-Policy header such as strict-origin-when-cross-origin.",
    },
}


@dataclass
class PageResult:
    url: str
    status_code: int | None
    response_time_ms: float | None
    content_type: str
    headers: dict[str, str]
    body: str
    links: list[str]
    forms: list[dict[str, Any]]
    error: str | None = None


def safe_get(session: requests.Session, url: str, cfg: dict[str, Any]) -> PageResult:
    start = time.perf_counter()
    try:
        r = session.get(
            url,
            timeout=(cfg["connect_timeout"], cfg["read_timeout"]),
            verify=cfg["verify_ssl"],
            allow_redirects=True,
            headers={"User-Agent": cfg["user_agent"]},
        )
        elapsed = (time.perf_counter() - start) * 1000
        content_type = r.headers.get("Content-Type", "")
        body = r.text[:300000]

        links: list[str] = []
        forms: list[dict[str, Any]] = []

        if "text/html" in content_type.lower():
            soup = BeautifulSoup(body, "html.parser")

            for a in soup.find_all("a", href=True):
                href = a.get("href", "").strip()
                if href:
                    links.append(urljoin(r.url, href))

            for form in soup.find_all("form"):
                action = urljoin(r.url, form.get("action", "") or r.url)
                method = (form.get("method", "get") or "get").lower()
                inputs = []
                for inp in form.find_all(["input", "textarea", "select"]):
                    name = inp.get("name")
                    if not name:
                        continue
                    value = inp.get("value", "")
                    inputs.append(
                        {
                            "name": name,
                            "value": value,
                            "tag": inp.name,
                            "type": inp.get("type", ""),
                        }
                    )
                forms.append({"action": action, "method": method, "inputs": inputs})

        return PageResult(
            url=r.url,
            status_code=r.status_code,
            response_time_ms=round(elapsed, 2),
            content_type=content_type,
            headers={k.lower(): v for k, v in r.headers.items()},
            body=body,
            links=links,
            forms=forms,
            error=None,
        )
    except Exception as exc:
        return PageResult(
            url=url,
            status_code=None,
            response_time_ms=None,
            content_type="",
            headers={},
            body="",
            links=[],
            forms=[],
            error=str(exc),
        )


def same_scope(base_url: str, candidate_url: str, allow_subdomains: bool) -> bool:
    b = urlparse(base_url)
    c = urlparse(candidate_url)

    if c.scheme not in ("http", "https"):
        return False

    if allow_subdomains:
        return c.netloc == b.netloc or c.netloc.endswith("." + b.netloc)
    return c.netloc == b.netloc


def normalize_url(url: str) -> str:
    p = urlparse(url)
    scheme = p.scheme.lower()
    netloc = p.netloc.lower()
    path = p.path.rstrip("/")
    if path == "":
        path = "/"

    return urlunparse((scheme, netloc, path, "", p.query, ""))


def build_url_with_param(url: str, key: str, value: str) -> str:
    p = urlparse(url)
    q = dict(parse_qsl(p.query, keep_blank_values=True))
    q[key] = value
    return urlunparse(p._replace(query=urlencode(q, doseq=True)))


def crawl(session: requests.Session, start_url: str, cfg: dict[str, Any]) -> list[PageResult]:
    queue = deque([(start_url, 0)])
    seen: set[str] = set()
    pages: list[PageResult] = []

    while queue and len(pages) < int(cfg["max_pages"]):
        current_url, depth = queue.popleft()
        current_url = normalize_url(current_url)

        if current_url in seen:
            continue
        seen.add(current_url)

        page = safe_get(session, current_url, cfg)
        pages.append(page)

        if depth >= int(cfg["max_depth"]) or page.error:
            continue

        for link in page.links:
            link = normalize_url(link)
            if link not in seen and same_scope(start_url, link, cfg["allow_subdomains"]):
                queue.append((link, depth + 1))

    return pages


def add_finding(findings: list[dict[str, Any]], finding: dict[str, Any], dedupe_key: tuple[Any, ...]) -> None:
    if not hasattr(add_finding, "_seen"):
        add_finding._seen = set()  # type: ignore[attr-defined]
    if dedupe_key in add_finding._seen:  # type: ignore[attr-defined]
        return
    add_finding._seen.add(dedupe_key)  # type: ignore[attr-defined]
    findings.append(finding)


def count_severities(findings: list[dict[str, Any]]) -> dict[str, int]:
    counts = {"High": 0, "Medium": 0, "Low": 0}
    for f in findings:
        sev = f.get("severity", "Low")
        counts[sev] = counts.get(sev, 0) + 1
    return counts


def calculate_risk_score(counts: dict[str, int]) -> int:
    return counts.get("High", 0) * 5 + counts.get("Medium", 0) * 3 + counts.get("Low", 0)


def domain_summary_findings(pages: list[PageResult]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    header_presence: dict[str, int] = {k: 0 for k in IMPORTANT_SECURITY_HEADERS.keys()}
    page_count = 0

    for page in pages:
        if page.error:
            continue
        page_count += 1
        for header_name in IMPORTANT_SECURITY_HEADERS.keys():
            if header_name in page.headers:
                header_presence[header_name] += 1

    for header_name, meta in IMPORTANT_SECURITY_HEADERS.items():
        if header_name == "strict-transport-security":
            https_pages = [p for p in pages if not p.error and p.url.startswith("https://")]
            if not https_pages:
                continue
            present_on_https = sum(1 for p in https_pages if header_name in p.headers)
            if present_on_https == 0:
                add_finding(
                    findings,
                    {
                        "scope": "domain",
                        "type": meta["title"],
                        "severity": meta["severity"],
                        "confidence": meta["confidence"],
                        "status": "Confirmed",
                        "url": urlparse(https_pages[0].url).scheme + "://" + urlparse(https_pages[0].url).netloc,
                        "parameter": "",
                        "evidence": f"Header '{header_name}' was not observed on any scanned HTTPS page.",
                        "recommendation": meta["recommendation"],
                    },
                    ("domain", header_name),
                )
            continue

        if page_count > 0 and header_presence[header_name] == 0:
            add_finding(
                findings,
                {
                    "scope": "domain",
                    "type": meta["title"],
                    "severity": meta["severity"],
                    "confidence": meta["confidence"],
                    "status": "Confirmed",
                    "url": "",
                    "parameter": "",
                    "evidence": f"Header '{header_name}' was not observed on any scanned page.",
                    "recommendation": meta["recommendation"],
                },
                ("domain", header_name),
            )

    return findings


def page_level_findings(pages: list[PageResult]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []

    for page in pages:
        if page.error:
            add_finding(
                findings,
                {
                    "scope": "page",
                    "type": "Page Fetch Error",
                    "severity": "Low",
                    "confidence": "High",
                    "status": "Confirmed",
                    "url": page.url,
                    "parameter": "",
                    "evidence": page.error,
                    "recommendation": "Verify target availability, connectivity, and SSL settings.",
                },
                ("page-error", page.url),
            )
            continue

        powered = page.headers.get("x-powered-by", "")
        if powered:
            add_finding(
                findings,
                {
                    "scope": "page",
                    "type": "Technology Disclosure via X-Powered-By",
                    "severity": "Low",
                    "confidence": "High",
                    "status": "Confirmed",
                    "url": page.url,
                    "parameter": "",
                    "evidence": f"X-Powered-By header exposed: {powered}",
                    "recommendation": "Remove or suppress technology disclosure headers where possible.",
                },
                ("powered-by", page.url, powered),
            )

        server = page.headers.get("server", "")
        if server and any(token in server.lower() for token in ["apache", "nginx", "iis", "php"]):
            add_finding(
                findings,
                {
                    "scope": "page",
                    "type": "Server Banner Disclosure",
                    "severity": "Low",
                    "confidence": "High",
                    "status": "Confirmed",
                    "url": page.url,
                    "parameter": "",
                    "evidence": f"Server header exposed: {server}",
                    "recommendation": "Minimize server banner information in responses.",
                },
                ("server-banner", page.url, server),
            )

        interesting_inputs = []
        for form in page.forms:
            for inp in form["inputs"]:
                name = inp.get("name", "")
                if any(k in name.lower() for k in ["search", "query", "q", "id", "name", "message", "comment"]):
                    interesting_inputs.append(name)

        if interesting_inputs:
            add_finding(
                findings,
                {
                    "scope": "page",
                    "type": "Interesting User Input Surface Identified",
                    "severity": "Low",
                    "confidence": "Medium",
                    "status": "Observed",
                    "url": page.url,
                    "parameter": ", ".join(sorted(set(interesting_inputs))),
                    "evidence": "Potentially security-relevant input fields were discovered in forms.",
                    "recommendation": "Review validation, sanitization, and output encoding for these inputs.",
                },
                ("input-surface", page.url, tuple(sorted(set(interesting_inputs)))),
            )

    return findings


def response_difference_score(base: PageResult, test: PageResult) -> tuple[int, list[str]]:
    score = 0
    reasons: list[str] = []

    if test.error and not base.error:
        score += 2
        reasons.append("test request caused a connection or fetch error")

    if base.status_code is not None and test.status_code is not None and base.status_code != test.status_code:
        score += 2
        reasons.append(f"status code changed from {base.status_code} to {test.status_code}")

    if base.body and test.body:
        diff_ratio = abs(len(test.body) - len(base.body)) / max(len(base.body), 1)
        if diff_ratio > 0.30:
            score += 1
            reasons.append("response length changed significantly")

    return score, reasons


def active_sqli_tests(session, pages, cfg):
    findings = []
    tested = 0
    budget = int(cfg["active_tests_budget"])

    for page in pages:
        if tested >= budget:
            break
        if page.error:
            continue

        parsed = urlparse(page.url)
        params = dict(parse_qsl(parsed.query, keep_blank_values=True))
        if not params:
            continue

        for param in params:
            if tested >= budget:
                break

            # baseline (original)
            base_resp = safe_get(session, page.url, cfg)
            tested += 1

            # TRUE condition
            true_url = build_url_with_param(page.url, param, "1 OR 1=1")
            true_resp = safe_get(session, true_url, cfg)
            tested += 1

            # FALSE condition
            false_url = build_url_with_param(page.url, param, "1 AND 1=2")
            false_resp = safe_get(session, false_url, cfg)
            tested += 1

            if not (base_resp.body and true_resp.body and false_resp.body):
                continue

            base_len = len(base_resp.body)
            true_len = len(true_resp.body)
            false_len = len(false_resp.body)

            # logic: true response similar to base, false different
            if abs(true_len - base_len) < 100 and abs(false_len - base_len) > 200:
                findings.append({
                    "scope": "page",
                    "type": "SQL Injection",
                    "severity": "High",
                    "confidence": "High",
                    "status": "Confirmed",
                    "url": true_url,
                    "parameter": param,
                    "evidence": "Boolean-based response difference detected (TRUE vs FALSE condition).",
                    "recommendation": "Use parameterized queries and input validation."
                })
                return findings

    return findings


def reflected_context_is_risky(body: str, marker: str) -> bool:
    low = body.lower()
    marker_low = marker.lower()

    risky_patterns = [
        f"<script>{marker_low}</script>",
        f"\"{marker_low}\"",
        f"'{marker_low}'",
        f"value=\"{marker_low}\"",
        f">{marker_low}<",
    ]

    return any(pattern in low for pattern in risky_patterns)


def active_xss_tests(session: requests.Session, pages: list[PageResult], cfg: dict[str, Any]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    budget = int(cfg["active_tests_budget"])
    tested = 0

    for page in pages:
        if tested >= budget:
            break
        if page.error:
            continue

        parsed = urlparse(page.url)
        params = dict(parse_qsl(parsed.query, keep_blank_values=True))
        if not params:
            continue

        for param in params:
            if tested >= budget:
                break

            test_url = build_url_with_param(page.url, param, REFLECTION_MARKER)
            resp = safe_get(session, test_url, cfg)
            tested += 1

            if resp.error or not resp.body:
                continue

            if REFLECTION_MARKER in resp.body:
                risky_context = reflected_context_is_risky(resp.body, REFLECTION_MARKER)

                add_finding(
                    findings,
                    {
                        "scope": "page",
                        "type": "Reflected Input Detected" if not risky_context else "Possible Reflected XSS",
                        "severity": "Low" if not risky_context else "Medium",
                        "confidence": "Low" if not risky_context else "Medium",
                        "status": "Observed" if not risky_context else "Possible",
                        "url": test_url,
                        "parameter": param,
                        "evidence": (
                            "Injected marker was reflected in the response, but exploitability was not confirmed."
                            if not risky_context
                            else "Injected marker was reflected in a potentially risky output context. Manual verification is required."
                        ),
                        "recommendation": "Apply context-aware output encoding, input validation, and manual verification.",
                    },
                    ("xss", page.url, param),
                )

    return findings


def run_scan(target: str, cfg: dict[str, Any]) -> dict[str, Any]:
    if hasattr(add_finding, "_seen"):
        add_finding._seen.clear()  # type: ignore[attr-defined]

    session = requests.Session()
    adapter = requests.adapters.HTTPAdapter(max_retries=cfg["max_retries"])
    session.mount("http://", adapter)
    session.mount("https://", adapter)

    notes = [
        "Use only on authorized targets.",
        "This scanner combines passive checks with limited low-risk active validation.",
        "Possible findings should be manually verified before being treated as confirmed vulnerabilities.",
    ]

    pages = crawl(session, target, cfg)

    findings: list[dict[str, Any]] = []

    if urlparse(target).scheme != "https":
        add_finding(
            findings,
            {
                "scope": "domain",
                "type": "No HTTPS",
                "severity": "Medium",
                "confidence": "High",
                "status": "Confirmed",
                "url": target,
                "parameter": "",
                "evidence": "The target was scanned over HTTP instead of HTTPS.",
                "recommendation": "Use HTTPS to protect traffic confidentiality and integrity.",
            },
            ("domain", "no-https"),
        )

    findings.extend(domain_summary_findings(pages))
    findings.extend(page_level_findings(pages))
    findings.extend(active_sqli_tests(session, pages, cfg))
    findings.extend(active_xss_tests(session, pages, cfg))

    findings.sort(
        key=lambda x: (
            {"High": 0, "Medium": 1, "Low": 2}.get(x.get("severity", "Low"), 3),
            x.get("type", ""),
            x.get("url", ""),
        )
    )

    severity_counts = count_severities(findings)
    risk_score = calculate_risk_score(severity_counts)

    summary = {
        "target": target,
        "pages_scanned": len(pages),
        "total_findings": len(findings),
        "severity_counts": severity_counts,
        "risk_score": risk_score,
        "status": "completed",
    }

    pages_data = [
        {
            "url": p.url,
            "status_code": p.status_code,
            "response_time_ms": p.response_time_ms,
            "content_type": p.content_type,
            "error": p.error,
            "forms_count": len(p.forms),
            "links_count": len(p.links),
        }
        for p in pages
    ]

    return {
        "summary": summary,
        "findings": findings,
        "pages": pages_data,
        "notes": notes,
        "config": cfg,
    }
