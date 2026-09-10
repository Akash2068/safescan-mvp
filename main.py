from __future__ import annotations

import hashlib
import json
import mimetypes
import os
import re
import uuid
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse


ROOT = Path(__file__).parent
DATA_DIR = ROOT / "data"
SCANS_FILE = DATA_DIR / "scans.json"
PORT = int(os.environ.get("PORT", "8000"))


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def load_scans() -> list[dict]:
    DATA_DIR.mkdir(exist_ok=True)
    if not SCANS_FILE.exists():
        return []
    try:
        return json.loads(SCANS_FILE.read_text())
    except (json.JSONDecodeError, OSError):
        return []


def save_scans(scans: list[dict]) -> None:
    DATA_DIR.mkdir(exist_ok=True)
    SCANS_FILE.write_text(json.dumps(scans[:50], indent=2))


def verdict_for(score: int) -> str:
    if score > 80:
        return "dangerous"
    if score > 60:
        return "suspicious"
    if score > 30:
        return "caution"
    return "low-risk"


def url_scan(target: str) -> dict:
    normalized = target.strip()
    if not re.match(r"^https?://", normalized, re.I):
        normalized = "https://" + normalized
    parsed = urlparse(normalized)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("INVALID_URL")

    host = parsed.hostname.lower().rstrip(".")
    findings: list[dict] = []
    score = 0

    def finding(severity: str, points: int, title: str, description: str, category: str) -> None:
        nonlocal score
        score += points
        findings.append(
            {
                "severity": severity,
                "points": points,
                "title": title,
                "description": description,
                "category": category,
            }
        )

    if parsed.scheme == "http":
        finding("medium", 22, "Connection is not encrypted", "The link uses HTTP, so data can be read or changed in transit.", "transport")
    if "@" in parsed.netloc:
        finding("high", 28, "Obfuscated destination", "The URL contains an @ symbol, which can hide the real destination from a quick glance.", "url")
    if "xn--" in host:
        finding("high", 34, "Punycode domain", "This domain uses internationalized characters that can resemble another brand.", "domain")
    if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", host):
        finding("high", 30, "Direct IP address", "The link points directly to an IP address instead of a recognizable domain.", "domain")
    if parsed.port and parsed.port not in {80, 443}:
        finding("medium", 18, "Unusual port", f"The destination uses port {parsed.port}, which is uncommon for public websites.", "network")
    if len(host) > 38 or host.count(".") > 4:
        finding("medium", 16, "Complex domain structure", "The domain has an unusually long or deeply nested hostname.", "domain")
    if len(parsed.query) > 160:
        finding("low", 8, "Large tracking payload", "The link carries a large query string. This is not malicious by itself.", "url")
    if any(token in host for token in ("login", "verify", "secure", "account", "wallet", "claim")) and host not in {
        "login.microsoftonline.com",
        "accounts.google.com",
        "secure.bankofamerica.com",
    }:
        finding("medium", 20, "Credential-themed domain", "The hostname uses language commonly seen in credential phishing links.", "phishing")

    if not findings:
        findings.append(
            {
                "severity": "low",
                "points": 0,
                "title": "No obvious threats detected",
                "description": "This quick scan did not find a strong signal of abuse. It is not a guarantee of safety.",
                "category": "reputation",
            }
        )

    score = min(100, score)
    verdict = verdict_for(score)
    scan_id = str(uuid.uuid4())
    created = now_iso()
    return {
        "id": scan_id,
        "type": "url",
        "target": normalized,
        "normalizedUrl": normalized,
        "status": "complete",
        "riskScore": score,
        "verdict": verdict,
        "reputation": "No known threats found" if score < 31 else "Signals need a closer look",
        "redirects": 0,
        "findings": findings,
        "createdAt": created,
        "completedAt": created,
        "disclaimer": "SafeScan uses multiple signals, not a guarantee of safety.",
    }


def file_scan(payload: dict) -> dict:
    file_name = str(payload.get("fileName", "untitled"))
    file_size = int(payload.get("fileSize", 0))
    sha256 = str(payload.get("sha256", "")).lower()
    mime_type = payload.get("mimeType") or mimetypes.guess_type(file_name)[0] or "application/octet-stream"
    extension = Path(file_name).suffix.lower()
    client_signals = payload.get("signals") if isinstance(payload.get("signals"), list) else []
    findings: list[dict] = []
    score = 4

    if extension in {".apk", ".exe", ".msi", ".bat", ".cmd", ".scr"}:
        findings.append(
            {
                "severity": "medium",
                "points": 24,
                "title": "Executable file",
                "description": "This file can run code on a device. Review its source and permissions before opening.",
                "category": "file-type",
            }
        )
        score += 24
    elif extension == ".pdf":
        findings.append(
            {
                "severity": "low",
                "points": 0,
                "title": "PDF ready for basic analysis",
                "description": "SafeScan can check metadata, links, JavaScript, embedded files, and QR codes in the next scan pass.",
                "category": "document",
            }
        )
    else:
        findings.append(
            {
                "severity": "low",
                "points": 0,
                "title": "File fingerprint created",
                "description": "No reputation match was found in this local MVP scan.",
                "category": "reputation",
            }
        )

    signal_rules = {
        "javascript": (
            "high",
            30,
            "JavaScript found in document",
            "This document contains JavaScript. It can be legitimate, but it deserves review before opening.",
            "document",
        ),
        "embedded-file": (
            "high",
            24,
            "Embedded file found",
            "The document contains another embedded file. Only extract it if you trust the source.",
            "document",
        ),
        "embedded-url": (
            "medium",
            12,
            "Embedded links found",
            "This document contains links that should be checked before following them.",
            "document",
        ),
    }
    for signal in client_signals:
        rule = signal_rules.get(str(signal))
        if rule:
            severity, points, title, description, category = rule
            findings.append(
                {
                    "severity": severity,
                    "points": points,
                    "title": title,
                    "description": description,
                    "category": category,
                }
            )
            score += points

    if file_size > 50 * 1024 * 1024:
        findings.append(
            {
                "severity": "medium",
                "points": 10,
                "title": "Large file",
                "description": "Large uploads deserve extra care and are limited in the MVP.",
                "category": "file-size",
            }
        )
        score += 10

    scan_id = str(uuid.uuid4())
    created = now_iso()
    return {
        "id": scan_id,
        "type": "apk" if extension == ".apk" else ("pdf" if extension == ".pdf" else "file"),
        "target": file_name,
        "fileName": file_name,
        "fileSize": file_size,
        "mimeType": mime_type,
        "sha256": sha256,
        "status": "complete",
        "riskScore": min(100, score),
        "verdict": verdict_for(score),
        "reputation": "No known hash match" if score < 31 else "Manual review recommended",
        "findings": findings,
        "createdAt": created,
        "completedAt": created,
        "disclaimer": "SafeScan uses multiple signals, not a guarantee of safety.",
    }


class SafeScanHandler(BaseHTTPRequestHandler):
    def log_message(self, format: str, *args) -> None:
        return

    def send_json(self, status: int, payload: dict | list) -> None:
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def read_json(self) -> dict:
        length = int(self.headers.get("Content-Length", 0))
        return json.loads(self.rfile.read(length) or b"{}")

    def do_OPTIONS(self) -> None:
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.end_headers()

    def do_GET(self) -> None:
        if self.path == "/health":
            self.send_json(200, {"status": "ok", "service": "safescan-mvp"})
            return
        if self.path.startswith("/v1/scans/") and self.path.count("/") == 3:
            scan_id = self.path.rsplit("/", 1)[-1]
            scan = next((item for item in load_scans() if item["id"] == scan_id), None)
            self.send_json(200 if scan else 404, scan or {"error": "SCAN_NOT_FOUND"})
            return
        if self.path.startswith("/v1/scans"):
            self.send_json(200, {"scans": load_scans()[:20]})
            return
        file_path = ROOT / ("index.html" if self.path in {"/", ""} else self.path.lstrip("/"))
        if file_path.is_file() and ROOT in file_path.parents:
            content_type = mimetypes.guess_type(file_path.name)[0] or "application/octet-stream"
            body = file_path.read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        self.send_json(404, {"error": "NOT_FOUND"})

    def do_POST(self) -> None:
        try:
            payload = self.read_json()
            if self.path == "/v1/scans/url":
                scan = url_scan(str(payload.get("url", "")))
            elif self.path == "/v1/scans/file":
                scan = file_scan(payload)
            elif self.path == "/v1/reports":
                self.send_json(201, {"status": "received"})
                return
            else:
                self.send_json(404, {"error": "NOT_FOUND"})
                return
            scans = load_scans()
            scans.insert(0, scan)
            save_scans(scans)
            self.send_json(201, scan)
        except ValueError as exc:
            self.send_json(400, {"error": str(exc)})
        except (json.JSONDecodeError, TypeError):
            self.send_json(400, {"error": "INVALID_JSON"})
        except Exception:
            self.send_json(500, {"error": "SCAN_FAILED"})


def main() -> None:
    server = ThreadingHTTPServer(("0.0.0.0", PORT), SafeScanHandler)
    print(f"SafeScan MVP running on port {PORT}")
    server.serve_forever()


if __name__ == "__main__":
    main()
