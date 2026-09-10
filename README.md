# SafeScan MVP

SafeScan is a responsive, Android-first product prototype based on the attached
technical blueprint: **scan before you trust**.

## Included in this MVP

- URL scanning with normalization and heuristic risk scoring
- QR flow that accepts a decoded URL, then runs it through the URL scanner
- Camera QR scanning through the browser Barcode Detector API when supported
- File/APK/PDF fingerprinting with browser-side SHA-256 calculation
- Basic client-side PDF signal detection for JavaScript, embedded files, and links
- Risk verdicts: low-risk, caution, suspicious, dangerous
- Findings, reputation summary, scan history, and local history deletion
- Server-backed history plus an installable PWA shell
- Responsive mobile layout for the planned Android client experience
- JSON API seams:
  - `POST /v1/scans/url`
  - `POST /v1/scans/file`
  - `GET /v1/scans`
  - `GET /v1/scans/:scanId`
  - `POST /v1/reports`
  - `GET /health`

The scanner is intentionally positioned as a **pre-trust scanner**, not a
guaranteed antivirus. The reputation-provider and isolated-worker integrations
from the blueprint are the next production step.

## Run

```bash
python main.py
```

Then open the app on the exposed port. The backend is implemented with Python's
standard library so the prototype can run without a database or external API
credentials.