# CyberS — CVE Vulnerability Analysis Tool

CyberS is a Python-based tool that fetches CVE data from multiple intelligence sources,
applies AI-powered analysis and remediation recommendations, and delivers structured
reports through a Gradio web interface.

96 tests passing across 6 test modules.

---

## Project Overview

Security teams and researchers often need to quickly assess the real-world severity of a
CVE — beyond the base CVSS score. CyberS addresses this by combining multi-source data
ingestion (NVD, OSV, GitHub Advisory) with Google Gemini AI for contextual analysis, and
threat intelligence signals including PoC availability, CISA KEV membership, and EPSS
exploit probability.

The result is a single-page web UI that takes a CVE ID as input and returns a complete,
exportable vulnerability report in seconds.

---

## Architecture

| Module           | Responsibility |
|------------------|----------------|
| `fetcher.py`     | Retrieves CVE records from NVD API with fallback to OSV.dev and GitHub Advisory Database |
| `analyzer.py`    | Uses Google Gemini 2.5 Flash to extract impact, attack vector, severity, and affected components |
| `recommender.py` | Uses Google Gemini 2.5 Flash to generate patch actions, workarounds, and prioritization guidance |
| `threat.py`      | Detects PoC exploits via GitHub Search, checks CISA Known Exploited Vulnerabilities (KEV), and retrieves EPSS scores from the FIRST API |
| `reporter.py`    | Aggregates module outputs into structured JSON and assembles a Markdown report for export |
| `app.py`         | Gradio web UI — entry point that wires all modules together and manages user interaction |

---

## How to Run

### Prerequisites

- Python 3.10+
- A Google API key with access to the Gemini API (required)
- A GitHub personal access token (optional, increases GitHub Search rate limits)

### Configuration

Add your API keys to `project/key.yaml`:

```yaml
GOOGLE_API_KEY: "your-google-api-key"
GITHUB_TOKEN: "your-github-token"   # optional
```

### Install Dependencies

```bash
pip install -r requirements.txt
```

### Launch

```bash
python project/app.py
```

The Gradio interface will open in your browser automatically.

---

## Usage

1. Enter a CVE ID (e.g., `CVE-2024-12345`) in the input field.
2. Select optional threat intelligence checks:
   - PoC detection via GitHub Search
   - CISA KEV database lookup
   - EPSS exploit probability scoring
3. Click **Analyze**.
4. Review the structured JSON report covering vulnerability summary, impact, affected
   components, and remediation recommendations.
5. Click **Generate Report** to export a formatted Markdown report.

---

## Test Coverage

96 tests across 6 files covering all modules (`test_fetcher`, `test_analyzer`,
`test_recommender`, `test_threat`, `test_reporter`, `test_app`).

```bash
pytest project/tests/
```
