# IOC Threat Intelligence Analyzer

A local multi-source IOC investigation application using exactly:

- VirusTotal for IP, domain, URL, and file-hash reports.
- AbuseIPDB for IPv4 and IPv6 reputation only.
- ThreatFox for malware-associated IOC intelligence.
- URLhaus for malware-distribution hosts, URLs, and payload hashes.

The application accepts IPv4, IPv6, domains, URLs, MD5, SHA-1, and SHA-256 values, detects the type automatically, preserves real provider states, correlates independent findings, calculates an explainable score, stores investigations, and generates reports.

## Run locally

Requires Python 3.10 or newer. Nothing else needs to be installed first.

**Windows** — double-click `run.bat`, or:

```powershell
.\run.ps1
```

**macOS and Linux**:

```bash
./run.sh
```

On first run the launcher finds a Python interpreter, creates `.venv`, installs dependencies, and copies `.env.example` to `.env`. The interface then opens at `http://127.0.0.1:8000`.

A virtual environment records an absolute path to the interpreter that built it, so a `.venv` copied between computers — or left behind by an interpreter that was moved or uninstalled — cannot run. The launcher detects that and rebuilds the environment automatically. Pass `-Recreate` (`--recreate` on macOS and Linux) to force a rebuild.

Options: `-Port 8080`, `-NoBrowser`, `-Reload` on Windows; `--port 8080`, `--no-browser`, `--reload` elsewhere.

## Configuration

Copy `.env.example` to `.env` and configure:

```env
VIRUSTOTAL_API_KEY=
ABUSEIPDB_API_KEY=
THREATFOX_API_KEY=
URLHAUS_API_KEY=
AI_API_KEY=
```

Keys remain server-side. A missing or rejected key produces an explicit provider status; the application never substitutes fabricated intelligence.

## Provider behavior

- AbuseIPDB is queried only for IP addresses. Other IOC types show `Not Applicable`.
- AbuseIPDB (abuseipdb.com) and abuse.ch are unrelated services. One abuse.ch Auth-Key
  serves both ThreatFox and URLhaus; leaving `URLHAUS_API_KEY` blank reuses
  `THREATFOX_API_KEY`. An abuse.ch key placed in `ABUSEIPDB_API_KEY` is reported as a
  configuration mix-up rather than a credential failure.
- ThreatFox files botnet C&C addresses under the `ip:port` IOC type, so an IP is searched
  in a form that matches those records. An `address:port` input is accepted directly.
- URLhaus indexes MD5 and SHA-256 payload hashes; SHA-1 shows `Not Applicable`.
- No user-submitted URL is visited, downloaded, or executed.
- VirusTotal retrieves existing reports; it does not submit files or URLs for scanning.
- ThreatFox no-match results explicitly state that absence is not proof of safety.
- One provider failure does not stop the remaining analysis or report persistence.

## Risk model

The score is evidence-based rather than an average. It considers VirusTotal engine detections, AbuseIPDB confidence/report volume, ThreatFox matches and confidence, URLhaus distribution activity and whether those URLs are still serving, and agreement between independent positive sources. Evidence keys are deduplicated.

Severity bands: Low 0–20, Moderate 21–40, Suspicious 41–60, High 61–80, Critical 81–100.

## Tests

```powershell
.\.venv\Scripts\python.exe -m pytest backend -q
```

On macOS and Linux:

```bash
.venv/bin/python -m pytest backend -q
```

Automated provider tests use labeled transport fixtures and never present fixture data as live intelligence. Real credential checks are separate:

```powershell
Set-Location backend
..\.venv\Scripts\python.exe -m scripts.verify_providers
..\.venv\Scripts\python.exe -m scripts.e2e_live
```

The live scripts print normalized statuses and summary values only; they do not print credentials or raw responses.

## Current configuration limitation

An AbuseIPDB key and an AI-provider key have not been supplied. Those components therefore report `not configured`. No AI narrative is fabricated while the AI provider is unconfigured. VirusTotal, ThreatFox, and URLhaus are configured and answering.
