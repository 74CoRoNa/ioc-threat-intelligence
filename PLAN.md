# CyberIP Analyzer — Implementation Plan

**Project:** Mini SOC Investigation & Threat Intelligence Tool
**Stack:** FastAPI (Python) · SQLite · vanilla HTML/CSS/JS · httpx · dnspython · pytest
**Source of truth for requirements:** `message.txt`

---

## Repository Layout

Frontend and backend live side by side in the same root, as two separate folders.

```
cyberip-analyzer/                 <- repo root
│
├── backend/
│   ├── app/
│   │   ├── main.py               # FastAPI app factory + router mounting
│   │   ├── api/                  # routers (one file per resource)
│   │   │   ├── ip.py
│   │   │   ├── subnet.py
│   │   │   ├── dns.py
│   │   │   ├── domain.py
│   │   │   ├── ioc.py
│   │   │   ├── investigations.py
│   │   │   └── stats.py
│   │   ├── services/             # business logic, one concern per service
│   │   │   ├── ip_service.py
│   │   │   ├── subnet_service.py
│   │   │   ├── dns_service.py
│   │   │   ├── url_service.py
│   │   │   ├── asn_service.py
│   │   │   ├── virustotal_service.py
│   │   │   ├── abuseipdb_service.py
│   │   │   ├── ioc_extractor.py
│   │   │   ├── risk_engine.py
│   │   │   └── report_service.py
│   │   ├── models/               # SQLAlchemy ORM models (DB tables)
│   │   ├── schemas/              # Pydantic request/response models
│   │   ├── core/                 # config, logging, exceptions, http client, db
│   │   └── utils/                # validators, regex patterns, formatters
│   ├── tests/
│   │   ├── unit/
│   │   ├── integration/
│   │   └── fixtures/             # canned API responses for mocking
│   └── requirements.txt
│
├── frontend/
│   ├── index.html                # IP analyzer (home)
│   ├── subnet.html
│   ├── domain.html
│   ├── ioc.html
│   ├── history.html
│   ├── dashboard.html
│   ├── css/
│   │   ├── base.css              # reset, design tokens, typography
│   │   ├── layout.css            # nav, grid, cards
│   │   └── components.css        # tables, badges, forms, risk meter
│   └── js/
│       ├── api.js                # single fetch wrapper for all calls
│       ├── render.js             # shared DOM builders (tables, badges)
│       ├── ip.js
│       ├── subnet.js
│       ├── domain.js
│       ├── ioc.js
│       ├── history.js
│       └── dashboard.js
│
├── .env.example
├── .gitignore
├── README.md
├── PLAN.md
└── docker-compose.yml
```

**Rule:** the backend never contains HTML strings; the frontend never contains business logic. They talk only over the JSON REST API.

---

## Phase Overview

| Phase | Name | Depends on | External APIs |
|---|---|---|---|
| 0 | Project Foundation | — | none |
| 1 | IP Analyzer & Subnet Calculator | 0 | none |
| 2 | DNS & Domain/URL Analyzer | 1 | DNS only |
| 3 | Persistence & Investigation History | 1 | none |
| 4 | Threat Intelligence Integrations | 3 | VT, AbuseIPDB, RDAP |
| 5 | Risk Assessment Engine | 4 | none |
| 6 | IOC Extractor & Bulk Analysis | 5 | reuses 2 + 4 |
| 7 | Investigation Report | 5 | none |
| 8 | Dashboard | 3, 5 | none |
| 9 | Hardening, Docs & Delivery | all | none |

Do not start a phase until the previous one's **Exit Criteria** all pass.

---

## Phase 0 — Project Foundation

**Goal:** an empty-but-running skeleton. `uvicorn` starts, the frontend loads in a browser, `pytest` runs green.

### Tasks
- **P0-T1** Create the folder tree above (empty `__init__.py` in every Python package).
- **P0-T2** Write `backend/requirements.txt`: `fastapi`, `uvicorn[standard]`, `pydantic`, `pydantic-settings`, `httpx`, `dnspython`, `python-dotenv`, `sqlalchemy`, `pytest`, `pytest-asyncio`, `respx` (httpx mocking).
- **P0-T3** Create the venv, install deps, verify imports.
- **P0-T4** `core/config.py` — `Settings` via `pydantic-settings` reading `.env`: `VT_API_KEY`, `ABUSEIPDB_API_KEY`, `DB_PATH`, `HTTP_TIMEOUT`, `CORS_ORIGINS`, `ENV`. All API keys default to `None` — never required.
- **P0-T5** `.env.example` listing every key with **empty** values and comments. Add `.env` to `.gitignore`.
- **P0-T6** `core/logging.py` — structured logger with a filter that redacts anything resembling an API key from log records.
- **P0-T7** `core/exceptions.py` — app exception hierarchy (`ValidationError`, `UpstreamUnavailable`, `NotConfigured`, `NotFound`) plus FastAPI handlers returning one consistent JSON envelope: `{"error": {"code", "message", "details"}}`.
- **P0-T8** `main.py` — app factory, CORS middleware, router registration, `GET /api/health` returning `{status, version, integrations: {virustotal: bool, abuseipdb: bool}}`.
- **P0-T9** Serve the frontend: mount `frontend/` as StaticFiles at `/` in dev so a single `uvicorn` command runs the whole app.
- **P0-T10** `frontend/css/base.css` + `layout.css` — design tokens (colors incl. the risk palette, spacing, radius), shared nav bar, dark SOC-console look, no frameworks.
- **P0-T11** `frontend/index.html` shell with the shared nav (IP · Subnet · Domain · IOC · History · Dashboard) and an empty results area.
- **P0-T12** `frontend/js/api.js` — `apiPost(path, body)` / `apiGet(path)` wrapper with error-envelope handling and a loading-state helper.
- **P0-T13** pytest config (testpaths, asyncio mode) + one smoke test hitting `/api/health` with `TestClient`.

### Exit Criteria
- `uvicorn app.main:app --reload` serves the API **and** the page.
- `/api/health` returns 200 and reports both integrations as `false`.
- `pytest` passes.

---

## Phase 1 — IP Analyzer & Subnet Calculator

**Goal:** the offline core. All network math is correct, tested, and visible in the UI. Zero external calls.

### Tasks
- **P1-T1** `utils/validators.py` — `parse_ip()`, `parse_network()`, input normalization (strip, lowercase, reject empty/oversized input). Raise the app `ValidationError` with a clear message.
- **P1-T2** `services/subnet_service.py`, stdlib `ipaddress` only:
  - `calculate(ip_cidr) -> SubnetResult`: network address, subnet mask, wildcard mask, first/last usable host, broadcast, total addresses, usable hosts, prefix length.
  - Edge cases handled explicitly: `/31` (RFC 3021 point-to-point, 2 addresses, no broadcast), `/32` (single host), IPv6 (no broadcast/wildcard — return `null`, not a fabricated value).
  - Bare IP with no CIDR: assume `/32` (v4) or `/128` (v6) and flag `assumed_prefix: true`.
- **P1-T3** `services/ip_service.py`:
  - `analyze(ip) -> IPAnalysis`: version (4/6), public/private, plus classification flags — loopback, link-local, multicast, reserved, unspecified, CGNAT (100.64.0.0/10), documentation ranges.
  - **Legacy class A/B/C** from the first octet, IPv4 only, returned with an explicit `legacy_only: true` note. **Never used for network math.**
  - Delegate the subnet math to `SubnetService` — no duplicated calculations.
  - `reverse_dns`, `country`, `asn`, `isp` returned as `null` with `enrichment: "pending"` — filled in Phases 2 and 4.
- **P1-T4** `schemas/ip.py`, `schemas/subnet.py` — Pydantic request models (with `Field` constraints and examples) and typed response models. Never return raw dicts.
- **P1-T5** `api/ip.py` — `POST /api/analyze/ip`.
- **P1-T6** `api/subnet.py` — `POST /api/subnet/calculate`.
- **P1-T7** `frontend/js/ip.js` + rendering: three cards — *Address Info*, *Network Info*, *Enrichment (pending)*. Badges for Public/Private and IPv4/IPv6.
- **P1-T8** `frontend/subnet.html` + `js/subnet.js` — form, results table, copy-to-clipboard per value.
- **P1-T9** `frontend/css/components.css` — tables, key/value rows, badges, error banner, spinner.
- **P1-T10** **Tests** (`tests/unit/test_subnet.py`, `test_ip.py`) with hand-verified expected values:
  - `/8 /16 /24 /25 /26 /27 /28 /29 /30 /31 /32` — network ID, broadcast, first/last host, usable count for each.
  - Private vs public: `10.x`, `172.16–31.x`, `192.168.x`, `127.0.0.1`, `169.254.x`, `8.8.8.8`.
  - IPv6: `2001:db8::/32`, `::1`, `fe80::/10`.
  - Legacy class A/B/C detection.
  - Invalid input: `999.1.1.1`, `192.168.1.0/33`, `abc`, empty → validation error.
- **P1-T11** **Tests** (`tests/integration/test_api_phase1.py`) — status codes, response shape, error envelope on bad input.

### Exit Criteria
- Every subnet value cross-checked against a known-good calculator for at least three prefixes.
- `/31` and `/32` behave sensibly; IPv6 produces no nonsense fields.
- Both pages usable end to end in the browser.
- **This is the spec's "Phase 1" — stop here and test manually before continuing.**

---

## Phase 2 — DNS & Domain/URL Analyzer

**Goal:** resolution and safe URL dissection. Still no vendor APIs.

### Tasks
- **P2-T1** `services/dns_service.py` with `dnspython`, async, per-query timeout from config:
  - `resolve(domain)` → A, AAAA, MX (with priority), NS, TXT, CNAME, SOA. Each record type resolved independently so one failure doesn't kill the rest.
  - `reverse(ip)` → PTR.
  - Per-record-type status: `ok` / `no_record` / `timeout` / `error` — never an empty list that silently hides a failure.
- **P2-T2** Wire PTR into `IPService.analyze()` so the Phase 1 `reverse_dns` field now populates.
- **P2-T3** `utils/patterns.py` — compiled regexes for domain, URL, IPv4, IPv6, MD5/SHA1/SHA256, plus defanged forms (`hxxp`, `[.]`, `(.)`) and a `refang()` helper. Shared with Phase 6.
- **P2-T4** `services/url_service.py`:
  - `urlparse` breakdown: scheme, host, port (explicit or default), path, query params (parsed into pairs), fragment, userinfo.
  - Registered-domain / subdomain split, IDN → punycode, host-is-an-IP detection.
  - HTTPS detection and suspicious-pattern flags: IP-as-host, non-standard port, `@` in the authority, excessive subdomain depth, punycode/homograph, risky TLD list, very long URL.
  - Host DNS resolution via `DNSService`.
  - **No HTTP request is made.** No redirect following, no TLS handshake in v1 — `tls` and `redirect_chain` stay `null` with reason `"disabled_in_v1"`.
- **P2-T5** `schemas/dns.py`, `schemas/domain.py`.
- **P2-T6** `api/dns.py` + `api/domain.py` — `POST /api/analyze/domain`, `POST /api/analyze/url`. A shared target-type detector routes bare domain vs full URL vs IP.
- **P2-T7** `frontend/domain.html` + `js/domain.js` — one input box that auto-detects target type; sections for URL breakdown, DNS records, and flags.
- **P2-T8** **Tests** — mocked resolver (no live DNS in tests): record parsing, partial failure (MX times out while A succeeds), NXDOMAIN, PTR present/absent, a 20+ case URL-parsing table (defanged, IDN, explicit port, userinfo, IP host), refang correctness.

### Exit Criteria
- A domain with no MX still returns full A/NS/TXT data plus an explicit `no_record` status.
- No outbound HTTP to the analyzed target — verifiable by grepping for any fetch of user-supplied URLs.

---

## Phase 3 — Persistence & Investigation History

**Goal:** every analysis is recorded and retrievable.

### Tasks
- **P3-T1** `core/database.py` — SQLAlchemy engine/session for SQLite, `get_db` dependency, path from config, foreign-key pragma ON.
- **P3-T2** `models/` — four tables:
  - `investigations`: id, target, target_type, created_at, status, duration_ms, raw_result (JSON)
  - `iocs`: id, investigation_id (FK), ioc_value, ioc_type, first_seen, last_seen
  - `threat_results`: id, investigation_id (FK), source, status (`ok` / `not_configured` / `error`), raw_response (JSON), fetched_at
  - `risk_assessments`: id, investigation_id (FK), score, verdict, evidence (JSON), created_at
  - Indexes on `target`, `created_at`, `verdict`.
- **P3-T3** Schema creation on startup (`create_all`) plus a `scripts/reset_db.py` helper. Note in the README that Alembic is a future improvement.
- **P3-T4** `services/investigation_service.py` — `record()` writes an investigation and its children in one transaction; `list(filters, page)`; `get(id)`; `delete(id)`.
- **P3-T5** Refactor the Phase 1–2 endpoints to persist through `InvestigationService` and return the new `investigation_id`.
- **P3-T6** `api/investigations.py` — `GET /api/investigations` (pagination, filter by type/verdict/date, search by target), `GET /api/investigations/{id}`, `DELETE /api/investigations/{id}`.
- **P3-T7** `frontend/history.html` + `js/history.js` — filterable, paginated table; clicking a row reopens the stored result.
- **P3-T8** **Tests** — temp-file SQLite fixture, write/read round trip, cascade delete, pagination boundaries, filter correctness, JSON column round trip.

### Exit Criteria
- Restarting the server preserves history.
- Every Phase 1–2 analysis appears in `history.html` and reopens with identical data.

---

## Phase 4 — Threat Intelligence Integrations

**Goal:** VirusTotal, AbuseIPDB, and ASN enrichment — all optional, all fail-soft.

### Tasks
- **P4-T1** `core/http_client.py` — one shared `httpx.AsyncClient`: global timeout, connection limits, retry-once on connect errors only (never on 4xx), and a `NotConfigured` short-circuit when a key is missing. Keys travel in headers and are **never logged or echoed in responses**.
- **P4-T2** `services/virustotal_service.py` — `lookup_ip()`, `lookup_domain()`, `lookup_url()` (URL id = base64url of the URL; no submission). Normalize to a common shape: malicious / suspicious / harmless / undetected / total engines, reputation, detection-ratio string, last analysis date.
  - Wording rule enforced in the mapper: emit `"N security engines reported results"` — never `"confirmed clean"`.
- **P4-T3** `services/abuseipdb_service.py` — `check(ip)` → abuse confidence score, total reports, distinct reporters, country, ISP, domain, usage type, last reported date, category names (map numeric category IDs to labels).
- **P4-T4** `services/asn_service.py` — ASN / org / country. Primary source RDAP (no key required); fall back to whatever AbuseIPDB already returned. Cache results.
- **P4-T5** A uniform degradation contract: every TI service returns `{status: "ok" | "not_configured" | "rate_limited" | "timeout" | "error", data, message}`. **A missing key or a dead vendor never raises out of the analyzer** — the rest of the report still renders.
- **P4-T6** TTL cache (in-memory, or a `threat_results` lookup by target + source + age) so repeat lookups don't burn quota. TTL configurable.
- **P4-T7** Run providers concurrently with `asyncio.gather(..., return_exceptions=True)`; keep total analysis under a configured wall-clock budget.
- **P4-T8** Persist every provider call into `threat_results` — including `not_configured`, so reports are honest about what was and wasn't consulted.
- **P4-T9** Frontend: threat-intel cards with a per-source status chip (`OK` / `Not configured` / `Unavailable`), detection ratio, and a link out to the vendor page.
- **P4-T10** **Tests** — `respx`-mocked HTTP for: normal response, 401 bad key, 429 rate limit, 500, timeout, malformed JSON, and missing key. Assert the analyzer still returns 200 with partial data in every case, and that no test touches a real vendor.

### Exit Criteria
- With **no** `.env` keys at all, every analysis still completes and states clearly which sources were unavailable.
- Grepping the logs after a run shows no API key material.

---

## Phase 5 — Risk Assessment Engine

**Goal:** a defensible, explainable 0–100 score built from evidence — never from a single source.

### Tasks
- **P5-T1** `services/risk_engine.py`, evidence-first:
  - An `Evidence` dataclass: `source`, `key` (stable dedup id), `weight`, `description`, `confidence`.
  - Collectors turn each analyzer's output into `Evidence` objects.
  - The scorer sums weights, **deduplicating by `key`**, so the same fact reported by two sources cannot double-count.
  - Score clamped 0–100; verdict bands 0–20 LOW · 21–50 MEDIUM · 51–75 HIGH · 76–100 CRITICAL.
- **P5-T2** The scoring table lives in **one config constant**, not scattered through the code — tunable and easy to explain in the project discussion:
  - VT malicious: 0 → 0 · 1–2 → +15 · 3–5 → +30 · 6+ → +40
  - VT suspicious: small additive bump, capped
  - AbuseIPDB confidence: 0–20 → 0 · 21–50 → +10 · 51–75 → +20 · 76–100 → +30
  - Contextual modifiers: high report volume, recency of last report, missing PTR, suspicious URL flags, abuse-prone hosting hints
  - Neutralizers: a private or reserved IP forces LOW with an explanatory note (internal address, not internet-routable)
- **P5-T3** A **confidence** metric separate from the score: how many sources actually returned data. A score built on one source is reported as low confidence, and the UI says so.
- **P5-T4** Explanation output — an ordered evidence list with each item's point contribution, so `Risk Score: 78/100` always ships with its *why*.
- **P5-T5** Language guard — a test asserting no user-facing string contains definitive phrasing (`"is malicious"`, `"confirmed"`, `"definitely"`). Approved phrasing: `"High risk based on available intelligence."`
- **P5-T6** Persist score, verdict, and evidence into `risk_assessments`; include them in analyze responses.
- **P5-T7** Frontend risk panel: colored score meter, verdict badge, expandable evidence list with point contributions, confidence indicator.
- **P5-T8** **Tests** — a 10+ scenario scoring matrix asserting exact scores and verdicts; a dedup test (same evidence key from two sources counts once); boundary tests at 20/21, 50/51, 75/76; a no-data case → LOW with `confidence: none`; a private-IP case.

### Exit Criteria
- Every score ships with an evidence list that arithmetically sums to it.
- No user-facing string asserts malice as fact.

---

## Phase 6 — IOC Extractor & Bulk Analysis

**Goal:** paste a log, get IOCs, analyze them all.

### Tasks
- **P6-T1** `services/ioc_extractor.py` on the Phase 2 patterns — extract IPv4, IPv6, domains, URLs, MD5, SHA1, SHA256, emails.
  - Refang defanged indicators before matching.
  - Deduplicate, preserve first-seen order, count occurrences.
  - Noise control: private/loopback IPs flagged (not dropped), version-number false positives excluded, common benign domains marked rather than removed.
  - Input size cap and max-IOC cap with a clear "truncated" message.
- **P6-T2** `api/ioc.py` — `POST /api/analyze/log` (raw text → IOC list, no analysis) and `POST /api/analyze/ioc` (analyze one IOC, auto-routed by type).
- **P6-T3** Bulk "Analyze All": a bounded-concurrency runner (semaphore, ~5 at a time) with per-IOC error isolation so one failure never aborts the batch. Returns per-IOC status and score.
- **P6-T4** Hash IOCs: VT file-hash lookup when a key is configured, otherwise a clean "hash recognized, no source configured" result. Hashes get no DNS/network analysis.
- **P6-T5** Group the batch under a single parent investigation so a log analysis is one reviewable unit.
- **P6-T6** `frontend/ioc.html` + `js/ioc.js` — textarea, "Extract", an IOC table with type badges and checkboxes, "Analyze Selected / Analyze All", live progress, sortable by risk score.
- **P6-T7** **Tests** — a realistic multi-line sample log fixture with an exact expected extraction set; defanged input; overlapping matches (decide deliberately whether a URL also emits its bare domain, then test that decision); hash-length discrimination; batch runner with one failing IOC.

### Exit Criteria
- A pasted 50-line log yields a correct, deduplicated IOC list and a complete batch analysis with no unhandled error.

---

## Phase 7 — Investigation Report

**Goal:** one button turns an investigation into a shareable analyst report.

### Tasks
- **P7-T1** `services/report_service.py` — assemble from stored data (never re-query vendors): target, timestamp, target type, IP info, network info, DNS info, threat intel per source with status, IOC info, risk score, verdict, evidence, recommendations, plus an explicit **sources consulted / unavailable** section.
- **P7-T2** Recommendation generator — rules mapping verdict and evidence to **defensive-only** actions: investigate related internal hosts, search firewall logs, pivot in the SIEM, check EDR alerts, consider blocking after validation. No offensive suggestions, ever.
- **P7-T3** `GET /api/investigations/{id}/report?format=json|md|html` — Markdown/HTML rendered server-side from a template.
- **P7-T4** A standard disclaimer block on every report: tool limitations, single-source caveat, "not a SIEM / EDR / IDS / sandbox".
- **P7-T5** Frontend: a "Generate Report" button on every result view → preview page, copy to clipboard, download `.md`, and print-to-PDF CSS (`@media print`).
- **P7-T6** **Tests** — a full investigation produces every required section; missing TI sections degrade gracefully; recommendations match the verdict; the disclaimer is always present.

### Exit Criteria
- A report generated from a stored investigation is complete, honest about gaps, and readable when printed.

---

## Phase 8 — Dashboard

**Goal:** an at-a-glance SOC overview.

### Tasks
- **P8-T1** `api/stats.py` — `GET /api/stats/summary` (totals, counts per verdict, today / 7-day counts), `GET /api/stats/recent`, `GET /api/stats/top-iocs` (most-seen and highest-scoring), `GET /api/stats/distribution` (risk buckets + a time series). All computed with SQL aggregates, not Python loops over whole tables.
- **P8-T2** `frontend/dashboard.html` + `js/dashboard.js` — stat tiles, recent-investigations table, top suspicious IOCs, risk distribution.
- **P8-T3** Charts in **plain CSS/SVG** (no chart library in v1): horizontal bars for the distribution, an inline-SVG sparkline for volume over time, sharing the risk color palette with the Phase 5 risk panel.
- **P8-T4** Empty states for a fresh DB ("No investigations yet — start with an IP analysis").
- **P8-T5** **Tests** — aggregate correctness against a seeded fixture DB; an empty DB returns zeros rather than errors.

### Exit Criteria
- The dashboard is correct against a seeded database and doesn't break when empty.

---

## Phase 9 — Hardening, Documentation & Delivery

**Goal:** ship-ready and defensible in a project discussion.

### Tasks
- **P9-T1** Security pass against the spec's checklist — verify each item and note where it is enforced:
  - Pydantic validation on every endpoint; input length caps
  - Keys only in `.env`; `.env` gitignored; `.env.example` complete
  - A timeout on every outbound request
  - No user input reaching `eval` / `exec` / `subprocess` / `os.system`
  - No SSRF: the server never fetches user-supplied URLs. If fetching is ever added, an allowlist plus private-range blocking is mandatory
  - SQL only through the ORM / parameterized queries
  - No secrets in the database or logs
  - Frontend renders via `textContent` and safe DOM builders — no `innerHTML` with API data (XSS)
- **P9-T2** Simple per-IP rate limiting on the analyze endpoints, plus surfacing vendor rate-limit state to the user.
- **P9-T3** Error-handling review: confirm each of the spec's failure cases produces its specified message (`"API key not configured"`, `"No DNS information available"`, clear validation errors).
- **P9-T4** Code-quality pass: type hints throughout, short docstrings on services and non-obvious functions, dead code removed, no duplicated logic (especially network math), consistent naming. Strip redundant comments — anything that only restates the code, plus leftover commented-out blocks and section banners (see Working Rule 4).
- **P9-T5** Coverage review — every item in the spec's testing section has at least one test; run the whole suite with the network disabled to prove nothing depends on a live API.
- **P9-T6** `README.md` — overview, architecture (with a request-flow diagram), features, installation, environment variables, API-key setup, how to run, how to use, full endpoint reference, **risk-scoring methodology**, security considerations, limitations, future improvements.
- **P9-T7** README section **"CyberOps Concepts Demonstrated"**: IOC, threat intelligence, DNS, IP addressing, CIDR, network analysis, risk assessment, log analysis, API integration — each with a line or two on where it lives in the code.
- **P9-T8** Explicit **Limitations** section: not a SIEM, not an EDR, not an IDS, not a malware sandbox. It is a *Mini SOC Investigation and Threat Intelligence Tool*.
- **P9-T9** `docker-compose.yml` + a backend `Dockerfile` serving the frontend statically; document the non-Docker path as the default.
- **P9-T10** Final manual QA run: walk all six pages with a known-good target list (public IP, private IP, IPv6, domain, URL, pasted log) and record the results.
- **P9-T11** Prepare the discussion defense: be able to explain the risk formula, why CIDR (not legacy class) drives the math, why the tool avoids definitive verdicts, and the SSRF decision.

### Exit Criteria
- Full test suite green with the network disabled.
- Fresh clone → `.env.example` copied with no keys → the app runs and every feature degrades gracefully.
- The README lets someone else run it without asking you a single question.

---

## Working Rules (every phase)

1. **One phase at a time.** Finish, test, and manually verify before moving on.
2. After each phase, produce: what was built · files changed · how to run it · how to test it.
3. No file becomes a dumping ground — if a service passes roughly 300 lines, split it.
4. **Keep comments minimal.** Clear names and small functions carry the meaning; a comment restating what the line already says is noise. Write a comment only where the code cannot explain itself — a non-obvious *why*, an RFC or vendor quirk (`/31` per RFC 3021, a VirusTotal field oddity), or a deliberate trade-off. Short docstrings stay on services and public functions per the spec; banner blocks, section dividers, commented-out code, and line-by-line narration do not.
5. Every external dependency is mockable, and mocked in tests.
6. Commit at the end of each phase with a message naming the phase.
7. Any deviation from `message.txt` gets written into the README's *Design Decisions*.

## Deferred to v2 (explicitly out of scope)

React frontend · PostgreSQL · Redis · Alembic migrations · authentication and multi-user · live TLS certificate inspection · redirect-chain following · Shodan / GreyNoise / OTX integrations · scheduled re-scanning · CSV / STIX export.
