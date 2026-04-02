# Security Auditor CLI

Automated web application security reconnaissance and triage tool built with Node.js, Puppeteer, and OpenAI.

This scanner:
- crawls a target URL,
- captures and analyzes HTTP traffic,
- runs passive and active security checks,
- consolidates duplicate findings,
- generates a markdown report and machine-readable JSON findings.

## Features

- Interactive CLI prompt for target URL (or pass URL directly).
- Passive checks:
  - missing security headers
  - cookie hardening issues
  - form risk heuristics (CSRF indicators, sensitive data over GET, password-over-HTTP)
  - transport and script security checks
- Active checks:
  - sensitive path probing
  - robots/security.txt intelligence
  - CORS misconfiguration checks
  - reflected input / XSS candidates
  - SQL error leakage checks
  - open redirect checks
  - risky HTTP methods / TRACE checks
- Finding consolidation:
  - groups repeated findings under one title
  - lists all affected endpoints together
- AI-assisted report generation with `gpt-5.4-mini`.
- Deterministic fallback report if AI analysis fails.

## Requirements

- Node.js 20+ (tested with Node 22)
- npm
- OpenAI API key

## Setup

1. Install dependencies:

```powershell
npm install
```

2. Create/update `.env`:

```env
OPENAI_API_KEY=your_openai_key_here
OPENAI_MODEL=gpt-5.4-mini
```

## Usage

### Interactive mode (recommended)

Run:

```powershell
node index.js
```

You will be prompted:

```text
Enter target URL (include http:// or https://):
```

### Direct mode

Run:

```powershell
node index.js https://example.com
```

or

```powershell
npm run audit -- https://example.com
```

## Output

After a run, the tool writes:

- `report_<hostname>_<timestamp>.md` (human-readable report)
- `findings_<hostname>_<timestamp>.json` (structured findings)

The report contains consolidated findings so repeated issues (for example, missing security headers) are grouped with all affected endpoints.

## Safety and Legal

Use this tool only on systems you own or are explicitly authorized to test.
Unauthorized scanning may violate law, contracts, or policy.

## Notes

- Network and target behavior can change results between runs.
- Some findings are heuristic indicators and may require manual validation.
- AI output quality depends on captured evidence and model behavior.
