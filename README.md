# Surfaceproof

Evidence-first auditing of explicitly scoped public web artifacts.

Surfaceproof inventories a page and only the assets it directly references, applies exact-host and request/byte budgets, detects selected credential-shaped values and public identifiers, and produces redacted JSON, Markdown, and SARIF evidence. Raw candidate values are used transiently for fingerprinting and are never written to reports.

> Defensive research only. Authorization, scope, and safe harbor remain the operator's responsibility. Surfaceproof does not log in, submit forms, guess routes, enumerate identifiers, validate credentials, or mutate remote systems.

## Why this exists

Public-artifact reviews often fail in two directions: broad scanners overreach, while regex-only tools label every client ID or documentation fixture a secret. Surfaceproof instead emphasizes bounded collection, explicit evidence, contextual classification, false-positive rejection, and honest negative results.

## Safety properties

- exact hostname allowlist; no implicit wildcard expansion
- HTTPS-only unless local HTTP is explicitly enabled
- non-default ports denied unless explicitly listed
- redirect containment before following a redirect
- finite request, per-asset byte, total-byte, and inter-request delay controls
- only seed pages, directly referenced scripts/styles, and directly declared source maps
- no crawling, route guessing, authentication, forms, APIs, credential validation, or mutation
- redacted values plus stable 12-character SHA-256 fingerprints in every output
- output language that treats a clean bounded pass as coverage—not proof a host is globally clean

## Install

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install .
```

Python 3.9+ is supported with no runtime dependencies.

## Quick start

Create a scope file:

```json
{
  "allowed_hosts": ["www.example.com", "static.example.com"],
  "max_requests": 30,
  "max_total_bytes": 8000000,
  "max_asset_bytes": 1500000,
  "delay_seconds": 0.5
}
```

Run a bounded review:

```sh
surfaceproof scan \
  --scope scope.json \
  --json report.json \
  --markdown report.md \
  --sarif report.sarif \
  https://www.example.com/
```

Compare two observations:

```sh
surfaceproof diff old-report.json new-report.json --output diff.json
```

## Detection and classification

The initial release recognizes a deliberately small set of high-signal patterns: AWS access-key IDs, classic GitHub PATs, Stripe live secret/restricted keys, Slack webhooks, private-key headers, browser client IDs, and Sanity project IDs. Findings are classified as:

- `credential_candidate` — secret-shaped material requiring manual review
- `likely_fixture` — secret-shaped material near documentation/example language
- `public_identifier` — configuration that is usually browser-intended and not itself a credential

A candidate is not proof that a credential is active, privileged, in scope, or reportable. Surfaceproof intentionally does not validate it.

## Output model

Each resource records requested/final URL, HTTP status, content type, byte count, SHA-256, and whether a redirect was blocked. Each finding records type, classification, confidence, stable fingerprint, redacted representation, source URL, line, and contextual rationale.

The JSON schema version is `1.0`. SARIF output can be uploaded to compatible analysis systems. Markdown is designed for human triage and private disclosure preparation.

## Architecture

```text
scope.json -> exact policy gate -> bounded HTTP collector
                                   |-> directly linked HTML assets
                                   |-> directly declared source maps
                                   v
                         transient contextual detector
                                   v
                    redacted JSON / Markdown / SARIF
                                   v
                         fingerprint-only run diff
```

See `docs/THREAT_MODEL.md` and `docs/EVIDENCE_MODEL.md`.

## Development and verification

```sh
python -m pip install -e . pytest tomli
pytest
python -m compileall -q surfaceproof tests
```

The integration tests use a local ephemeral HTTP server to verify same-host collection, source-map discovery, out-of-scope redirect blocking, budget enforcement, and absence of raw candidate values in serialized reports.

## Non-goals

Surfaceproof is not a vulnerability scanner, crawler, exploit framework, credential checker, subdomain enumerator, or authorization oracle. It makes no severity decision and submits nothing.

## Responsible use

Use only where you have permission. Read the current program policy before every engagement. If authorization is unclear, stop at ordinary public observation and request an approved private reporting route. Never place unresolved findings, active credentials, customer data, or private report correspondence in a public repository.

## License

MIT. See `LICENSE`.

## Author

Luke Schneider — https://github.com/pzzzy

Security reports about Surfaceproof itself belong in a private GitHub Security Advisory; see `SECURITY.md`.
