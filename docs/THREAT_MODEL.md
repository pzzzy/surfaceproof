# Threat model

## Protected interests

Surfaceproof is designed to protect target systems from accidental overreach, researchers from ambiguous scope expansion, and evidence packets from leaking the material they are intended to document.

## Trust boundaries

1. The operator supplies seed URLs and an explicit exact-host scope file.
2. Remote servers control response bodies, content types, links, redirects, and declared source-map locations.
3. The detector handles response text transiently.
4. Only redacted findings and hashes cross into report files.

## Addressed risks

- Redirect escape: redirects are intercepted and checked against the exact host/port policy before any follow-up.
- Crawl expansion: only directly referenced scripts, styles, and directly declared source maps are queued.
- Resource exhaustion: request, per-asset, and aggregate-byte budgets fail closed.
- Accidental aggressive traffic: a configurable delay is applied between requests.
- Secret persistence: reports retain redacted values and fingerprints, never the full matched value.
- False-positive inflation: fixture language and browser-intended identifiers receive separate classifications.
- Overstated negatives: reports explicitly describe bounded coverage.

## Residual risks

- Response bytes exist transiently in process memory.
- A malicious server can provide misleading content types or huge declared lengths; actual read limits remain authoritative.
- Pattern matching is incomplete and contextual classification is heuristic.
- A public URL can still be legally or contractually out of scope.
- A stable fingerprint can permit correlation if an observer already possesses the exact candidate value.

## Explicitly excluded behavior

No login, cookies, bearer tokens, form submission, route guessing, parameter variation, ID enumeration, API replay, credential validation, write test, exploitation, port scan, DNS enumeration, or browser automation.

## Fail-closed decisions

Invalid scope, unknown scope keys, wildcard hosts, non-approved schemes/ports, over-budget resources, aggregate exhaustion, and seeds outside scope terminate the scan with an error.

## Reporting a vulnerability in Surfaceproof

Use a private GitHub Security Advisory. Do not include live third-party credentials or confidential target evidence; use a synthetic reproducer whenever possible.
