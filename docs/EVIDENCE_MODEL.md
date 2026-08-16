# Evidence model

Surfaceproof separates observation from inference.

## Resource observation

A resource record states what was requested and returned: URLs, status, content type, bytes, digest, and redirect disposition. It does not claim ownership, vulnerability, confidentiality, or impact.

## Finding observation

A finding records a pattern class, redacted representation, stable fingerprint, source and line. Full values are deliberately absent.

## Classification

- `credential_candidate`: resembles a credential and deserves manual review.
- `likely_fixture`: resembles a credential but appears near example, placeholder, or fixture language.
- `public_identifier`: configuration normally designed to be present in browser code.

These labels are triage aids, not severity ratings.

## Minimum corroboration before disclosure

A responsible analyst should independently establish exact scope, current program status, service binding, why the value is not browser-intended, and minimally sufficient impact using only actions the program permits. If that requires credential use or state change and it is not explicitly authorized, stop and ask for permission.

## Bounded negatives

“No candidates were identified” means only that the selected detectors found no candidates in the resources collected under that run's exact policy and budgets. It never means the application, organization, or host is clean.

## Fingerprints

Surfaceproof uses the first 12 hexadecimal characters of SHA-256 over the transient matched value. This supports run comparison without storing the value. Public reports should still avoid linking a fingerprint to an unresolved, named third party unless disclosure is authorized.
