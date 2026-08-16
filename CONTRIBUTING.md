# Contributing

Contributions that improve bounded collection, redaction, evidence quality, portability, or false-positive handling are welcome.

1. Open an issue describing the defensive use case without live third-party secrets.
2. Add a failing test first.
3. Implement the smallest change that passes.
4. Run `pytest` and `python -m compileall -q surfaceproof tests`.
5. Update documentation when behavior changes.

Detection fixtures must be synthetic. Construct secret-shaped values from fragments in tests so repository secret scanners do not mistake fixtures for active credentials. Features for login, credential validation, route guessing, exploitation, or state-changing probes are out of scope.
