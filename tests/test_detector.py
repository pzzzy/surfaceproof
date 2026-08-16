from surfaceproof.detector import detect


def test_detect_redacts_and_fingerprints_without_retaining_secret() -> None:
    secret = "AKIA" + "A" * 16
    findings = detect(f'const accessKey = "{secret}";', source_url="https://example.com/app.js")
    assert len(findings) == 1
    finding = findings[0]
    assert finding.kind == "aws_access_key_id"
    assert finding.redacted == "AKIA…AAAA"
    assert len(finding.fingerprint) == 12
    assert secret not in repr(finding)
    assert secret not in finding.to_dict().values()


def test_context_classifier_downranks_documentation_fixture() -> None:
    secret = "ghp_" + "A" * 36
    [finding] = detect(
        f'example placeholder token: "{secret}"',
        source_url="https://example.com/docs.js",
    )
    assert finding.classification == "likely_fixture"
    assert finding.confidence == "low"


def test_public_identifiers_are_classified_not_mislabeled_as_secrets() -> None:
    findings = detect(
        'clientId="abc123ABC_-"; projectId="a1b2c3d4"; dataset="production";',
        source_url="https://example.com/app.js",
    )
    kinds = {f.kind for f in findings}
    assert "public_client_id" in kinds
    assert "sanity_project_id" in kinds
    assert all(f.classification == "public_identifier" for f in findings)


def test_deduplicates_same_value_without_persisting_value() -> None:
    secret = "sk_live_" + "A" * 24
    findings = detect(f'one="{secret}"; two="{secret}"', source_url="https://example.com/a.js")
    assert len(findings) == 1
