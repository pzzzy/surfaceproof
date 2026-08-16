from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:  # Python 3.9-3.10
    import tomli as tomllib


def test_project_metadata_has_console_entrypoint_and_supported_python() -> None:
    data = tomllib.loads(Path("pyproject.toml").read_text())
    assert data["project"]["scripts"]["surfaceproof"] == "surfaceproof.cli:main"
    assert data["project"]["requires-python"] == ">=3.9"
