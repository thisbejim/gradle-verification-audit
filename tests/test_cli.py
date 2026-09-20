import json
from pathlib import Path

from gradle_verification_audit.cli import main

FIXTURES = Path(__file__).parent / "fixtures"


def test_json_output_is_versioned(capsys):
    assert main([str(FIXTURES / "clean.xml"), "--format", "json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["schema_version"] == 1
    assert payload["summary"]["components"] == 1


def test_sarif_output_has_results(capsys):
    assert main([str(FIXTURES / "broken.xml"), "--format", "sarif"]) == 1
    payload = json.loads(capsys.readouterr().out)
    assert payload["version"] == "2.1.0"
    assert payload["runs"][0]["results"]


def test_strict_turns_warning_into_failure(capsys):
    assert main([str(FIXTURES / "broken.xml"), "--strict"]) == 1
    assert "FAIL" in capsys.readouterr().out


def test_help_is_available(capsys):
    try:
        main(["--help"])
    except SystemExit as exc:
        assert exc.code == 0
    assert "offline" in capsys.readouterr().out.lower()
