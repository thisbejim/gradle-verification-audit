from pathlib import Path

from gradle_verification_audit.engine import audit_file
from gradle_verification_audit.model import Severity

FIXTURES = Path(__file__).parent / "fixtures"


def codes(result):
    return {diagnostic.code for diagnostic in result.diagnostics}


def test_clean_metadata_passes():
    result = audit_file(FIXTURES / "clean.xml")
    assert not result.errors
    assert result.components == 1
    assert result.artifacts == 1
    assert result.checksums == 1


def test_sha512_is_accepted(tmp_path):
    metadata = tmp_path / "verification-metadata.xml"
    metadata.write_text(
        '<verification-metadata xmlns="https://schema.gradle.org/dependency-verification">'
        '<components><component group="g" name="n" version="1">'
        '<artifact name="n-1.jar"><sha512 value="' + "b" * 128 + '" /></artifact>'
        "</component></components></verification-metadata>",
        encoding="utf-8",
    )
    result = audit_file(metadata)
    assert not result.errors
    assert result.checksums == 1


def test_broken_metadata_reports_actionable_rules():
    result = audit_file(FIXTURES / "broken.xml")
    assert result.errors
    assert {"GVA301", "GVA304", "GVA307", "GVA102", "GVA106", "GVA201", "GVA105"} <= codes(result)
    assert all(d.path.endswith("broken.xml") for d in result.diagnostics)
    assert any(d.line for d in result.diagnostics)


def test_secure_policy_upgrades_weak_hash_and_missing_verifier():
    result = audit_file(FIXTURES / "broken.xml", secure=True)
    assert any(d.code == "GVA202" and d.severity == Severity.ERROR for d in result.diagnostics)
    assert any(d.code == "GVA206" and d.severity == Severity.ERROR for d in result.diagnostics)


def test_directory_resolves_default_gradle_path(tmp_path):
    project = tmp_path / "project"
    metadata = project / "gradle" / "verification-metadata.xml"
    metadata.parent.mkdir(parents=True)
    metadata.write_text((FIXTURES / "clean.xml").read_text(), encoding="utf-8")
    result = audit_file(project)
    assert not result.errors
    assert result.path == str(metadata)


def test_missing_file_is_an_error(tmp_path):
    result = audit_file(tmp_path / "missing.xml")
    assert result.errors[0].code == "GVA000"


def test_entity_declaration_is_rejected():
    result = audit_file(FIXTURES / "entity.xml")
    assert result.errors[0].code == "GVA000"
    assert "DOCTYPE" in result.errors[0].message
