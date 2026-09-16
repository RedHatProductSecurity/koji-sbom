"""Tests for koji_sbom.sbom_io.sbom_document_nvr."""

from __future__ import annotations

import json

from koji_sbom.sbom_io import sbom_document_nvr

_NVR = "postgresql-13.23-5.el9_8"


def test_sbom_document_nvr_spdx_name(tmp_path):
    path = tmp_path / "sbom.json"
    path.write_text(json.dumps({"spdxVersion": "SPDX-2.3", "name": _NVR}), encoding="utf-8")
    assert sbom_document_nvr(path) == _NVR


def test_sbom_document_nvr_cyclonedx(tmp_path):
    path = tmp_path / "bom.json"
    path.write_text(
        json.dumps({"bomFormat": "CycloneDX", "metadata": {"component": {"name": _NVR}}}),
        encoding="utf-8",
    )
    assert sbom_document_nvr(path) == _NVR


def test_sbom_document_nvr_cyclonedx_split_name_version(tmp_path):
    """SBOMer CycloneDX SBOMs store the package name and version separately."""
    path = tmp_path / "bom.json"
    path.write_text(
        json.dumps(
            {
                "bomFormat": "CycloneDX",
                "metadata": {"component": {"name": "postgresql", "version": "13.23-5.el9_8"}},
            }
        ),
        encoding="utf-8",
    )
    assert sbom_document_nvr(path) == "postgresql-13.23-5.el9_8"


def test_sbom_document_nvr_missing_file(tmp_path):
    assert sbom_document_nvr(tmp_path / "missing.json") is None


def test_sbom_document_nvr_invalid_json(tmp_path):
    path = tmp_path / "bad.json"
    path.write_text("not json", encoding="utf-8")
    assert sbom_document_nvr(path) is None
