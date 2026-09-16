"""Tests for koji_sbom.buildmeta."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from koji_sbom.buildmeta import (
    DEFAULT_FEDORA_KOJI_WEB,
    KOJI_CMDB_ID,
    koji_build_url,
    write_fedora_rpm_buildmeta,
)


def _build() -> dict[str, Any]:
    return {
        "build_id": 3088712,
        "package_name": "openssl",
        "name": "openssl",
        "version": "4.0.2",
        "release": "1.fc46",
        "nvr": "openssl-4.0.2-1.fc46",
        "epoch": 1,
        "source": "git+https://src.fedoraproject.org/rpms/openssl?#abc123",
    }


def test_koji_build_url() -> None:
    assert koji_build_url(_build()) == f"{DEFAULT_FEDORA_KOJI_WEB}/buildinfo?buildID=3088712"
    assert koji_build_url({}) == ""


def test_write_fedora_rpm_buildmeta(tmp_path: Path) -> None:
    write_fedora_rpm_buildmeta(tmp_path, "openssl", _build())

    meta = json.loads((tmp_path / "openssl-rpm-buildmeta.json").read_text(encoding="utf-8"))
    assert meta["origin"] == "koji"
    assert meta["build_system_cmdb_id"] == KOJI_CMDB_ID
    assert meta["build_url"] == f"{DEFAULT_FEDORA_KOJI_WEB}/buildinfo?buildID=3088712"
    assert meta["nvr"] == "openssl-4.0.2-1.fc46"
