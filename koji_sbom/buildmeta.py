"""
Shared RPM build-metadata read/write for SPDX SBOM sidecars.

``{component}-rpm-buildmeta.json`` sits beside ``{component}-rpm-sbom.json`` in
collector trees.  Channel-specific writers (RHEL Brew, Fedora Koji) supply
``origin``, CMDB id, and ``build_url``; ingest reads the file generically.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from koji_sbom.git_source import extract_git_from_brew_build

KOJI_CMDB_ID = "KOJI-001"
"""CMDB ID for community Fedora builds from koji.fedoraproject.org."""

DEFAULT_FEDORA_KOJI_WEB = "https://koji.fedoraproject.org/koji"

__all__ = [
    "DEFAULT_FEDORA_KOJI_WEB",
    "KOJI_CMDB_ID",
    "koji_build_url",
    "load_rpm_buildmeta",
    "normalize_committish_for_build_manifest",
    "write_fedora_rpm_buildmeta",
    "write_rpm_buildmeta",
]


def load_rpm_buildmeta(
    component_dir: Path | None,
    component: str,
) -> dict[str, Any] | None:
    """
    Load ``{component}-rpm-buildmeta.json`` from *component_dir*.

    Returns ``None`` when the file is absent or malformed.
    """
    if component_dir is None:
        return None
    path = component_dir / f"{component}-rpm-buildmeta.json"
    if not path.is_file():
        return None
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
        return data if isinstance(data, dict) else None
    except (OSError, json.JSONDecodeError):
        return None


def write_rpm_buildmeta(
    component_dir: Path,
    component: str,
    build: dict[str, Any],
    *,
    git_source: tuple[str, str] | None = None,
    origin: str,
    build_system_cmdb_id: str,
    build_url: str,
) -> None:
    """
    Write ``{component}-rpm-buildmeta.json`` for a Koji/Brew RPM build.

    Parameters
    ----------
    component_dir:
        Directory that already contains (or will contain) the RPM SBOM.
    component:
        Package name (``build["package_name"]``).
    build:
        Koji/Brew ``getBuild`` dict.
    git_source:
        ``(repository_url, committish)`` extracted from ``build["source"]``; omit
        to let :func:`extract_git_from_brew_build` derive it automatically.
    origin:
        Channel label stored in the sidecar (e.g. ``"brew"`` or ``"koji"``).
    build_system_cmdb_id:
        CMDB identifier for the build system (e.g. ``BREW-001``, ``KOJI-001``).
    build_url:
        Human-facing buildinfo URL for the build.
    """
    if git_source is None:
        git_source = extract_git_from_brew_build(build) or ("", "")

    repo_url, committish = git_source

    meta: dict[str, Any] = {
        "origin": origin.lower(),
        "build_system_cmdb_id": build_system_cmdb_id,
        "build_id": build.get("build_id") or build.get("id"),
        "nvr": build.get("nvr"),
        "package_name": build.get("package_name") or build.get("name"),
        "version": build.get("version"),
        "release": build.get("release"),
        "epoch": build.get("epoch") or 0,
        "repository_url": repo_url or "",
        "committish": committish or "",
        "build_url": build_url,
    }

    component_dir.mkdir(parents=True, exist_ok=True)
    path = component_dir / f"{component}-rpm-buildmeta.json"
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(meta, fh, indent=2)
        fh.write("\n")


def koji_build_url(
    build: dict[str, Any],
    *,
    koji_web: str = DEFAULT_FEDORA_KOJI_WEB,
) -> str:
    """Return a human-facing Koji buildinfo URL for *build*."""
    bid = build.get("build_id") or build.get("id")
    if bid:
        return f"{koji_web.rstrip('/')}/buildinfo?buildID={bid}"
    return ""


def write_fedora_rpm_buildmeta(
    component_dir: Path,
    component: str,
    build: dict[str, Any],
    *,
    git_source: tuple[str, str] | None = None,
    koji_web: str = DEFAULT_FEDORA_KOJI_WEB,
) -> None:
    """Write ``{component}-rpm-buildmeta.json`` for a Fedora Koji RPM build."""
    if git_source is None:
        git_source = extract_git_from_brew_build(build) or ("", "")

    write_rpm_buildmeta(
        component_dir,
        component,
        build,
        git_source=git_source,
        origin="koji",
        build_system_cmdb_id=KOJI_CMDB_ID,
        build_url=koji_build_url(build, koji_web=koji_web),
    )


def normalize_committish_for_build_manifest(committish: str) -> str:
    """
    Return *committish* cleaned for storage; empty string when it looks like a
    bare version string rather than a real VCS ref (e.g. ``5.1.8-6.el9``).

    A valid committish is a 40-hex SHA-1 or a branch/tag with no embedded
    ``-el``/``.el`` dist tags.  Anything that looks like an NVR fragment is
    dropped to avoid silently wrong ``committish`` values in the database.
    """
    c = (committish or "").strip()
    if not c:
        return ""
    # 40-hex = Git SHA-1
    if re.fullmatch(r"[0-9a-f]{40}", c, re.IGNORECASE):
        return c
    # Reject NVR-like strings (contain a dist tag suffix like .el8 or -6.el9)
    if re.search(r"\.(el|fc|rhel)\d", c):
        return ""
    return c
