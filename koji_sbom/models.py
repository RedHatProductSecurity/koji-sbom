"""Typed records for Koji RPM dependency and bundled provide extraction."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class RpmDep:
    """Koji ``getRPMDeps`` row (Deptopia ``RpmDep``)."""

    name: str
    version: str
    dep_type: int  # 0 requires, 1 provides


@dataclass
class BundledDep:
    """Single ``bundled()`` or ``golang()`` provide after parsing."""

    path: str
    version: str
    lang: str  # "generic", "golang", "python", ...
    vcs_url: str = ""
    download_url: str = ""
