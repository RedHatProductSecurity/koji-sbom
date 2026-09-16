"""Collect Koji ``Provides`` / ``Requires`` for every RPM in a build."""

from __future__ import annotations

import logging

from koji_sbom.koji_session import KojiClient
from koji_sbom.models import RpmDep

log = logging.getLogger(__name__)


def _list_rpm_ids_for_build(client: KojiClient, build_id: int) -> list[int]:
    ids: list[int] = []
    for row in client.list_rpms(build_id):
        rid = row.get("id") or row.get("rpm_id")
        if isinstance(rid, int):
            ids.append(rid)
    return ids


def _flatten_rpm_deps_by_type(dep_batches: list[list[dict]], want_type: int) -> list[RpmDep]:
    out: list[RpmDep] = []
    for batch in dep_batches:
        for d in batch:
            if not isinstance(d, dict):
                continue
            t = d.get("type")
            if t != want_type:
                continue
            name = str(d.get("name") or "")
            ver = str(d.get("version") or "")
            out.append(RpmDep(name=name, version=ver, dep_type=want_type))
    return out


def _get_dep_batches(client: KojiClient, build_id: int) -> list[list[dict]]:
    rpm_ids = _list_rpm_ids_for_build(client, build_id)
    if not rpm_ids:
        return []
    batches = client.get_rpm_deps_multicall(rpm_ids)
    if len(batches) != len(rpm_ids):
        log.warning(
            "getRPMDeps multicall length mismatch build=%s rpm_ids=%s batches=%s",
            build_id,
            len(rpm_ids),
            len(batches),
        )
    return batches


def all_provides_for_build(client: KojiClient, build_id: int) -> list[RpmDep]:
    """Every ``Provides`` (type 1) from ``getRPMDeps`` for each RPM in the build."""
    provides, _ = rpm_provides_and_requires_for_build(client, build_id)
    return provides


def all_requires_for_build(client: KojiClient, build_id: int) -> list[RpmDep]:
    """
    Every unique ``Requires`` (type 0) from ``getRPMDeps`` for each RPM in the build.

    Dedupes by ``name + "/" + version`` like Deptopia ``GetRpmsDeps``.
    """
    _, requires = rpm_provides_and_requires_for_build(client, build_id)
    return requires


def rpm_provides_and_requires_for_build(
    client: KojiClient,
    build_id: int,
) -> tuple[list[RpmDep], list[RpmDep]]:
    """Single ``multiCall`` of ``getRPMDeps`` — both Provides (1) and Requires (0)."""
    batches = _get_dep_batches(client, build_id)
    provides = _flatten_rpm_deps_by_type(batches, 1)
    requires = _dedupe_requires(_flatten_rpm_deps_by_type(batches, 0))
    return provides, requires


def _dedupe_requires(rows: list[RpmDep]) -> list[RpmDep]:
    """Collapse duplicate name/version pairs (multiple arches)."""
    by_key: dict[str, RpmDep] = {}
    for row in rows:
        key = f"{row.name}/{row.version}"
        if key not in by_key:
            by_key[key] = row
    return list(by_key.values())
