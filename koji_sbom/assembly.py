"""
SPDX 2.3 assembly utilities for metadata-only RPM SBOMs.

Produces ``{component}-rpm-sbom.json`` SPDX 2.3 documents for RPM builds.
"""

from __future__ import annotations

import hashlib
import re
import uuid
from datetime import datetime, timezone
from importlib.metadata import version
from typing import Any

REPORTED_BINARY_ARCHES = frozenset({"noarch", "x86_64"})

# ── PURL construction ─────────────────────────────────────────────────────────


def rpm_purl(
    name: str,
    version: str,
    release: str,
    *,
    namespace: str = "redhat",
    epoch: int | str = 0,
    arch: str = "src",
    module_nsvc: str | None = None,
    upstream: str | None = None,
) -> str:
    """
    Build a ``pkg:rpm/<namespace>/`` PURL per Red Hat security-data-guidelines.

    ``module_nsvc`` is the colon-delimited ``name:stream:version:context``
    string added as the ``rpmmod`` qualifier for modular RPMs.

    ``upstream`` is the SourceRPM filename (``name-ver-rel.src.rpm``) used by
    container SBOMs and RHCOS Brew enrichment for binary→SRPM lineage.
    """
    qualifiers: list[str] = [f"arch={arch}"]
    ep = int(epoch or 0)
    if ep:
        qualifiers.append(f"epoch={ep}")
    if module_nsvc:
        qualifiers.append(f"rpmmod={module_nsvc}")
    if upstream:
        qualifiers.append(f"upstream={upstream}")
    qs = "&".join(qualifiers)
    return f"pkg:rpm/{namespace}/{name}@{version}-{release}?{qs}"


# ── SPDX ID helpers ───────────────────────────────────────────────────────────


def _spdx_ref(label: str) -> str:
    safe = re.sub(r"[^A-Za-z0-9\-.]", "-", label)
    return f"SPDXRef-{safe}"


def _stable_id(category: str, key: str) -> str:
    h = hashlib.sha256(key.encode()).hexdigest()[:12]
    return f"SPDXRef-{category}-{h}"


def binary_spdx_id(rpm_name: str, arch: str) -> str:
    """Stable SPDX id for one binary subpackage (name + arch)."""
    return _stable_id("BinaryRPM", f"{rpm_name}\x00{arch}")


def is_binary_rpm(rpm: dict[str, Any]) -> bool:
    """True for qualifying noarch/x86_64 non-debug binary subpackages."""
    arch = str(rpm.get("arch") or "")
    if arch in ("src", "nosrc", "source"):
        return False
    if arch not in REPORTED_BINARY_ARCHES:
        return False
    name = str(rpm.get("name") or "")
    if name.endswith("-debuginfo") or name.endswith("-debugsource"):
        return False
    return True


def filter_binary_rpms(rpms: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Return sorted qualifying binary RPM rows from a Koji ``listRPMs`` result."""
    out = [r for r in rpms if is_binary_rpm(r)]
    out.sort(key=lambda r: (str(r.get("name") or ""), str(r.get("arch") or "")))
    return out


# ── SRPM package ──────────────────────────────────────────────────────────────


def make_srpm_package(
    build: dict[str, Any],
    *,
    namespace: str = "redhat",
    git_source: tuple[str, str] | None = None,
    module_nsvc: str | None = None,
    cpe_refs: list[str] | None = None,
) -> dict[str, Any]:
    """
    Build the root SRPM SPDX package dict.

    Parameters
    ----------
    build:
        Brew ``getBuild`` dict.
    git_source:
        ``(repository_url, committish)`` for ``downloadLocation``.
    module_nsvc:
        ``name:stream:version:context`` for modular SRPMs.
    cpe_refs:
        Product CPE strings from Errata Tool (omit for ``rhel-br-8``).
    """
    name = build.get("package_name") or build.get("name") or ""
    version = build.get("version") or ""
    release = build.get("release") or ""
    epoch = int(build.get("epoch") or 0)
    nvr = build.get("nvr") or f"{name}-{version}-{release}"

    download_location = "NOASSERTION"
    if git_source:
        url, committish = git_source
        if url:
            download_location = f"{url}#{committish}" if committish else url

    purl = rpm_purl(
        name,
        version,
        release,
        namespace=namespace,
        epoch=epoch,
        arch="src",
        module_nsvc=module_nsvc,
    )

    external_refs: list[dict[str, str]] = [
        {
            "referenceCategory": "PACKAGE-MANAGER",
            "referenceType": "purl",
            "referenceLocator": purl,
        }
    ]
    for cpe in cpe_refs or []:
        external_refs.append(
            {
                "referenceCategory": "SECURITY",
                "referenceType": "cpe23Type",
                "referenceLocator": cpe,
            }
        )

    return {
        "SPDXID": "SPDXRef-SRPM",
        "name": name,
        "versionInfo": f"{version}-{release}",
        "downloadLocation": download_location,
        "filesAnalyzed": False,
        "primaryPackagePurpose": "SOURCE",
        "comment": f"SRPM build {nvr}",
        "externalRefs": external_refs,
    }


# ── Binary RPM package ────────────────────────────────────────────────────────


def make_binary_rpm_package(
    rpm: dict[str, Any],
    build: dict[str, Any],
    *,
    namespace: str = "redhat",
    module_nsvc: str | None = None,
) -> dict[str, Any]:
    """
    Build one binary RPM SPDX package (``GENERATED_FROM`` the SRPM).

    Uses the subpackage *name* and *arch* from the Koji ``listRPMs`` row.
    """
    name = str(rpm.get("name") or build.get("package_name") or build.get("name") or "")
    version = build.get("version") or ""
    release = build.get("release") or ""
    epoch = int(build.get("epoch") or 0)
    arch = str(rpm.get("arch") or "noarch")
    srpm_name = build.get("package_name") or build.get("name") or name
    nvr = build.get("nvr") or f"{srpm_name}-{version}-{release}"
    upstream = f"{nvr}.src.rpm"

    purl = rpm_purl(
        name,
        version,
        release,
        namespace=namespace,
        epoch=epoch,
        arch=arch,
        module_nsvc=module_nsvc,
        upstream=upstream,
    )

    return {
        "SPDXID": binary_spdx_id(name, arch),
        "name": name,
        "versionInfo": f"{version}-{release}",
        "downloadLocation": "NOASSERTION",
        "filesAnalyzed": False,
        "primaryPackagePurpose": "LIBRARY",
        "externalRefs": [
            {
                "referenceCategory": "PACKAGE-MANAGER",
                "referenceType": "purl",
                "referenceLocator": purl,
            }
        ],
    }


# ── Full SPDX document assembly ───────────────────────────────────────────────


def assemble_rpm_spdx_document(
    build: dict[str, Any],
    syft_packages: list[dict[str, Any]],
    syft_relationships: list[dict[str, Any]],
    bundled_packages: list[dict[str, Any]],
    bundled_relationships: list[dict[str, Any]],
    *,
    rpms: list[dict[str, Any]] | None = None,
    source_packages: list[dict[str, Any]] | None = None,
    source_relationships: list[dict[str, Any]] | None = None,
    namespace: str = "redhat",
    git_source: tuple[str, str] | None = None,
    module_nsvc: str | None = None,
    cpe_refs: list[str] | None = None,
) -> dict[str, Any]:
    """
    Produce the final ``{component}-rpm-sbom.json`` SPDX 2.3 document.

    Package order:
    1. SRPM root (described by document)
    2. Binary RPM subpackages (GENERATED_FROM SRPM)
    3. Spec source archives (CONTAINS from SRPM)
    4. Syft packages (DEPENDENCY_OF SRPM)
    5. Bundled provides packages (DEPENDENCY_OF SRPM)
       — includes ``pkg:golang/stdlib@X.Y`` entries derived from ``go.mod``
    """
    srpm_pkg = make_srpm_package(
        build,
        namespace=namespace,
        git_source=git_source,
        module_nsvc=module_nsvc,
        cpe_refs=cpe_refs,
    )
    binaries = filter_binary_rpms(rpms or [])
    binary_pkgs = [
        make_binary_rpm_package(rpm, build, namespace=namespace, module_nsvc=module_nsvc)
        for rpm in binaries
    ]

    src_pkgs = source_packages or []
    src_rels = source_relationships or []
    packages = [srpm_pkg] + binary_pkgs + src_pkgs + syft_packages + bundled_packages

    relationships: list[dict[str, Any]] = [
        {
            "spdxElementId": "SPDXRef-DOCUMENT",
            "relationshipType": "DESCRIBES",
            "relatedSpdxElement": "SPDXRef-SRPM",
        },
    ]
    for pkg in binary_pkgs:
        relationships.append(
            {
                "spdxElementId": pkg["SPDXID"],
                "relationshipType": "GENERATED_FROM",
                "relatedSpdxElement": "SPDXRef-SRPM",
            }
        )
    relationships.extend(src_rels)
    relationships.extend(syft_relationships)
    relationships.extend(bundled_relationships)

    name = build.get("nvr") or build.get("package_name") or "unknown"
    doc_id = f"https://koji-sbom.fedoraproject.org/rpm-sbom/{uuid.uuid4()}"

    return {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": name,
        "documentNamespace": doc_id,
        "creationInfo": {
            "created": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "creators": [f"Tool: koji-sbom-{version('koji-sbom')}"],
        },
        "documentDescribes": ["SPDXRef-SRPM"],
        "packages": packages,
        "relationships": relationships,
    }
