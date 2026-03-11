"""Generate SPDX SBOM from database for a stream."""
from datetime import datetime, timezone

from django.db.models import Prefetch

from sbom.models import Build, Package, Stream


def generate_sbom(stream_tag: str) -> dict | None:
    """
    Generate SPDX 2.3 JSON document for the given stream.
    Returns None if stream not found.
    """
    try:
        stream = Stream.objects.get(tag=stream_tag)
    except Stream.DoesNotExist:
        return None

    builds = (
        Build.objects.filter(streams=stream)
        .prefetch_related(
            Prefetch("packages", queryset=Package.objects.order_by("arch", "name"))
        )
        .order_by("-build_id")
    )

    packages = []
    relationships = []
    doc_namespace = f"https://koji-sbom.local/{stream_tag}.spdx.json"

    for build in builds:
        build_packages = list(build.packages.all())
        if not build_packages:
            continue

        srpm = next((p for p in build_packages if p.arch == "src"), None)
        binary_rpms = [p for p in build_packages if p.arch != "src"]

        srpm_spdx_id = f"SPDXRef-SRPM-{build.id}"
        if srpm:
            packages.append(_spdx_package(srpm, srpm_spdx_id, build))
        else:
            packages.append(_synthetic_srpm(build, srpm_spdx_id))

        relationships.append({
            "spdxElementId": "SPDXRef-DOCUMENT",
            "relationshipType": "DESCRIBES",
            "relatedSpdxElementId": srpm_spdx_id,
        })

        for pkg in binary_rpms:
            pkg_spdx_id = _sanitize_spdx_id(f"SPDXRef-{pkg.arch}-{pkg.name}")
            packages.append(_spdx_package(pkg, pkg_spdx_id, build))
            relationships.append({
                "spdxElementId": pkg_spdx_id,
                "relationshipType": "GENERATED_FROM",
                "relatedSpdxElementId": srpm_spdx_id,
            })

    if not packages:
        return {
            "spdxVersion": "SPDX-2.3",
            "dataLicense": "CC0-1.0",
            "SPDXID": "SPDXRef-DOCUMENT",
            "creationInfo": {
                "created": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "creators": ["Tool: koji-sbom", "Organization: Red Hat"],
            },
            "name": stream_tag,
            "documentNamespace": doc_namespace,
            "packages": [],
            "relationships": [],
        }

    return {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "creationInfo": {
            "created": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "creators": ["Tool: koji-sbom", "Organization: Red Hat"],
        },
        "name": stream_tag,
        "documentNamespace": doc_namespace,
        "packages": packages,
        "relationships": relationships,
    }


def _sanitize_spdx_id(value: str) -> str:
    """Emit valid SPDXRef-[idstring] - letters, numbers, ., - only."""
    value = value.replace("_", "-")
    return "".join(c for c in value if c.isalnum() or c in ".-")


def _synthetic_srpm(build: Build, spdx_id: str) -> dict:
    """Create synthetic SRPM entry when we only have binary RPMs (e.g. from YUM)."""
    version_release = f"{build.version}-{build.release}"
    purl = f"pkg:rpm/redhat/{build.pkg_name}@{version_release}?arch=src"
    return {
        "SPDXID": spdx_id,
        "name": build.pkg_name,
        "versionInfo": version_release,
        "supplier": "Organization: Red Hat",
        "downloadLocation": "NOASSERTION",
        "packageFileName": f"{build.nvr}.src.rpm",
        "licenseConcluded": "NOASSERTION",
        "externalRefs": [
            {
                "referenceCategory": "PACKAGE-MANAGER",
                "referenceType": "purl",
                "referenceLocator": purl,
            }
        ],
        "checksums": [],
    }


def _spdx_package(pkg: Package, spdx_id: str, build: Build) -> dict:
    """Build SPDX package dict per security-data-guidelines."""
    version_release = f"{pkg.version}-{pkg.release}"
    purl = f"pkg:rpm/redhat/{pkg.name}@{version_release}?arch={pkg.arch}"
    package = {
        "SPDXID": spdx_id,
        "name": pkg.name,
        "versionInfo": version_release,
        "supplier": "Organization: Red Hat",
        "downloadLocation": "NOASSERTION",
        "packageFileName": f"{pkg.nvr}.{pkg.arch}.rpm",
        "licenseConcluded": "NOASSERTION",
        "externalRefs": [
            {
                "referenceCategory": "PACKAGE-MANAGER",
                "referenceType": "purl",
                "referenceLocator": purl,
            }
        ],
        "checksums": [],
    }
    if pkg.payload_hash:
        package["checksums"].append({
            "algorithm": "SHA256",
            "checksumValue": pkg.payload_hash,
        })
    return package
