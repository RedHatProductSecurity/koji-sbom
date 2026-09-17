"""Tests for bundled provide parsing per security-data-guidelines sbom.md."""

from __future__ import annotations

import pytest
from koji_sbom.bundled import (
    bundled_golang_from_provides,
    bundled_provides_to_spdx_fragments,
    bundled_purls,
)
from koji_sbom.models import RpmDep

# Examples from security-data-guidelines docs/sbom.md "Bundled dependencies" table.
BUNDLED_PURL_EXAMPLES = [
    ("bundled(libvterm)", "", "pkg:generic/libvterm"),
    ("golang(github.com/foo/bar)", "1.2.3", "pkg:golang/github.com/foo/bar@1.2.3"),
    ("bundled(python(requests))", "2.31.0", "pkg:pypi/requests@2.31.0"),
    ("bundled(python3dist(requests))", "2.31.0", "pkg:pypi/requests@2.31.0"),
    ("bundled(python3-requests)", "2.31.0", "pkg:pypi/requests@2.31.0"),
    ("bundled(nodejs(lodash))", "4.17.21", "pkg:npm/lodash@4.17.21"),
    ("bundled(npm(lodash))", "4.17.21", "pkg:npm/lodash@4.17.21"),
    ("bundled(nodejs-lodash)", "4.17.21", "pkg:npm/lodash@4.17.21"),
    ("bundled(ruby(rake))", "13.0.6", "pkg:gem/rake@13.0.6"),
    ("bundled(rubygem-rake)", "13.0.6", "pkg:gem/rake@13.0.6"),
    ("bundled(crate(serde))", "1.0.0", "pkg:cargo/serde@1.0.0"),
    ("bundled(mvn(org/foo))", "1.0.0", "pkg:maven/org/foo@1.0.0"),
]


@pytest.mark.parametrize(
    ("provide_name", "provide_version", "expected_purl"),
    BUNDLED_PURL_EXAMPLES,
    ids=[row[0] for row in BUNDLED_PURL_EXAMPLES],
)
def test_bundled_purl_examples_from_guidelines(
    provide_name: str,
    provide_version: str,
    expected_purl: str,
) -> None:
    deps = bundled_golang_from_provides([RpmDep(provide_name, provide_version, 1)])
    assert len(deps) == 1
    assert bundled_purls(deps[0])[0] == expected_purl


def test_bundled_libvterm_spdx_shape_from_guidelines() -> None:
    """Unversioned ``bundled(libvterm)`` matches the SPDX 2.3 doc example."""
    deps = bundled_golang_from_provides([RpmDep("bundled(libvterm)", "", 1)])
    packages, relationships = bundled_provides_to_spdx_fragments(
        deps,
        srpm_spdx_id="SPDXRef-SRPM",
    )

    assert len(packages) == 1
    assert len(relationships) == 1

    pkg = packages[0]
    assert pkg["SPDXID"].startswith("SPDXRef-Bundled-")
    assert pkg["name"] == "libvterm (generic)"
    assert pkg["versionInfo"] == "NOASSERTION"
    assert pkg["downloadLocation"] == "NOASSERTION"
    assert pkg["filesAnalyzed"] is False
    assert pkg["primaryPackagePurpose"] == "LIBRARY"
    assert pkg["externalRefs"] == [
        {
            "referenceCategory": "PACKAGE-MANAGER",
            "referenceType": "purl",
            "referenceLocator": "pkg:generic/libvterm",
        }
    ]

    rel = relationships[0]
    assert rel["spdxElementId"] == pkg["SPDXID"]
    assert rel["relationshipType"] == "DEPENDENCY_OF"
    assert rel["relatedSpdxElement"] == "SPDXRef-SRPM"


def test_github_provenance_preserves_generic_provide_identity() -> None:
    """Source provenance supplements, but never replaces, bundled(foo)."""
    dep = RpmDep("bundled(expat)", "", 1)
    bundled = bundled_golang_from_provides([dep])
    bundled[0].vcs_url = "git+https://github.com/libexpat/libexpat"

    packages, _ = bundled_provides_to_spdx_fragments(bundled, srpm_spdx_id="SPDXRef-SRPM")

    assert packages[0]["name"] == "expat (generic)"
    assert [ref["referenceLocator"] for ref in packages[0]["externalRefs"]] == [
        "pkg:generic/expat?vcs_url=git%2Bhttps%3A%2F%2Fgithub.com%2Flibexpat%2Flibexpat",
        "pkg:github/libexpat/libexpat",
    ]
