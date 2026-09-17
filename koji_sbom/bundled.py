"""
``bundled()`` / ``golang()`` / ``python*dist()`` from Koji Provides.

Lightweight SPDX 2 document fragments for metadata-only RPM SBOMs.
"""

from __future__ import annotations

import hashlib
import re
from typing import Any
from urllib.parse import quote

from koji_sbom.models import BundledDep, RpmDep

LANG_TO_PURL_TYPE: dict[str, str] = {
    "golang": "golang",
    "python": "pypi",
    "nodejs": "npm",
    "rust": "cargo",
    "ruby": "gem",
    "java": "maven",
    "generic": "generic",
}

_GITHUB_OWNER_REPO_RE = re.compile(
    r"(?:git\+)?https?://(?:www\.)?github\.com/([^/\s)>\"']+)/([^/\s)>\"'#]+)",
    re.IGNORECASE,
)


def github_owner_repo(url: str) -> tuple[str, str] | None:
    """Parse ``(owner, repo)`` from a github.com URL, or return ``None``."""
    if not url:
        return None
    match = _GITHUB_OWNER_REPO_RE.search(url)
    if not match:
        return None
    owner = match.group(1).lower().rstrip(".")
    repo = match.group(2).lower().rstrip(".")
    if repo.endswith(".git"):
        repo = repo[:-4]
    return owner, repo


def bundled_purls(dep: BundledDep) -> list[str]:
    """Return PURLs for a bundled dependency, preserving its RPM Provide identity.

    The first PURL is always derived from the RPM's virtual Provide.  Source-tree
    enrichment may add an upstream GitHub PURL as supplemental provenance, but it
    must not replace the identity declared by the shipped RPM.
    """
    ver = f"@{dep.version}" if dep.version else ""
    purl_type = LANG_TO_PURL_TYPE.get(dep.lang, "generic")

    if purl_type != "generic":
        base = f"pkg:{purl_type}/{dep.path}{ver}"
        qualifiers: list[str] = []
        if dep.vcs_url:
            qualifiers.append(f"vcs_url={quote(dep.vcs_url, safe='')}")
        if dep.download_url:
            qualifiers.append(f"download_url={quote(dep.download_url, safe='')}")
        if qualifiers:
            return [f"{base}?{'&'.join(qualifiers)}"]
        return [base]

    # A generic bundled provide is the authoritative identity. Retain its
    # generic name and type (for example bundled(expat)) while qualifying it
    # with any source-tree provenance discovered by the caller.
    base = f"pkg:generic/{dep.path}{ver}"
    qualifiers: list[str] = []
    if dep.vcs_url:
        qualifiers.append(f"vcs_url={quote(dep.vcs_url, safe='')}")
    if dep.download_url:
        qualifiers.append(f"download_url={quote(dep.download_url, safe='')}")
    purls = [f"{base}?{'&'.join(qualifiers)}" if qualifiers else base]

    github_coords = github_owner_repo(dep.vcs_url) or github_owner_repo(dep.download_url)
    if github_coords:
        owner, repo = github_coords
        purls.append(f"pkg:github/{owner}/{repo}{ver}")
    return purls


def bundled_purl(dep: BundledDep) -> str:
    """Primary purl for a bundled dependency (first entry from ``bundled_purls``)."""
    return bundled_purls(dep)[0]


def bundled_display_lang(dep: BundledDep) -> str:
    """Language label for an SPDX package name."""
    return dep.lang


def bundled_display_name(dep: BundledDep) -> str:
    """Package name for SPDX, based on the original RPM virtual Provide."""
    label = dep.path
    lang = bundled_display_lang(dep)
    name = f"{label} ({lang})"
    if dep.version:
        name = f"{name} {dep.version}"
    return name


def dep_lang_from_inner(name_inner: str) -> tuple[str, str]:
    """Map inner provide name → (path, lang). Mirrors ``getDepListLangFromName``."""
    if name_inner.startswith("golang)") and "(" in name_inner:
        ss = name_inner[len("golang)") :].lstrip()
        if ss.startswith("(") and ")" in ss:
            path = ss[1 : ss.index(")")]
            return path, "golang"

    s = name_inner
    if " with " in s:
        s = s.strip().strip("()")
        s = s.split(" ", 1)[0]

    parts = s.split("(", 1)
    if len(parts) > 1:
        prefix, rest = parts[0], parts[1].rstrip(")")
        lp = prefix.lower()
        if "golang" in lp:
            return rest, "golang"
        if "python" in lp:
            return rest, "python"
        if "npm" in lp or "nodejs" in lp:
            return rest, "nodejs"
        if "ruby" in lp:
            return rest, "ruby"
        if "crate" in lp:
            return rest, "rust"
        if "mvn" in lp:
            return rest, "java"

    sl = name_inner.lower()
    if sl.startswith("nodejs-"):
        return name_inner.split("-", 1)[1], "nodejs"
    if sl.startswith("python-") or sl.startswith("python3-") or sl.startswith("python2-"):
        return name_inner.split("-", 1)[1], "python"
    if sl.startswith("rubygem-"):
        return name_inner.split("-", 1)[1], "ruby"

    return name_inner, "generic"


def _parse_wrapped(
    prefix: str, rpm_name: str, rpm_ver: str, default_lang: str
) -> BundledDep | None:
    pfx = prefix + "("
    if not rpm_name.startswith(pfx) or not rpm_name.endswith(")"):
        return None
    inner = rpm_name[len(pfx) : -1]
    path, lang = dep_lang_from_inner(inner)
    if lang == "generic" and default_lang != "generic":
        lang = default_lang
    return BundledDep(path=path, version=rpm_ver, lang=lang)


_PYTHON_DIST_RE = re.compile(r"^python(?:\d+(?:\.\d+)?)?dist\(([^)]+)\)$")


def _parse_python_dist(rpm_name: str, rpm_ver: str) -> BundledDep | None:
    """
    Parse ``python3dist(foo)``, ``python3.11dist(bar)``, etc. → BundledDep.

    Matches RPM Provides like:
    - ``python3dist(requests)``
    - ``python3.11dist(requests)``
    - ``pythondist(requests)`` (older format)

    Returns a ``BundledDep`` with ``lang="python"`` and ``path`` = package name.
    """
    match = _PYTHON_DIST_RE.match(rpm_name)
    if not match:
        return None
    path = match.group(1)
    return BundledDep(path=path, version=rpm_ver, lang="python")


def bundled_golang_from_provides(provides: list[RpmDep]) -> list[BundledDep]:
    """Extract ``bundled(...)``, ``golang(...)``, and ``python*dist(...)`` Provides (type 1 rows)."""
    out: list[BundledDep] = []
    seen: set[tuple[str, str, str]] = set()
    for d in provides:
        b = _parse_wrapped("bundled", d.name, d.version, "generic")
        if b:
            key = (b.path, b.version, b.lang)
            if key not in seen:
                seen.add(key)
                out.append(b)
            continue
        g = _parse_wrapped("golang", d.name, d.version, "golang")
        if g:
            key = (g.path, g.version, g.lang)
            if key not in seen:
                seen.add(key)
                out.append(g)
            continue
        p = _parse_python_dist(d.name, d.version)
        if p:
            key = (p.path, p.version, p.lang)
            if key not in seen:
                seen.add(key)
                out.append(p)
    return out


def _ref_id(s: str) -> str:
    h = hashlib.sha256(s.encode("utf-8")).hexdigest()[:12]
    return f"SPDXRef-Bundled-{h}"


def _download_location(dep: BundledDep) -> str:
    if dep.vcs_url:
        return dep.vcs_url
    if dep.download_url:
        return dep.download_url
    return "NOASSERTION"


def bundled_provides_to_spdx_fragments(
    bundled: list[BundledDep],
    *,
    srpm_spdx_id: str,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """
    Return ``(packages, relationships)`` SPDX JSON-LD-style dicts (subset).

    Each bundled dep becomes a package; ``DEPENDENCY_OF`` links it to ``srpm_spdx_id``.
    """
    packages: list[dict[str, Any]] = []
    rels: list[dict[str, Any]] = []
    for b in bundled:
        purls = bundled_purls(b)
        purl = purls[0]
        pid = _ref_id(purl)
        name = bundled_display_name(b)
        external_refs = [
            {
                "referenceCategory": "PACKAGE-MANAGER",
                "referenceType": "purl",
                "referenceLocator": locator,
            }
            for locator in purls
        ]
        packages.append(
            {
                "SPDXID": pid,
                "name": name,
                "versionInfo": b.version or "NOASSERTION",
                "downloadLocation": _download_location(b),
                "filesAnalyzed": False,
                "primaryPackagePurpose": "LIBRARY",
                "externalRefs": external_refs,
            }
        )
        rels.append(
            {
                "spdxElementId": pid,
                "relationshipType": "DEPENDENCY_OF",
                "relatedSpdxElement": srpm_spdx_id,
            }
        )
    return packages, rels
