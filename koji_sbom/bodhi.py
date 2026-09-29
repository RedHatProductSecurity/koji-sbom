"""Resolve EPEL yum NVRs against Bodhi pending/testing updates.

Fetches Bodhi once per process (pending + testing RPM updates for current EPEL
releases) and compares with ``rpm.labelCompare``. Non-EPEL NVRs (including
``.fcN`` Fedora builds) are returned unchanged. ``generate_sbom`` stays exact;
callers that want Bodhi resolution invoke :func:`resolve_newer_epel_nvr` (or the
CLI, which does so before generation).
"""

from __future__ import annotations

import json
import logging
import re
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

import rpm

log = logging.getLogger(__name__)

BODHI_UPDATES_URL = "https://bodhi.fedoraproject.org/updates/"
BODHI_RELEASES_URL = "https://bodhi.fedoraproject.org/releases/"

_BODHI_STATUSES: tuple[str, ...] = ("pending", "testing")
_RELEASE_STATES: tuple[str, ...] = ("current",)
_ROWS_PER_PAGE = 100
_REQUEST_TIMEOUT_S = 120

_EL_MAJOR_RE = re.compile(r"\.el(\d+)")
_FC_RE = re.compile(r"\.fc\d+")
_EPEL_RELEASE_MAJOR_RE = re.compile(r"^EPEL-(\d+)")
_EPEL_RELEASE_MINOR_RE = re.compile(r"^EPEL-(\d+)\.(\d+)$")

# Process-wide caches so discovery / CLI do not re-page Bodhi per NVR.
_cached_index: EpelBodhiIndex | None = None
_cached_releases: tuple[EpelRelease, ...] | None = None


@dataclass(frozen=True)
class EpelRelease:
    """One current Bodhi EPEL release."""

    name: str
    dist_tag: str
    major: int
    minor: int | None  # set for EPEL-10.4-style names; None for EPEL-8 / EPEL-9N


@dataclass(frozen=True)
class EpelBodhiIndex:
    """Newest pending/testing RPM NVR per ``(package_name, epel_major)``."""

    newest: Mapping[tuple[str, int], tuple[str, object | None]] = field(default_factory=dict)

    def lookup(self, package_name: str, epel_major: int) -> tuple[str, object | None] | None:
        return self.newest.get((package_name, epel_major))


def package_name_from_nvr(nvr: str) -> str:
    """Extract the RPM package name from an NVR (first segment before version)."""
    parts = nvr.split("-")
    for i in range(1, len(parts)):
        if parts[i] and parts[i][0].isdigit():
            return "-".join(parts[:i])
    return nvr


def epel_major_from_nvr(nvr: str) -> int | None:
    """Return the EPEL major from an ``.elN`` NVR, or None for non-EPEL (e.g. ``.fcN``)."""
    if _FC_RE.search(nvr):
        return None
    match = _EL_MAJOR_RE.search(nvr)
    return int(match.group(1)) if match else None


def epel_major_from_release(release_name: str) -> int | None:
    """Map a Bodhi release name (``EPEL-10.4``, ``EPEL-9N``) to its EPEL major."""
    if release_name.endswith("N"):
        stem = release_name[:-1]
        match = _EPEL_RELEASE_MAJOR_RE.match(stem)
        return int(match.group(1)) if match else None
    match = _EPEL_RELEASE_MAJOR_RE.match(release_name)
    return int(match.group(1)) if match else None


def _epel_release_from_bodhi_row(row: Mapping[str, Any]) -> EpelRelease | None:
    name = str(row.get("name") or "")
    if not name.startswith("EPEL-") or name.endswith("M"):
        return None
    major = epel_major_from_release(name)
    if major is None:
        return None
    dist_tag = str(row.get("dist_tag") or "").strip()
    if not dist_tag:
        return None
    minor: int | None = None
    match = _EPEL_RELEASE_MINOR_RE.match(name)
    if match:
        minor = int(match.group(2))
    return EpelRelease(name=name, dist_tag=dist_tag, major=major, minor=minor)


def _releases_query_url(*, state: str, page: int) -> str:
    params = [
        ("state", state),
        ("rows_per_page", str(_ROWS_PER_PAGE)),
        ("page", str(page)),
    ]
    return f"{BODHI_RELEASES_URL}?{urllib.parse.urlencode(params)}"


def fetch_current_epel_releases() -> tuple[EpelRelease, ...]:
    """Return all current Bodhi EPEL releases (every major / minor still current)."""
    found: dict[str, EpelRelease] = {}
    for state in _RELEASE_STATES:
        page = 1
        pages = 1
        while page <= pages:
            url = _releases_query_url(state=state, page=page)
            log.debug("fetching Bodhi releases %s", url)
            payload = _http_get_json(url)
            pages = int(payload.get("pages") or 1)
            batch = payload.get("releases") or []
            if not isinstance(batch, list):
                raise RuntimeError(f"Bodhi releases list missing for state={state} page={page}")
            for row in batch:
                if not isinstance(row, dict):
                    continue
                release = _epel_release_from_bodhi_row(row)
                if release is not None:
                    found[release.name] = release
            page += 1
    releases = tuple(sorted(found.values(), key=lambda r: (r.major, r.minor or -1, r.name)))
    if not releases:
        raise RuntimeError("Bodhi returned no current EPEL releases")
    log.info(
        "Bodhi current EPEL releases: %s",
        ", ".join(r.name for r in releases),
    )
    return releases


def get_current_epel_releases(*, refresh: bool = False) -> tuple[EpelRelease, ...]:
    """Return process-cached current EPEL releases.

    Raises :class:`RuntimeError` if Bodhi ``/releases`` cannot be fetched.
    """
    global _cached_releases
    if _cached_releases is not None and not refresh:
        return _cached_releases
    _cached_releases = fetch_current_epel_releases()
    return _cached_releases


def get_current_epel_release_names(*, refresh: bool = False) -> tuple[str, ...]:
    """Bodhi release names for all current EPEL majors (and current minors)."""
    return tuple(r.name for r in get_current_epel_releases(refresh=refresh))


def get_latest_epel_koji_tag(major: int, *, refresh: bool = False) -> str:
    """Return the Koji ``dist_tag`` for the newest current EPEL *major* minor.

    Skips ``*N`` (Next) releases. Raises :class:`LookupError` if no current
    non-Next release exists for *major*.
    """
    candidates = [
        r
        for r in get_current_epel_releases(refresh=refresh)
        if r.major == major and not r.name.endswith("N")
    ]
    if not candidates:
        raise LookupError(f"no current Bodhi EPEL release for major {major}")
    best = max(candidates, key=lambda r: (r.minor is not None, r.minor or 0, r.name))
    return best.dist_tag


def _epoch_str(value: object | None) -> str:
    if value is None or value == "":
        return "0"
    if isinstance(value, bool):
        return "0"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, str) and value.isdigit():
        return value
    return "0"


def _version_release_from_nvr(package_name: str, nvr: str) -> tuple[str, str] | None:
    prefix = f"{package_name}-"
    if not package_name or not nvr.startswith(prefix):
        return None
    rest = nvr[len(prefix) :]
    if "-" not in rest:
        return rest, ""
    version, release = rest.rsplit("-", 1)
    return version, release


def compare_rpm_nvrs(
    package_name: str,
    left_nvr: str,
    right_nvr: str,
    *,
    left_epoch: object | None = None,
    right_epoch: object | None = None,
) -> int | None:
    """Compare two NVRs for *package_name* via ``rpm.labelCompare``.

    Returns -1/0/1, or None if either NVR is unparsable.
    Requires the system ``python3-rpm`` package (``import rpm``).
    """
    left = _version_release_from_nvr(package_name, left_nvr)
    right = _version_release_from_nvr(package_name, right_nvr)
    if left is None or right is None:
        return None

    return int(
        rpm.labelCompare(
            (_epoch_str(left_epoch), left[0], left[1]),
            (_epoch_str(right_epoch), right[0], right[1]),
        )
    )


def _pick_newer(
    package_name: str,
    left: tuple[str, object | None],
    right: tuple[str, object | None],
) -> tuple[str, object | None]:
    left_nvr, left_epoch = left
    right_nvr, right_epoch = right
    cmp = compare_rpm_nvrs(
        package_name,
        left_nvr,
        right_nvr,
        left_epoch=left_epoch,
        right_epoch=right_epoch,
    )
    if cmp is None:
        return left if left_nvr >= right_nvr else right
    if cmp >= 0:
        return left
    return right


def _http_get_json(url: str) -> dict[str, Any]:
    req = urllib.request.Request(
        url,
        headers={
            "Accept": "application/json",
            "User-Agent": "koji-sbom/bodhi",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=_REQUEST_TIMEOUT_S) as resp:
            payload = json.load(resp)
    except urllib.error.HTTPError as exc:
        body = ""
        try:
            body = exc.read().decode("utf-8", errors="replace")[:200]
        except Exception:  # noqa: BLE001 — best-effort error detail
            pass
        raise RuntimeError(f"Bodhi HTTP {exc.code} for {url}: {body}") from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(f"Bodhi request failed for {url}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"Bodhi returned invalid JSON for {url}: {exc}") from exc
    if not isinstance(payload, dict):
        raise RuntimeError(f"Bodhi returned non-object JSON for {url}")
    return payload


def _updates_query_url(
    *,
    status: str,
    page: int,
    releases: Sequence[str],
    rows_per_page: int = _ROWS_PER_PAGE,
) -> str:
    params: list[tuple[str, str]] = [
        ("status", status),
        ("content_type", "rpm"),
        ("rows_per_page", str(rows_per_page)),
        ("page", str(page)),
    ]
    for release in releases:
        params.append(("releases", release))
    return f"{BODHI_UPDATES_URL}?{urllib.parse.urlencode(params)}"


def _iter_bodhi_updates(
    *,
    status: str,
    releases: Sequence[str],
) -> list[dict[str, Any]]:
    updates: list[dict[str, Any]] = []
    page = 1
    pages = 1
    while page <= pages:
        url = _updates_query_url(status=status, page=page, releases=releases)
        log.debug("fetching Bodhi %s", url)
        payload = _http_get_json(url)
        pages = int(payload.get("pages") or 1)
        batch = payload.get("updates") or []
        if not isinstance(batch, list):
            raise RuntimeError(f"Bodhi updates list missing for status={status} page={page}")
        updates.extend(u for u in batch if isinstance(u, dict))
        page += 1
    return updates


def _index_from_updates(updates: Sequence[Mapping[str, Any]]) -> EpelBodhiIndex:
    newest: dict[tuple[str, int], tuple[str, object | None]] = {}
    for update in updates:
        release = update.get("release") if isinstance(update.get("release"), dict) else {}
        release_name = str(release.get("name") or "")
        major = epel_major_from_release(release_name)
        if major is None:
            continue
        builds = update.get("builds") or []
        if not isinstance(builds, list):
            continue
        for build in builds:
            if not isinstance(build, dict):
                continue
            if build.get("type") != "rpm":
                continue
            nvr = build.get("nvr")
            if not isinstance(nvr, str) or not nvr:
                continue
            # Prefer NVR-derived major so EPEL-10.x never indexes under a wrong major.
            nvr_major = epel_major_from_nvr(nvr)
            if nvr_major is None or nvr_major != major:
                continue
            name = package_name_from_nvr(nvr)
            if not name:
                continue
            key = (name, major)
            candidate = (nvr, build.get("epoch"))
            prev = newest.get(key)
            if prev is None:
                newest[key] = candidate
            else:
                newest[key] = _pick_newer(name, prev, candidate)
    return EpelBodhiIndex(newest=newest)


def fetch_epel_bodhi_index(
    *,
    releases: Sequence[str] | None = None,
) -> EpelBodhiIndex:
    """Page Bodhi for pending and testing EPEL RPM updates and index newest NVRs.

    When *releases* is omitted, all current EPEL majors/minors from Bodhi
    ``/releases`` are used. Raises :class:`RuntimeError` if Bodhi is unavailable.
    """
    if releases is None:
        releases = get_current_epel_release_names()
    updates: list[dict[str, Any]] = []
    for status in _BODHI_STATUSES:
        updates.extend(_iter_bodhi_updates(status=status, releases=releases))
    index = _index_from_updates(updates)
    log.info(
        "Bodhi EPEL index (%s): %d pending/testing updates → %d package/major NVRs",
        ",".join(releases),
        len(updates),
        len(index.newest),
    )
    return index


def get_epel_bodhi_index(
    *,
    refresh: bool = False,
    releases: Sequence[str] | None = None,
) -> EpelBodhiIndex:
    """Return a process-cached :class:`EpelBodhiIndex`, fetching Bodhi if needed."""
    global _cached_index
    if _cached_index is not None and not refresh and releases is None:
        return _cached_index
    index = fetch_epel_bodhi_index(releases=releases)
    if releases is None:
        _cached_index = index
    return index


def clear_epel_bodhi_index_cache() -> None:
    """Drop the process-cached Bodhi index and release list (for tests)."""
    global _cached_index, _cached_releases
    _cached_index = None
    _cached_releases = None


def resolve_newer_epel_nvr(
    nvr: str,
    *,
    index: EpelBodhiIndex | None = None,
) -> str:
    """Return whichever is newer of *nvr* and a Bodhi pending/testing build.

    Non-EPEL NVRs (including ``.fcN``) are returned unchanged. An older Bodhi
    build does not replace *nvr*. When *index* is omitted, Bodhi is fetched once
    per process via :func:`get_epel_bodhi_index`.
    """
    major = epel_major_from_nvr(nvr)
    if major is None:
        return nvr
    name = package_name_from_nvr(nvr)
    if not name:
        return nvr
    bodhi_index = index if index is not None else get_epel_bodhi_index()
    candidate = bodhi_index.lookup(name, major)
    if candidate is None:
        return nvr
    bodhi_nvr, bodhi_epoch = candidate
    newer_nvr, _ = _pick_newer(name, (nvr, None), (bodhi_nvr, bodhi_epoch))
    if newer_nvr != nvr:
        log.debug("Bodhi newer than yum/CLI: %s → %s", nvr, newer_nvr)
    return newer_nvr


def resolve_newer_epel_nvrs(
    nvrs: Sequence[str],
    *,
    index: EpelBodhiIndex | None = None,
) -> list[str]:
    """Resolve each NVR in *nvrs* via :func:`resolve_newer_epel_nvr` (shared index)."""
    bodhi_index = index if index is not None else get_epel_bodhi_index()
    return [resolve_newer_epel_nvr(nvr, index=bodhi_index) for nvr in nvrs]


DEFAULT_FEDORA_ALL_KOJI_TAG = "rawhide"


def looks_like_rpm_nvr(value: str) -> bool:
    """Return True when *value* looks like ``name-version-release``, not a bare package."""
    name = package_name_from_nvr(value)
    return bool(name) and name != value and value.startswith(f"{name}-")


def latest_tagged_nvr(
    koji_url: str,
    package: str,
    *,
    tag: str,
) -> str:
    """Return the latest tagged NVR for *package* in *tag* on *koji_url*."""
    from koji_sbom.koji_session import KojiClient

    client = KojiClient(koji_url)
    rows = client.list_tagged(tag, package=package, latest=True, inherit=True)
    for row in rows:
        nvr = row.get("nvr")
        if isinstance(nvr, str) and nvr:
            return nvr
    raise LookupError(f"no build for package {package!r} in Koji tag {tag!r}")


def lookup_package_stream_nvrs(
    package: str,
    koji_url: str,
    *,
    use_bodhi: bool = True,
    index: EpelBodhiIndex | None = None,
) -> dict[str, str | None]:
    """Return latest NVRs for *package* on ``fedora-all`` and every current ``epel-N``.

    ``fedora-all`` uses the Koji ``rawhide`` tag (no Bodhi). Each ``epel-N`` uses
    the newest current Koji ``dist_tag`` for that major from Bodhi (e.g. ``epel10.4``
    for major 10), then :func:`resolve_newer_epel_nvrs` when *use_bodhi* is true.
    ``*N`` (Next) releases are not listed as separate streams. Missing streams map
    to ``None``.
    """
    bodhi_index = None
    if use_bodhi:
        bodhi_index = index if index is not None else get_epel_bodhi_index()

    majors = sorted({r.major for r in get_current_epel_releases() if not r.name.endswith("N")})
    streams: list[tuple[str, str, bool]] = [
        ("fedora-all", DEFAULT_FEDORA_ALL_KOJI_TAG, False),
    ]
    for major in majors:
        streams.append((f"epel-{major}", get_latest_epel_koji_tag(major), True))

    out: dict[str, str | None] = {}
    for stream_id, tag, stream_uses_bodhi in streams:
        try:
            nvr = latest_tagged_nvr(koji_url, package, tag=tag)
        except LookupError:
            out[stream_id] = None
            continue
        if use_bodhi and stream_uses_bodhi:
            nvr = resolve_newer_epel_nvrs([nvr], index=bodhi_index)[0]
        out[stream_id] = nvr
    return out
