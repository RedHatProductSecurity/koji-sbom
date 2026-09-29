"""
Koji / Brew XML-RPC client (Deptopia ``internal/sources/brew.go`` patterns).

``multiCall`` uses ``methodName`` / ``params`` dict shapes as required by kojihub.
"""

from __future__ import annotations

import http.client
import logging
import socket
import ssl
import threading
import time
import urllib.parse
import xml.parsers.expat
import xmlrpc.client
from collections.abc import Iterable
from typing import Any

log = logging.getLogger(__name__)

_TRANSIENT_ERRORS = (
    TimeoutError,
    ConnectionError,
    socket.timeout,
    ssl.SSLEOFError,
    ssl.SSLZeroReturnError,
    xmlrpc.client.ProtocolError,
    xml.parsers.expat.ExpatError,
)

_SOCKET_TIMEOUT = 120


class _TimeoutTransport(xmlrpc.client.SafeTransport):
    """SafeTransport subclass that sets a socket timeout on every connection."""

    def make_connection(self, host: str) -> http.client.HTTPSConnection:
        conn = super().make_connection(host)
        conn.timeout = _SOCKET_TIMEOUT
        return conn


class _HTTPTimeoutTransport(xmlrpc.client.Transport):
    """Transport subclass that sets a socket timeout on every connection."""

    def make_connection(self, host: str) -> http.client.HTTPConnection:
        conn = super().make_connection(host)
        conn.timeout = _SOCKET_TIMEOUT
        return conn


_MAX_RETRIES = 4
_BACKOFF_BASE = 5.0

_KOJI_ERRORS = (xmlrpc.client.Fault,) + _TRANSIENT_ERRORS


class KojiClient:
    """Thin wrapper around Koji hub XML-RPC.

    ``xmlrpc.client.ServerProxy`` reuses a single HTTP connection and is not
    thread-safe.  Each thread gets its own ``ServerProxy`` via ``threading.local``
    so concurrent workers never share a connection.
    """

    def __init__(self, hub_url: str) -> None:
        self.hub_url = hub_url.rstrip("/")
        self._local = threading.local()

    def _reset_proxy(self) -> None:
        """Drop the cached proxy so the next access creates a fresh connection."""
        self._local.proxy = None

    @property
    def _proxy(self) -> xmlrpc.client.ServerProxy:
        """Per-thread ServerProxy — created on first access in each thread."""
        proxy = getattr(self._local, "proxy", None)
        if proxy is None:
            secure = urllib.parse.urlsplit(self.hub_url).scheme != "http"
            transport = _TimeoutTransport() if secure else _HTTPTimeoutTransport()
            self._local.proxy = xmlrpc.client.ServerProxy(
                self.hub_url,
                transport=transport,
                allow_none=True,
                headers=(("User-Agent", "koji-sbom/1.0"), ("Accept", "*/*")),
            )
        return self._local.proxy

    def _call_with_retry(self, label: str, method_name: str, *args: Any, **kwargs: Any) -> Any:
        """Invoke XML-RPC *method_name* with exponential-backoff retry on transient errors."""
        for attempt in range(_MAX_RETRIES + 1):
            try:
                fn = getattr(self._proxy, method_name)
                return fn(*args, **kwargs)
            except _TRANSIENT_ERRORS as exc:
                if attempt == _MAX_RETRIES:
                    raise
                wait = _BACKOFF_BASE * (2**attempt)
                log.warning(
                    "%s: transient error (attempt %d/%d), retrying in %.0fs: %s",
                    label,
                    attempt + 1,
                    _MAX_RETRIES + 1,
                    wait,
                    exc,
                )
                self._reset_proxy()
                time.sleep(wait)
        raise RuntimeError("unreachable")  # pragma: no cover

    def list_tagged(
        self,
        brew_tag: str,
        *,
        latest: bool = True,
        inherit: bool = True,
        package: str | None = None,
    ) -> list[dict[str, Any]]:
        """
        ``listTagged(tag, {latest, inherit, package?})`` → build dicts with ``build_type`` = ``"rpm"``.

        Mirrors Deptopia ``getLatestBuildsTypes`` / ``GetLatestBuildsForTags``.
        ``latest=True`` gives one build per package name (same as Deptopia's default
        for errata streams); ``latest=False`` returns all historical builds in the tag.
        When *package* is set, only that package's builds are returned.
        """
        params: dict[str, Any] = {
            "latest": latest,
            "inherit": inherit,
            "__starstar": True,
        }
        if package is not None:
            params["package"] = package
        try:
            rows = self._call_with_retry(f"listTagged({brew_tag})", "listTagged", brew_tag, params)
        except _KOJI_ERRORS as e:
            log.warning("listTagged(%s) failed: %s", brew_tag, e)
            return []
        if not isinstance(rows, list):
            return []
        out: list[dict[str, Any]] = []
        for r in rows:
            if isinstance(r, dict) and r.get("build_id"):
                r.setdefault("build_type", "rpm")
                out.append(r)
        return out

    def get_build(self, nvr: str | int) -> dict[str, Any] | None:
        """Single ``getBuild`` (NVR string or integer build id)."""
        try:
            row = self._call_with_retry(f"getBuild({nvr})", "getBuild", nvr)
        except _KOJI_ERRORS:
            return None
        if isinstance(row, dict) and row.get("build_id"):
            return row
        return None

    def multicall_get_build(
        self, nvrs: list[str], *, chunk: int = 500
    ) -> list[dict[str, Any] | None]:
        """``getBuild`` per NVR via ``multiCall``; sequential fallback if batch mismatches."""
        out: list[dict[str, Any] | None] = []
        for i in range(0, len(nvrs), chunk):
            chunk_nvrs = nvrs[i : i + chunk]
            calls = [{"methodName": "getBuild", "params": [n]} for n in chunk_nvrs]
            try:
                raw = self._call_with_retry(
                    f"multiCall(getBuild, {len(chunk_nvrs)} NVRs)",
                    "multiCall",
                    calls,
                )
            except _KOJI_ERRORS:
                raw = None
            if not isinstance(raw, list) or len(raw) != len(chunk_nvrs):
                for n in chunk_nvrs:
                    out.append(self.get_build(n))
                continue
            for slot in raw:
                row: dict[str, Any] | None = None
                if isinstance(slot, dict) and "faultCode" in slot:
                    row = None
                elif isinstance(slot, list) and slot:
                    first = slot[0]
                    if isinstance(first, dict) and "faultCode" in first:
                        row = None
                    elif isinstance(first, dict) and first.get("build_id"):
                        row = first
                elif isinstance(slot, dict) and slot.get("build_id"):
                    row = slot
                out.append(row)
        return out

    def multicall_get_build_by_id(
        self, build_ids: list[int], *, chunk: int = 500
    ) -> dict[int, dict[str, Any]]:
        """``getBuild`` per integer build id; returns ``{build_id: build_dict}``."""
        unique = sorted(set(build_ids))
        out: dict[int, dict[str, Any]] = {}
        for i in range(0, len(unique), chunk):
            batch = unique[i : i + chunk]
            calls = [{"methodName": "getBuild", "params": [bid]} for bid in batch]
            try:
                raw = self._call_with_retry(
                    f"multiCall(getBuild, {len(batch)} ids)",
                    "multiCall",
                    calls,
                )
            except _KOJI_ERRORS:
                raw = None
            if not isinstance(raw, list) or len(raw) != len(batch):
                for bid in batch:
                    b = self.get_build(bid)
                    if b:
                        out[bid] = b
                continue
            for bid, slot in zip(batch, raw):
                row: dict[str, Any] | None = None
                if isinstance(slot, dict) and "faultCode" in slot:
                    row = None
                elif isinstance(slot, list) and slot:
                    first = slot[0]
                    if isinstance(first, dict) and "faultCode" in first:
                        row = None
                    elif isinstance(first, dict) and first.get("build_id"):
                        row = first
                elif isinstance(slot, dict) and slot.get("build_id"):
                    row = slot
                if row:
                    out[bid] = row
        return out

    def get_rpm(self, filename: str) -> dict[str, Any] | None:
        """``getRPM(filename)`` (e.g. ``foo-1.el8.src.rpm``)."""
        try:
            row = self._call_with_retry(f"getRPM({filename})", "getRPM", filename)
        except _KOJI_ERRORS:
            return None
        if isinstance(row, dict) and row.get("id"):
            return row
        return None

    def multicall_get_rpm(
        self, filenames: list[str], *, chunk: int = 500
    ) -> list[dict[str, Any] | None]:
        """``getRPM`` per filename via ``multiCall``; sequential fallback on mismatch."""
        out: list[dict[str, Any] | None] = []
        for i in range(0, len(filenames), chunk):
            chunk_fns = filenames[i : i + chunk]
            calls = [{"methodName": "getRPM", "params": [fn]} for fn in chunk_fns]
            try:
                raw = self._call_with_retry(
                    f"multiCall(getRPM, {len(chunk_fns)} files)",
                    "multiCall",
                    calls,
                )
            except _KOJI_ERRORS:
                raw = None
            if not isinstance(raw, list) or len(raw) != len(chunk_fns):
                for fn in chunk_fns:
                    out.append(self.get_rpm(fn))
                continue
            for slot in raw:
                row: dict[str, Any] | None = None
                if isinstance(slot, dict) and "faultCode" in slot:
                    row = None
                elif isinstance(slot, list) and slot:
                    first = slot[0]
                    if isinstance(first, dict) and "faultCode" in first:
                        row = None
                    elif isinstance(first, dict) and first.get("id"):
                        row = first
                elif isinstance(slot, dict) and slot.get("id"):
                    row = slot
                out.append(row)
        return out

    def get_build_from_rpm_filename(self, filename: str) -> dict[str, Any] | None:
        """``getRPM`` then ``getBuild`` (Deptopia ``getBuildFromRPMFilenameWithClient``)."""
        rpm = self.get_rpm(filename)
        if not rpm:
            return None
        bid = rpm.get("build_id")
        if isinstance(bid, int):
            try:
                b = self._call_with_retry(f"getBuild({bid})", "getBuild", bid)
            except _KOJI_ERRORS:
                return None
            if isinstance(b, dict) and b.get("build_id"):
                return b
        return None

    def list_rpms(self, build_id: int) -> list[dict[str, Any]]:
        """``listRPMs(buildID)`` → list of RPM dicts (includes ``id``, ``arch``, ``nvr``, …)."""
        try:
            rows = self._call_with_retry(f"listRPMs({build_id})", "listRPMs", build_id)
        except _KOJI_ERRORS as e:
            log.warning("listRPMs(%s): %s", build_id, e)
            raise
        if not isinstance(rows, list):
            raise LookupError(f"listRPMs({build_id}) returned unexpected type: {type(rows)!r}")
        return [r for r in rows if isinstance(r, dict)]

    def list_archives(
        self,
        build_id: int,
        *,
        type: str | None = None,
    ) -> list[dict[str, Any]]:
        """``listArchives(buildID[, type=…])`` → archive dicts (filename, btype, type_name, …)."""
        try:
            if type is not None:
                # Koji hub expects buildID positionally; type as named kw via __starstar.
                rows = self._call_with_retry(
                    f"listArchives({build_id}, type={type})",
                    "listArchives",
                    build_id,
                    {"type": type, "__starstar": True},
                )
            else:
                rows = self._call_with_retry(
                    f"listArchives({build_id})",
                    "listArchives",
                    build_id,
                )
        except _KOJI_ERRORS as e:
            log.warning("listArchives(%s): %s", build_id, e)
            return []
        if not isinstance(rows, list):
            return []
        return [r for r in rows if isinstance(r, dict)]

    def get_rpm_deps(self, rpm_id: int) -> list[dict[str, Any]]:
        try:
            rows = self._call_with_retry(f"getRPMDeps({rpm_id})", "getRPMDeps", rpm_id)
        except _KOJI_ERRORS:
            return []
        if not isinstance(rows, list):
            return []
        return [r for r in rows if isinstance(r, dict)]

    def list_tagged_all_nvrs(
        self,
        brew_tag: str,
        *,
        inherit: bool = True,
        build_type: str = "rpm",
    ) -> set[str]:
        """
        ``listTagged(tag, latest=False, inherit=True)`` → set of all NVRs in the tag
        lineage (across all historical builds, not just latest).

        Used by the Pulp-based errata stream filter: mirrors Deptopia
        ``GetLatestBuildsForTags`` (which calls listTagged with ``latest=false``).
        The type parameter restricts to RPM builds by default.
        """
        params: dict[str, Any] = {
            "latest": False,
            "inherit": inherit,
            "__starstar": True,
        }
        if build_type:
            params["type"] = build_type
        try:
            rows = self._call_with_retry(
                f"listTagged({brew_tag}, latest=False)",
                "listTagged",
                brew_tag,
                params,
            )
        except _KOJI_ERRORS as e:
            log.warning("listTagged(%s, latest=False) failed: %s", brew_tag, e)
            return set()
        if not isinstance(rows, list):
            return set()
        nvrs: set[str] = set()
        for r in rows:
            if isinstance(r, dict):
                nvr = r.get("nvr")
                if isinstance(nvr, str) and nvr:
                    nvrs.add(nvr)
        return nvrs

    def get_module_build_kojitag(self, module_build: dict[str, Any]) -> str | None:
        """
        Extract the flat Koji tag from a module build's ``extra`` dict.

        ``listTagged`` does NOT include the ``extra`` field — callers must first
        enrich the build via ``getBuild`` (see :meth:`expand_module_brew_tags`).

        Mirrors ``mb.Extra.TypeInfo.Module.KojiTag`` in Deptopia
        (XML-RPC field ``content_koji_tag``).
        """
        extra = module_build.get("extra") or {}
        if isinstance(extra, str):
            import json as _json

            try:
                extra = _json.loads(extra)
            except Exception:
                return None
        typeinfo = extra.get("typeinfo") or {}
        module_info = typeinfo.get("module") or {}
        # Brew stores the flat content tag as "content_koji_tag" in the XML-RPC
        # response; older builds may use "kojitag" or "koji_tag".
        tag = (
            module_info.get("content_koji_tag")
            or module_info.get("kojitag")
            or module_info.get("koji_tag")
        )
        return str(tag) if tag else None

    def expand_module_brew_tags(self, brew_tags: list[str]) -> list[str]:
        """
        Expand Brew tags: ``-modules-`` tags are replaced by the flat Koji tags
        of each module build inside them; all other tags are kept as-is.

        Mirrors Deptopia ``getAllBrewTags`` / ``getAllBrewTagsWorker``.

        ``listTagged`` returns only basic build info (no ``extra``), so we enrich
        module builds via a ``multiCall(getBuild, ...)`` before extracting the
        ``content_koji_tag`` — exactly as Deptopia's ``GetLatestDetailedBuildsType``
        (``listTagged`` + ``getDetailsWithSingleClient``) does.
        """
        expanded: list[str] = []
        seen: set[str] = set()

        for tag in brew_tags:
            if "-modules-" in tag:
                # Step 1: list all module builds in the tag (basic info only)
                basic_builds = self.list_tagged(tag, latest=False, inherit=True)
                if not basic_builds:
                    if tag not in seen:
                        seen.add(tag)
                        expanded.append(tag)
                    continue

                # Step 2: enrich with getBuild (populates extra.typeinfo.module)
                nvrs = [b["nvr"] for b in basic_builds if b.get("nvr")]
                detailed = self.multicall_get_build(nvrs)

                flat_tags: list[str] = []
                for detail in detailed:
                    if detail is None:
                        continue
                    kt = self.get_module_build_kojitag(detail)
                    if kt and kt not in seen:
                        seen.add(kt)
                        flat_tags.append(kt)

                if flat_tags:
                    expanded.extend(flat_tags)
                    log.info("expand_module_brew_tags: %s → %d flat tags", tag, len(flat_tags))
                else:
                    # Fallback: include the tag itself if enrichment yielded nothing
                    log.warning(
                        "expand_module_brew_tags: no flat tags from %s (%d module builds); "
                        "including tag as-is",
                        tag,
                        len(basic_builds),
                    )
                    if tag not in seen:
                        seen.add(tag)
                        expanded.append(tag)
            else:
                if tag not in seen:
                    seen.add(tag)
                    expanded.append(tag)

        return expanded

    def get_allowed_nvrs_for_tags(
        self,
        brew_tags: list[str],
        *,
        expand_module_tags: bool = True,
    ) -> set[str]:
        """
        Build the set of all NVRs present in any of the Brew tags (with
        ``latest=False, inherit=True``).

        When ``expand_module_tags=True`` (default) the ``-modules-`` tags are
        first expanded to their constituent flat Koji tags, mirroring Deptopia
        ``getAllBrewTags`` + ``GetLatestBuildsForTags``.
        """
        flat_tags = (
            self.expand_module_brew_tags(brew_tags) if expand_module_tags else list(brew_tags)
        )
        log.info("get_allowed_nvrs_for_tags: %d flat tags", len(flat_tags))

        all_nvrs: set[str] = set()
        for tag in flat_tags:
            nvrs = self.list_tagged_all_nvrs(tag, inherit=True)
            log.debug("  tag=%s → %d NVRs", tag, len(nvrs))
            all_nvrs |= nvrs

        log.info("get_allowed_nvrs_for_tags: %d unique NVRs total", len(all_nvrs))
        return all_nvrs

    def multicall_list_rpms(
        self, build_ids: Iterable[int], *, chunk: int = 500
    ) -> dict[int, list[dict[str, Any]]]:
        """``listRPMs`` per build id via ``multiCall``; sequential fallback on mismatch."""
        ids = list(build_ids)
        if not ids:
            return {}
        result: dict[int, list[dict[str, Any]]] = {}
        for i in range(0, len(ids), chunk):
            batch_ids = ids[i : i + chunk]
            calls = [{"methodName": "listRPMs", "params": [bid]} for bid in batch_ids]
            try:
                raw = self._call_with_retry(
                    f"multiCall(listRPMs, {len(batch_ids)})",
                    "multiCall",
                    calls,
                )
            except _KOJI_ERRORS:
                raw = None
            if not isinstance(raw, list) or len(raw) != len(batch_ids):
                for bid in batch_ids:
                    result[bid] = self.list_rpms(bid)
                continue
            for bid, slot in zip(batch_ids, raw):
                rpms: list[dict[str, Any]] = []
                if isinstance(slot, list):
                    for item in slot:
                        if isinstance(item, dict) and item.get("id"):
                            rpms.append(item)
                        elif isinstance(item, list):
                            rpms.extend(r for r in item if isinstance(r, dict) and r.get("id"))
                elif isinstance(slot, dict) and slot.get("id"):
                    rpms.append(slot)
                result[bid] = rpms
        return result

    def get_rpm_deps_multicall(self, rpm_ids: Iterable[int]) -> list[list[dict[str, Any]]]:
        """``getRPMDeps`` per RPM id; multicall with sequential fallback."""
        ids = list(rpm_ids)
        if not ids:
            return []
        calls = [{"methodName": "getRPMDeps", "params": [rid]} for rid in ids]
        try:
            raw = self._call_with_retry(
                f"multiCall(getRPMDeps, {len(ids)} ids)",
                "multiCall",
                calls,
            )
        except _KOJI_ERRORS:
            return [self.get_rpm_deps(rid) for rid in ids]
        if not isinstance(raw, list) or len(raw) != len(ids):
            return [self.get_rpm_deps(rid) for rid in ids]
        result: list[list[dict[str, Any]]] = []
        for slot in raw:
            chunk: list[dict[str, Any]] = []
            if isinstance(slot, list):
                for item in slot:
                    if isinstance(item, dict):
                        chunk.append(item)
                    elif isinstance(item, list):
                        chunk.extend(x for x in item if isinstance(x, dict))
            result.append(chunk)
        return result
