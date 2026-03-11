"""Errata Tool API client - fetch shipped errata and builds.

Uses GSSAPI (Kerberos) authentication like component-registry.
"""
import logging
from typing import Any

import requests
from django.conf import settings
from requests_gssapi import HTTPSPNEGOAuth

logger = logging.getLogger(__name__)

SHIPPED_LIVE_SEARCH = "show_state_SHIPPED_LIVE=1"


class ErrataTool:
    """Interface to the Errata Tool APIs, matching component-registry's approach."""

    GSSAPI_AUTH = HTTPSPNEGOAuth()

    def __init__(self):
        self.session = requests.Session()
        self.session.auth = self.GSSAPI_AUTH
        self._product_id_cache: dict[str, int] = {}

    def get(self, path: str, **request_kwargs: Any) -> dict[str, Any]:
        """Get the response to a REST API call or raise an exception."""
        url = f"{settings.ERRATA_TOOL_URL.rstrip('/')}/{path}"
        response = self.session.get(url, **request_kwargs)
        response.raise_for_status()
        return response.json()

    def get_paged(
        self, path: str, page_data_attr: str = "data", pager: str = "page[number]"
    ) -> list[dict[str, Any]]:
        """Iterate over data from paged Errata Tool API endpoint."""
        params = {pager: 1}
        data: list[dict[str, Any]] = []
        while True:
            page = self.get(path, params=params)
            page_data = page.get(page_data_attr, [])
            if page_data:
                data.extend(page_data)
                params[pager] = params.get(pager, 1) + 1
            else:
                break
        return data

    def _resolve_product_id(self, product_name: str) -> int | None:
        """Resolve product name to Errata Tool product ID."""
        if product_name in self._product_id_cache:
            return self._product_id_cache[product_name]
        products = self.get_paged("api/v1/products")
        for product in products:
            attrs = product.get("attributes", {})
            if attrs.get("name") == product_name or attrs.get("short_name") == product_name:
                pid = product.get("id")
                if pid is not None:
                    self._product_id_cache[product_name] = pid
                    return pid
        return None

    def get_shipped_errata_for_product(
        self,
        product_name: str,
        product_version: str | None = None,
        variants: list[str] | None = None,
    ) -> list[int]:
        """
        Query Errata Tool for shipped errata matching product (and optionally variants).
        Returns list of erratum IDs.
        """
        product_id = self._resolve_product_id(product_name)
        if product_id is None:
            logger.warning("Could not resolve product %s to Errata Tool product ID", product_name)
            return []
        search_values = f"{SHIPPED_LIVE_SEARCH}&product[]={product_id}"
        return self._do_errata_search(search_values, variants or [])

    def _do_errata_search(
        self, search_values: str, product_variants: list[str]
    ) -> list[int]:
        """Execute errata search, optionally filtering by variant."""
        if not search_values:
            return []
        product_errata = self.get_paged(f"api/v1/erratum/search?{search_values}")
        all_errata: set[int] = set()
        for erratum in product_errata:
            if not product_variants:
                all_errata.add(erratum["id"])
                continue
            is_rpm = "rpm" in erratum.get("content_types", [])
            endpoint = "builds_list.json" if is_rpm else "builds"
            try:
                builds = self.get(f"api/v1/erratum/{erratum['id']}/{endpoint}")
            except Exception:
                continue
            for product_version in builds.values() if isinstance(builds, dict) else []:
                for build in product_version.get("builds", []):
                    for build_data in (build.values() if isinstance(build, dict) else []):
                        for variant in build_data.get("variant_arch", {}).keys():
                            if variant in product_variants:
                                all_errata.add(erratum["id"])
                                break
        return list(all_errata)

    def get_builds_for_erratum(self, erratum_id: int) -> list[dict[str, Any]]:
        """
        Fetch RPM build list for an erratum.
        Returns list of build dicts with build_id, nvr (skips modules and containers).
        """
        try:
            data = self.get(f"api/v1/erratum/{erratum_id}/builds_list.json")
        except Exception as e:
            logger.exception("Errata builds_list failed for %s: %s", erratum_id, e)
            return []
        builds: list[dict[str, Any]] = []
        seen: set[tuple[int, str]] = set()
        for product_version in data.values() if isinstance(data, dict) else []:
            for build in product_version.get("builds", []):
                if not isinstance(build, dict):
                    continue
                for build_nvr, build_data in build.items():
                    if not isinstance(build_data, dict):
                        continue
                    if build_data.get("is_module"):
                        continue
                    variant_arch = build_data.get("variant_arch", {})
                    if self._is_container_only(variant_arch):
                        continue
                    bid = build_data.get("id")
                    nvr = build_data.get("nvr") or build_nvr
                    if bid is not None and nvr and (bid, nvr) not in seen:
                        seen.add((bid, nvr))
                        builds.append({"build_id": bid, "nvr": nvr})
        return builds

    @staticmethod
    def _is_container_only(variant_arch: dict) -> bool:
        """True if build only has container (multi) content, no RPMs."""
        rpm_arches = {"SRPMS", "noarch", "x86_64", "aarch64", "ppc64le", "s390x", "i686"}
        for arches in variant_arch.values():
            if not isinstance(arches, dict):
                continue
            for arch, files in arches.items():
                if arch in rpm_arches and files:
                    return False
        return True


def _get_client() -> ErrataTool | None:
    """Return configured ErrataTool client or None if not configured."""
    url = getattr(settings, "ERRATA_TOOL_URL", "") or None
    if not url:
        return None
    return ErrataTool()


def get_shipped_errata_for_product(
    product_name: str, product_version: str, variants: list[str]
) -> list[int]:
    """
    Query Errata Tool for shipped errata matching product/version/variants.
    Returns list of erratum IDs.
    """
    client = _get_client()
    if not client:
        logger.warning("ERRATA_TOOL_URL not configured")
        return []
    return client.get_shipped_errata_for_product(product_name, product_version, variants)


def get_builds_for_erratum(erratum_id: int) -> list[dict[str, Any]]:
    """
    Fetch RPM build list for an erratum.
    Returns list of build dicts with build_id, nvr.
    """
    client = _get_client()
    if not client:
        return []
    return client.get_builds_for_erratum(erratum_id)
