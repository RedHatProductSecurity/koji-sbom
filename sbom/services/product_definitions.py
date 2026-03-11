"""Fetch and filter product definitions for rhel-6, rhel-7, rhel-8 active streams."""
import json
import logging
import re
from urllib.request import urlopen

from django.conf import settings

from sbom.models import ErrataInfo, Stream, YumRepo

logger = logging.getLogger(__name__)

TARGET_MODULES = ["rhel-8", "rhel-7", "rhel-6"]


def fetch_product_definitions() -> dict:
    """Fetch products.json from PRODUCT_DEFINITIONS_URL."""
    url = getattr(settings, "PRODUCT_DEFINITIONS_URL", "")
    if not url:
        raise ValueError("PRODUCT_DEFINITIONS_URL not configured")
    if url.startswith("file://"):
        path = url[7:]
        with open(path) as f:
            return json.load(f)
    with urlopen(url, timeout=60) as resp:
        return json.load(resp)


def get_active_streams(data: dict) -> list[dict]:
    """
    Extract active streams from rhel-8, rhel-7, rhel-6 ps_modules.
    Returns list of stream dicts with tag, ps_module, errata_info, yum_repositories.
    """
    streams = []
    ps_modules = data.get("ps_modules", {})
    ps_update_streams = data.get("ps_update_streams", {})

    for mod_name in TARGET_MODULES:
        mod = ps_modules.get(mod_name)
        if not mod:
            continue
        active = mod.get("active_ps_update_streams", [])
        for tag in active:
            stream_def = ps_update_streams.get(tag, {})
            errata_info = stream_def.get("errata_info", [])
            yum_repos_raw = stream_def.get("yum_repositories", [])
            yum_repos = []
            for url in yum_repos_raw:
                yum_repos.append(url)
            streams.append({
                "tag": tag,
                "ps_module": mod_name,
                "name": stream_def.get("version", tag),
                "errata_info": errata_info,
                "yum_repositories": yum_repos,
            })
    return streams


def sync_streams_to_db(streams: list[dict]) -> None:
    """Create/update Stream, YumRepo, ErrataInfo from stream definitions."""
    for s in streams:
        stream, _ = Stream.objects.update_or_create(
            tag=s["tag"],
            defaults={"ps_module": s["ps_module"], "name": s["name"]},
        )
        YumRepo.objects.filter(stream=stream).delete()
        for url in s["yum_repositories"]:
            YumRepo.objects.get_or_create(stream=stream, url=url)
        ErrataInfo.objects.filter(stream=stream).delete()
        for ei in s["errata_info"]:
            for pv in ei.get("product_versions", []):
                pv_name = pv.get("name", "")
                variants = pv.get("variants", [])
                if pv_name:
                    ErrataInfo.objects.get_or_create(
                        stream=stream,
                        product_name=ei.get("product_name", ""),
                        product_version=pv_name,
                        defaults={"variants": variants},
                    )
