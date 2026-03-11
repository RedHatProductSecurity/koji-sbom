"""Scrape YUM repos for active streams - fetch RPM metadata from repodata."""
import logging
from datetime import datetime, timezone

from django.core.management.base import BaseCommand

from sbom.models import Build, Package, ScrapeRun, Stream, StreamBuild
from sbom.services.koji_client import get_list_rpms
from sbom.services.product_definitions import fetch_product_definitions, get_active_streams, sync_streams_to_db
from sbom.services.yum_scraper import (
    fetch_primary_db,
    fetch_primary_xml,
    fetch_repomd,
    parse_primary_rpms,
)

logger = logging.getLogger(__name__)


class Command(BaseCommand):
    help = "Scrape YUM repos for active RHEL streams"

    def handle(self, *args, **options):
        data = fetch_product_definitions()
        streams = get_active_streams(data)
        sync_streams_to_db(streams)

        for s in streams:
            if not s["yum_repositories"]:
                continue
            stream = Stream.objects.get(tag=s["tag"])
            for repo_url in s["yum_repositories"]:
                self._scrape_repo(stream, repo_url)

        ScrapeRun.objects.update_or_create(
            command="scrape_yum",
            defaults={"last_run": datetime.now(timezone.utc), "last_success": True},
        )
        self.stdout.write(self.style.SUCCESS("scrape_yum complete"))

    def _scrape_repo(self, stream: Stream, repo_url: str):
        try:
            repomd = fetch_repomd(repo_url)
            primary_url = repomd.get("primary") or repomd.get("primary_db")
            if not primary_url:
                return
            if "primary" in repomd:
                xml_bytes = fetch_primary_xml(primary_url)
                rpms = parse_primary_rpms(xml_bytes)
            else:
                rpms = fetch_primary_db(primary_url)
        except Exception as e:
            logger.exception("Failed to fetch %s: %s", repo_url, e)
            return

        seen_nvr = set()
        for r in rpms:
            nvr_key = (r["name"], r["version"], r["release"])
            if nvr_key in seen_nvr:
                continue
            seen_nvr.add(nvr_key)
            build = self._get_or_create_build_from_rpm(r)
            if build:
                StreamBuild.objects.get_or_create(stream=stream, build=build, defaults={"latest": True})
                self._maybe_populate_from_koji(build, r)

    def _get_or_create_build_from_rpm(self, r: dict) -> Build:
        nvr = f"{r['name']}-{r['version']}-{r['release']}"
        build, created = Build.objects.get_or_create(
            nvr=nvr,
            defaults={
                "build_id": None,
                "pkg_name": r["name"],
                "version": r["version"],
                "release": r["release"],
                "build_type": "rpm",
            },
        )
        return build

    def _maybe_populate_from_koji(self, build: Build, r: dict):
        if build.build_id:
            return
        try:
            import koji
            from django.conf import settings
            url = getattr(settings, "KOJI_URL", None)
            if not url:
                self._store_primary_rpm(build, r)
                return
            session = koji.ClientSession(url)
            koji_build = session.getBuild(build.nvr)
            if koji_build:
                build.build_id = koji_build["id"]
                build.save()
                rpms = get_list_rpms(build.build_id)
                for rpm in rpms:
                    Package.objects.update_or_create(
                        build=build,
                        nvr=rpm.get("nvr", ""),
                        arch=rpm.get("arch", "noarch"),
                        defaults={
                            "name": rpm.get("name", ""),
                            "version": rpm.get("version", ""),
                            "release": rpm.get("release", ""),
                            "rpm_id": rpm.get("id"),
                            "payload_hash": rpm.get("payloadhash", "") or "",
                        },
                    )
            else:
                self._store_primary_rpm(build, r)
        except Exception:
            self._store_primary_rpm(build, r)

    def _store_primary_rpm(self, build: Build, r: dict):
        Package.objects.update_or_create(
            build=build,
            nvr=r["nvr"],
            arch=r["arch"],
            defaults={
                "name": r["name"],
                "version": r["version"],
                "release": r["release"],
                "rpm_id": None,
                "payload_hash": "",
            },
        )
