"""Scrape errata for active streams - fetch builds and RPMs from Errata + Koji."""
import logging
from datetime import datetime, timezone

from django.core.management.base import BaseCommand

from sbom.models import Build, Erratum, Package, ScrapeRun, Stream, StreamBuild
from sbom.services.errata_client import get_builds_for_erratum, get_shipped_errata_for_product
from sbom.services.koji_client import get_list_rpms
from sbom.services.product_definitions import fetch_product_definitions, get_active_streams, sync_streams_to_db

logger = logging.getLogger(__name__)


class Command(BaseCommand):
    help = "Scrape errata for active RHEL streams, fetch builds and RPMs from Koji"

    def add_arguments(self, parser):
        parser.add_argument(
            "--stream",
            dest="stream_name",
            metavar="TAG",
            help="Only scrape errata for this stream (e.g. rhel-8.10.z)",
        )

    def handle(self, *args, **options):
        stream_name = options.get("stream_name")
        verbosity = options.get("verbosity", 1)

        data = fetch_product_definitions()
        streams = get_active_streams(data)
        sync_streams_to_db(streams)

        if stream_name:
            streams = [s for s in streams if s["tag"] == stream_name]
            if not streams:
                self.stderr.write(self.style.ERROR(f"Stream '{stream_name}' not found"))
                return
            if verbosity >= 1:
                self.stdout.write(f"Scraping errata for stream: {stream_name}")

        for s in streams:
            if not s["errata_info"]:
                if verbosity >= 2:
                    self.stdout.write(f"Skipping {s['tag']}: no errata_info")
                continue
            if verbosity >= 1:
                self.stdout.write(f"Processing stream {s['tag']}...")
            stream = Stream.objects.get(tag=s["tag"])
            stream_errata_count = 0
            stream_build_count = 0
            for ei in s["errata_info"]:
                for pv in ei.get("product_versions", []):
                    errata_ids = get_shipped_errata_for_product(
                        ei.get("product_name", ""),
                        pv.get("name", ""),
                        pv.get("variants", []),
                    )
                    if verbosity >= 1:
                        self.stdout.write(
                            f"  {pv.get('name', '?')}: {len(errata_ids)} errata"
                        )
                    for eid in errata_ids:
                        builds_added = self._process_erratum(stream, str(eid))
                        stream_errata_count += 1
                        stream_build_count += builds_added
                        if verbosity >= 3:
                            self.stdout.write(f"    Erratum {eid}: {builds_added} builds")
            if verbosity >= 2:
                self.stdout.write(
                    f"  {s['tag']}: {stream_errata_count} errata, {stream_build_count} builds"
                )

        ScrapeRun.objects.update_or_create(
            command="scrape_errata",
            defaults={"last_run": datetime.now(timezone.utc), "last_success": True},
        )
        self.stdout.write(self.style.SUCCESS("scrape_errata complete"))

    def _process_erratum(self, stream: Stream, erratum_id: str) -> int:
        """Process one erratum; return number of builds added."""
        erratum, _ = Erratum.objects.get_or_create(erratum_id=erratum_id)
        builds = get_builds_for_erratum(int(erratum_id))
        count = 0
        for b in builds:
            build_id = b.get("build_id")
            nvr = b.get("nvr", "")
            if not build_id or not nvr:
                continue
            build = self._get_or_create_build(build_id, nvr)
            if build:
                StreamBuild.objects.get_or_create(stream=stream, build=build, defaults={"latest": True})
                erratum.builds.add(build)
                self._populate_packages(build, build_id)
                count += 1
        return count

    def _get_or_create_build(self, build_id: int, nvr: str) -> Build | None:
        build, created = Build.objects.get_or_create(
            build_id=build_id,
            defaults={
                "nvr": nvr,
                "pkg_name": nvr.rsplit("-", 2)[0] if "-" in nvr else nvr,
                "version": "",
                "release": "",
                "build_type": "rpm",
            },
        )
        if created and nvr.count("-") >= 2:
            parts = nvr.rsplit("-", 2)
            build.pkg_name = parts[0]
            build.version = parts[1]
            build.release = parts[2]
            build.save()
        return build

    def _populate_packages(self, build: Build, build_id: int):
        rpms = get_list_rpms(build_id)
        for r in rpms:
            Package.objects.update_or_create(
                build=build,
                nvr=r.get("nvr", ""),
                arch=r.get("arch", "noarch"),
                defaults={
                    "name": r.get("name", ""),
                    "version": r.get("version", ""),
                    "release": r.get("release", ""),
                    "rpm_id": r.get("id"),
                    "payload_hash": r.get("payloadhash", "") or "",
                },
            )
