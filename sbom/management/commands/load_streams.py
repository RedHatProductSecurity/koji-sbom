"""Load stream definitions from product-definitions (no scraping)."""
from django.core.management.base import BaseCommand

from sbom.services.product_definitions import fetch_product_definitions, get_active_streams, sync_streams_to_db


class Command(BaseCommand):
    help = "Load stream definitions from product-definitions URL"

    def handle(self, *args, **options):
        data = fetch_product_definitions()
        streams = get_active_streams(data)
        sync_streams_to_db(streams)
        self.stdout.write(self.style.SUCCESS(f"Loaded {len(streams)} streams"))
