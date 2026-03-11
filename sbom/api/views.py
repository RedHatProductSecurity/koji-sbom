"""API views - status, streams, sbom."""
from django.db import connection
from django.http import JsonResponse
from django.views.decorators.http import require_GET
from django.views.decorators.csrf import csrf_exempt

from sbom.models import ScrapeRun, Stream
from sbom.services.sbom_generator import generate_sbom


@require_GET
@csrf_exempt
def status(request):
    """Health/status - DB connectivity, last scrape time."""
    db_ok = True
    try:
        connection.ensure_connection()
    except Exception:
        db_ok = False

    scrape_runs = {}
    for run in ScrapeRun.objects.all():
        scrape_runs[run.command] = {
            "last_run": run.last_run.isoformat() if run.last_run else None,
            "last_success": run.last_success,
        }

    return JsonResponse({
        "status": "ok" if db_ok else "degraded",
        "database": "connected" if db_ok else "disconnected",
        "scrape_runs": scrape_runs,
    })


@require_GET
@csrf_exempt
def streams(request):
    """List active streams with metadata."""
    streams_list = []
    for s in Stream.objects.all():
        streams_list.append({
            "tag": s.tag,
            "ps_module": s.ps_module,
            "name": s.name or s.tag,
            "build_count": s.streambuild_set.count(),
        })
    return JsonResponse({"streams": streams_list})


@require_GET
@csrf_exempt
def sbom(request, stream):
    """Generate SBOM for stream from DB (SPDX JSON)."""
    try:
        doc = generate_sbom(stream)
        if doc is None:
            return JsonResponse(
                {"error": f"Stream '{stream}' not found"},
                status=404,
            )
        return JsonResponse(doc, json_dumps_params={"indent": 2})
    except Exception as e:
        return JsonResponse(
            {"error": str(e)},
            status=500,
        )
