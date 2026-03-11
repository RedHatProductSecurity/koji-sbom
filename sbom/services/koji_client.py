"""Koji listRPMs wrapper - returns SRPM + binary RPMs for a build."""
import logging
from typing import Any

from django.conf import settings

logger = logging.getLogger(__name__)


def get_list_rpms(build_id: int) -> list[dict[str, Any]]:
    """
    Call Koji listRPMs(buildID) and return list of RPM dicts.
    Each dict has: name, version, release, arch, nvr, id (rpm_id), build_id, payloadhash.
    Returns empty list on error or if Koji not configured.
    """
    url = getattr(settings, "KOJI_URL", None)
    if not url:
        logger.warning("KOJI_URL not configured, skipping listRPMs")
        return []

    try:
        import koji
    except ImportError:
        logger.warning("koji package not installed")
        return []

    try:
        session = koji.ClientSession(url)
        auth_token = getattr(settings, "KOJI_AUTH_TOKEN", None)
        if auth_token:
            try:
                session.ssl_login(cert=auth_token)
            except Exception:
                pass
        rpms = session.listRPMs(buildID=build_id)
        try:
            session.logout()
        except Exception:
            pass
        return rpms
    except Exception as e:
        logger.exception("listRPMs failed for build %s: %s", build_id, e)
        return []
