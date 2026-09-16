"""Parse git source URLs from Koji/Brew build metadata."""

from __future__ import annotations

import re
from typing import Any

_GIT_URL_RE = re.compile(r"^(git\+https?://|git://|https://|http://)(.+?)(?:#(.+))?$")


def extract_git_from_brew_build(build: dict[str, Any]) -> tuple[str, str] | None:
    """
    Parse the ``source`` field of a Brew build dict into ``(url, committish)``.

    Typical values::

        git+https://pkgs.devel.redhat.com/rpms/bash#abc123def456
        git://pkgs.devel.redhat.com/rpms/bash#abc123def456
        git+https://src.fedoraproject.org/rpms/bash.git#abc123

    Returns ``None`` when ``source`` is absent or not a recognisable git URL.
    """
    source = str(build.get("source") or "")
    if not source:
        return None
    m = _GIT_URL_RE.match(source)
    if not m:
        return None
    scheme, rest, committish = m.group(1), m.group(2), m.group(3) or ""
    # Normalise git+https:// → https://
    url = scheme.lstrip("git+") + rest if scheme.startswith("git+") else scheme + rest
    return url, committish
