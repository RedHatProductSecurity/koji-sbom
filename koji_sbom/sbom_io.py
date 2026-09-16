"""Read SPDX/CycloneDX SBOM metadata from on-disk documents."""

from __future__ import annotations

import json
from pathlib import Path


def sbom_document_nvr(sbom_path: Path) -> str | None:
    """Return the document NVR from an SPDX/CycloneDX SBOM, if present."""
    try:
        with open(sbom_path, encoding="utf-8") as fh:
            doc = json.load(fh)
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(doc, dict):
        return None
    name = doc.get("name")
    if isinstance(name, str) and name:
        return name
    meta = doc.get("metadata")
    if isinstance(meta, dict):
        component = meta.get("component")
        if isinstance(component, dict):
            cname = component.get("name")
            if isinstance(cname, str) and cname:
                cversion = component.get("version")
                if isinstance(cversion, str) and cversion:
                    return f"{cname}-{cversion}"
                return cname
    return None
