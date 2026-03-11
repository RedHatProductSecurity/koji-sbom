"""Parse YUM repodata (primary.xml or primary.sqlite) for RPM metadata."""
import bz2
import gzip
import logging
import os
import sqlite3
import tempfile
from urllib.request import urlopen

from defusedxml.ElementTree import fromstring

logger = logging.getLogger(__name__)

REPO_NS = "http://linux.duke.edu/metadata/repo"
RPM_NS = "http://linux.duke.edu/metadata/rpm"


def fetch_repomd(repo_base: str) -> dict:
    """Fetch repomd.xml and return dict of data locations."""
    url = f"{repo_base.rstrip('/')}/repodata/repomd.xml"
    with urlopen(url, timeout=30) as resp:
        tree = fromstring(resp.read())
    out = {}
    for elem in tree.iter():
        if "}" in elem.tag:
            _, local = elem.tag.split("}", 1)
        else:
            local = elem.tag
        if local == "data":
            dtype = elem.get("type")
            loc = None
            for c in elem:
                if "}" in c.tag:
                    _, clocal = c.tag.split("}", 1)
                else:
                    clocal = c.tag
                if clocal == "location":
                    loc = c
                    break
            if loc is not None and dtype:
                href = loc.get("href", "")
                out[dtype] = f"{repo_base.rstrip('/')}/{href}"
    return out


def fetch_primary_xml(primary_url: str) -> bytes:
    """Fetch primary.xml (may be gzipped)."""
    with urlopen(primary_url, timeout=60) as resp:
        data = resp.read()
    if primary_url.endswith(".gz"):
        return gzip.decompress(data)
    return data


def fetch_primary_db(primary_db_url: str) -> list[dict]:
    """
    Fetch primary.sqlite.bz2, decompress, and return RPM metadata dicts.
    Each has: name, version, release, arch, epoch (optional), nvr.
    """
    with urlopen(primary_db_url, timeout=120) as resp:
        data = resp.read()
    if primary_db_url.endswith(".bz2"):
        data = bz2.decompress(data)
    with tempfile.NamedTemporaryFile(suffix=".sqlite", delete=False) as f:
        try:
            f.write(data)
            f.flush()
            return parse_primary_db_rpms(f.name)
        finally:
            try:
                os.unlink(f.name)
            except OSError:
                pass


def parse_primary_db_rpms(db_path: str) -> list[dict]:
    """
    Read primary.sqlite packages table and return RPM metadata dicts.
    Same format as parse_primary_rpms: name, version, release, arch, epoch, nvr.
    """
    rpms = []
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    try:
        cur = conn.execute(
            "SELECT name, epoch, version, release, arch FROM packages"
        )
        for row in cur:
            name = row["name"]
            version = row["version"]
            release = row["release"] or ""
            arch = row["arch"] or "noarch"
            epoch = str(row["epoch"]) if row["epoch"] is not None else "0"
            if name and version:
                rpms.append({
                    "name": name,
                    "version": version,
                    "release": release,
                    "arch": arch,
                    "epoch": epoch,
                    "nvr": f"{name}-{version}-{release}",
                })
    finally:
        conn.close()
    return rpms


def parse_primary_rpms(xml_bytes: bytes) -> list[dict]:
    """
    Parse primary.xml and yield RPM metadata dicts.
    Each has: name, version, release, arch, epoch (optional).
    """
    root = fromstring(xml_bytes)
    rpms = []
    for pkg in root.iter():
        if "}" in pkg.tag:
            _, local = pkg.tag.split("}", 1)
        else:
            local = pkg.tag
        if local != "package":
            continue
        name = version = release = arch = None
        epoch_val = "0"
        for c in pkg:
            if "}" in c.tag:
                _, clocal = c.tag.split("}", 1)
            else:
                clocal = c.tag
            if clocal == "name":
                name = c.text
            elif clocal == "version":
                version = c.get("ver")
                release = c.get("rel", "")
                epoch_val = c.get("epoch", "0")
            elif clocal == "arch":
                arch = c.text
        if name and version:
            rpms.append({
                "name": name,
                "version": version,
                "release": release or "",
                "arch": arch or "noarch",
                "epoch": epoch_val,
                "nvr": f"{name}-{version}-{release or ''}",
            })
    return rpms
