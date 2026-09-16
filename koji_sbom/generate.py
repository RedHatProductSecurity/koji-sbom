"""Metadata-only RPM SPDX SBOM generation from Koji hub (no SRPM download, no Syft)."""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from pathlib import Path
from typing import Any

from koji_sbom.assembly import assemble_rpm_spdx_document
from koji_sbom.bundled import (
    bundled_golang_from_provides,
    bundled_provides_to_spdx_fragments,
)
from koji_sbom.git_source import extract_git_from_brew_build
from koji_sbom.koji_rpm_deps import rpm_provides_and_requires_for_build
from koji_sbom.koji_session import KojiClient

log = logging.getLogger(__name__)

FEDORA = "fedora"
DEFAULT_FEDORA_KOJI_URL = "https://koji.fedoraproject.org/kojihub"


def koji_hub_from_env() -> str | None:
    """Return ``KOJI_HUB`` or ``KOJI_URL`` when set."""
    return os.environ.get("KOJI_HUB") or os.environ.get("KOJI_URL")


def resolve_koji_hub(koji_url: str | None = None) -> str:
    """Resolve hub URL from CLI flag, environment, then Fedora Koji."""
    return koji_url or koji_hub_from_env() or DEFAULT_FEDORA_KOJI_URL


def generate_sbom(
    koji_url: str,
    nvr: str | None = None,
    build_id: int | None = None,
    *,
    namespace: str = "redhat",
    module_nsvc: str | None = None,
    cpe_refs: list[str] | None = None,
) -> dict[str, Any]:
    """
    Build a metadata-only SPDX RPM SBOM from a Koji hub build.

    Exactly one of ``nvr`` or ``build_id`` must be provided.
    """
    if (nvr is None) == (build_id is None):
        raise ValueError("provide exactly one of nvr or build_id")

    client = KojiClient(koji_url)
    build_key = build_id if build_id is not None else nvr or ""
    build = client.get_build(build_key)
    if not build:
        raise LookupError(f"build not found: {build_key}")

    bid = int(build.get("build_id") or build.get("id") or 0)
    if not bid:
        raise LookupError(f"build has no id: {build.get('nvr')}")

    rpms = client.list_rpms(bid)

    provides, _req_rows = rpm_provides_and_requires_for_build(client, bid)

    bundled_packages: list[dict[str, Any]] = []
    bundled_rels: list[dict[str, Any]] = []
    if provides:
        bundled_deps = bundled_golang_from_provides(provides)
        if bundled_deps:
            bundled_packages, bundled_rels = bundled_provides_to_spdx_fragments(
                bundled_deps, srpm_spdx_id="SPDXRef-SRPM"
            )

    git_source = extract_git_from_brew_build(build)

    return assemble_rpm_spdx_document(
        build,
        [],
        [],
        bundled_packages,
        bundled_rels,
        rpms=rpms,
        namespace=namespace,
        git_source=git_source,
        module_nsvc=module_nsvc,
        cpe_refs=cpe_refs,
    )


def write_sbom_outputs(sbom: dict[str, Any], output_path: Path) -> None:
    """Write SPDX JSON for *sbom* to *output_path*."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as fh:
        json.dump(sbom, fh, indent=2)
        fh.write("\n")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="koji-sbom",
        description="Generate metadata-only RPM SPDX SBOM from Koji hub",
    )
    parser.add_argument(
        "nvr",
        nargs="?",
        metavar="NVR",
        help="Source NVR (SPDX JSON written to stdout unless --output is set)",
    )
    parser.add_argument(
        "--koji-url",
        default=None,
        help="Koji hub URL (default: KOJI_HUB/KOJI_URL, else Fedora Koji)",
    )
    parser.add_argument("--nvr", dest="nvr_flag", help="Source NVR (same as positional NVR)")
    parser.add_argument("--build-id", type=int, help="Koji build id (instead of NVR)")
    parser.add_argument(
        "--namespace",
        default=FEDORA,
        help="RPM PURL namespace (default: fedora)",
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="Write SPDX JSON to this path",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Print hub URL and build lookup to stderr",
    )
    args = parser.parse_args(argv)

    nvr = args.nvr or args.nvr_flag
    build_id = args.build_id
    if (nvr is None) == (build_id is None):
        parser.error("provide exactly one of NVR or --build-id")

    koji_url = resolve_koji_hub(args.koji_url)

    build_target = nvr if nvr is not None else f"build_id={build_id}"
    if args.verbose:
        print(f"koji hub: {koji_url}", file=sys.stderr)
        print(f"fetching: {build_target}", file=sys.stderr)

    sbom = generate_sbom(
        koji_url,
        nvr=nvr,
        build_id=build_id,
        namespace=args.namespace,
    )

    if args.output:
        write_sbom_outputs(sbom, args.output)
        return 0

    json.dump(sbom, sys.stdout, indent=2)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
