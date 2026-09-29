# koji-sbom

Python library for metadata-only RPM SPDX SBOM generation from Koji hub builds.
No SRPM download, no Syft, no database. Bodhi NVR comparison requires the system
``python3-rpm`` package (`import rpm`).


## Install

```bash
# Fedora / RHEL: python3-rpm provides ``import rpm``
sudo dnf install python3-rpm
pip install git+https://github.com/RedHatProductSecurity/koji-sbom@v0.1.2
```

For development:

```bash
python -m venv --system-site-packages .venv   # so ``import rpm`` works
source .venv/bin/activate
pip install -e ".[dev]"
```

## CLI

Generate an SPDX 2.3 SBOM for one build and print it to stdout:

```bash
koji-sbom openssl-4.0.2-1.fc46 > openssl-rpm-sbom.json
```

Fedora Koji defaults when `--namespace fedora` and no hub URL is configured:

```bash
koji-sbom --namespace fedora bash-5.3.15-2.fc45
```

For EPEL NVRs (``.elN``), the CLI compares the given NVR with Bodhi
`pending`/`testing` RPM updates for the same package and EPEL major. When a
newer Bodhi build exists, it prints a warning to stderr but still generates the
SBOM for the **requested** NVR. Pass `--no-bodhi` to skip the check, or pass the
Bodhi NVR explicitly to generate for that build.

``--package`` looks up the latest NVR on ``fedora-all`` (Koji ``rawhide``)
and every current ``epel-N`` major (newest Koji ``dist_tag`` for that major,
then Bodhi pending/testing via `resolve_newer_epel_nvrs`) and **prints those
NVRs** — it does not generate an SBOM. ``--nvr`` (or a positional NVR) generates
SPDX for that build only. ``--build-id`` does the same for a Koji build id.

```bash
# Print latest NVRs (no SBOM):
koji-sbom --package libheif
# → fedora-all: libheif-1.23.5-4.fc46
# → epel-8: …
# → epel-9: …
# → epel-10: libheif-1.23.5-4.el10_4
# Warns if Bodhi has newer, still writes SBOM for the given NVR:
koji-sbom --nvr libheif-1.20.2-6.el10_4
# Exact NVR, no Bodhi check:
koji-sbom --nvr --no-bodhi libheif-1.20.2-6.el10_4
```

Bodhi pending/testing queries include **all current EPEL releases** discovered
from Bodhi `/releases` (every major, and every still-current minor such as
EPEL-10.2/10.3/10.4). ``--package`` `epel-N` lookup uses the newest current
minor's `dist_tag` for that major (e.g. `epel10.4`). If Bodhi is unavailable,
lookups fail (no static fallback).

Write to a file instead of stdout:

```bash
koji-sbom openssl-4.0.2-1.fc46 --output openssl-rpm-sbom.json
```

The same entry point is also available as `koji-sbom-generate` and via `python -m koji_sbom`.

Environment variables:

| Variable | Description |
|----------|-------------|
| `KOJI_URL` | Koji/Brew hub URL (preferred) |
| `KOJI_HUB` | Alternate hub URL variable |

## Library API

```python
from koji_sbom.generate import generate_sbom
from koji_sbom.bodhi import resolve_newer_epel_nvr, lookup_package_stream_nvrs

sbom = generate_sbom("https://koji.fedoraproject.org/kojihub", nvr="openssl-4.0.2-1.fc46")
# Exact NVR — no Bodhi lookup. To prefer a staged EPEL update:
nvr = resolve_newer_epel_nvr("libheif-1.20.2-6.el10_4")
# Bare package → latest fedora-all + epel-N NVRs (Bodhi for EPEL):
streams = lookup_package_stream_nvrs("libheif", "https://koji.fedoraproject.org/kojihub")
```

Key modules:

- `koji_sbom.generate` — SBOM generation and CLI entry point
- `koji_sbom.bodhi` — EPEL yum vs Bodhi pending/testing NVR resolution
- `koji_sbom.koji_session` — Koji XML-RPC client with retry and multicall helpers
- `koji_sbom.assembly` — SPDX 2.3 document assembly
- `koji_sbom.sbom_io` — read document NVR from on-disk SPDX/CycloneDX files
- `koji_sbom.buildmeta` — RPM build-metadata sidecar read/write (including Fedora Koji writer)

## SBOM format

Follows [Red Hat security-data-guidelines](https://github.com/RedHatProductSecurity/security-data-guidelines):

- SRPM as root package with `arch=src` in PURL
- Binary RPM subpackages with `GENERATED_FROM` relationship to SRPM
- Bundled/golang/python provides from Koji `Provides`
- PURL format: `pkg:rpm/{namespace}/{name}@{version}-{release}?arch={arch}`

## Development

Version bumps are described in [DEVELOP.md](DEVELOP.md).

```bash
ruff format koji_sbom/ tests/
ruff check --fix koji_sbom/ tests/
pytest tests/ -v --tb=short
python -m build   # local smoke only
```

## License

Apache License 2.0 — see [LICENSE](LICENSE).
