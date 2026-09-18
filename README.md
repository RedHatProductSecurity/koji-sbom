# koji-sbom

Stdlib-only Python library for metadata-only RPM SPDX SBOM generation from Koji hub builds. No SRPM download, no Syft, no database.


## Install

```bash
pip install git+https://github.com/RedHatProductSecurity/koji-sbom@v0.1.1
```

For development:

```bash
python -m venv .venv
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

sbom = generate_sbom("https://koji.fedoraproject.org/kojihub", nvr="openssl-4.0.2-1.fc46")
```

Key modules:

- `koji_sbom.generate` — SBOM generation and CLI entry point
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

```bash
ruff format koji_sbom/ tests/
ruff check --fix koji_sbom/ tests/
pytest tests/ -v --tb=short
python -m build   # local smoke only
```

## License

Apache License 2.0 — see [LICENSE](LICENSE).
