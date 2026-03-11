# Koji SBOM Microservice

Django microservice that fetches product definitions for RHEL 6/7/8 active streams, scrapes errata and YUM data into a local database, and exposes an API with status, streams, and on-demand SBOM generation.

## Features

- **Active streams**: rhel-8.2.0.z, rhel-8.4.0.z, rhel-8.6.0.z, rhel-8.8.0.z, rhel-8.10.z, rhel-7-els, rhel-6-els
- **Data sources**: errata_info and yum_repositories from product-definitions
- **Koji listRPMs**: Fetches SRPM + all binary RPMs per build
- **SPDX 2.3 SBOM**: Per security-data-guidelines (SRPM + binary RPMs, GENERATED_FROM relationships)

## Setup

```bash
python -m venv .venv
source .venv/bin/activate  # or .venv\Scripts\activate on Windows
pip install -r requirements.txt
cp .env.example .env
# Edit .env with your configuration
python manage.py migrate
```

## Environment Variables

| Variable | Description |
|----------|-------------|
| `PRODUCT_DEFINITIONS_URL` | URL to products.json (default: prodsec.pages.redhat.com) |
| `ERRATA_TOOL_URL` | Errata Tool API base URL (GSSAPI/Kerberos auth) |
| `KOJI_URL` | Koji/Brew hub URL |
| `KOJI_AUTH_TOKEN` | Optional; for authenticated Koji access |
| `YUM_REPO_BASE_URL` | Override for internal URLs (e.g. cdn.redhat.com) |
| `DATABASE_URL` | SQLite or PostgreSQL connection string |

Secrets and `.env` are gitignored. Do not commit credentials.

## Management Commands

### scrape_errata

Fetches shipped errata for streams with errata_info, then builds and RPMs from Koji.

```bash
python manage.py scrape_errata
```

### scrape_yum

Fetches repodata from yum_repositories, parses primary.xml, and optionally enriches with Koji listRPMs.

```bash
python manage.py scrape_yum
```

## Daily Schedule

Run scrapers on a schedule (cron, systemd timer, or celery-beat):

```bash
# Example crontab (daily at 2am)
0 2 * * * cd /path/to/koji-sbom && .venv/bin/python manage.py scrape_errata
0 3 * * * cd /path/to/koji-sbom && .venv/bin/python manage.py scrape_yum
```

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/v1/status` | Health, DB connectivity, last scrape times |
| GET | `/api/v1/streams` | List active streams with build counts |
| GET | `/api/v1/sbom/{stream}` | Generate SPDX 2.3 JSON SBOM for stream |

## Run Server

```bash
python manage.py runserver 0.0.0.0:8000
# or with gunicorn:
gunicorn config.wsgi:application -b 0.0.0.0:8000
```

## SBOM Format

Follows [security-data-guidelines](https://github.com/RedHatProductSecurity/security-data-guidelines):

- SRPM as separate package with `arch=src` in purl
- Binary RPMs with `GENERATED_FROM` relationship to SRPM
- PURL format: `pkg:rpm/redhat/{name}@{version}-{release}?arch={arch}`
