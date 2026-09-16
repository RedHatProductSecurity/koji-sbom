"""``python -m koji_sbom <NVR>`` — generate an SPDX SBOM to stdout."""

from koji_sbom.generate import main

if __name__ == "__main__":
    raise SystemExit(main())
