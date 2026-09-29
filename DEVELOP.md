# Development

## Version bump

The package version is `[project].version` in `pyproject.toml`. SPDX documents
record it as `Tool: koji-sbom-<version>` (`importlib.metadata.version` in
`koji_sbom/assembly.py`). Releases are lightweight git tags named `v` plus
that version, pointing at the bump commit on `main`. The README install line
pins the same tag.

Bump the patch number for fixes and the minor number for features
(`0.1.1` → `0.1.2`).

1. Set the new version in all three places:

   - `pyproject.toml`: `version = "0.1.2"`
   - `README.md` install command: `@v0.1.2`
   - `tests/test_koji_sbom_generate.py`: `Tool: koji-sbom-0.1.2`

2. Reinstall the editable package so the SPDX creator string matches, then
   run the tests:

   ```bash
   python -m venv --system-site-packages .venv   # so ``import rpm`` works
   source .venv/bin/activate
   pip install -e ".[dev]"
   pytest tests/ -v --tb=short
   ```

3. Commit those version edits:

   ```bash
   git commit -m "chore: update to v0.1.2"
   ```

4. After that commit is on `main`, tag it and push the tag. Do not tag a
   feature branch.

   ```bash
   git tag v0.1.2
   git push origin v0.1.2
   ```

`pip install git+https://github.com/RedHatProductSecurity/koji-sbom@v0.1.2`
resolves only after the tag exists on the remote.
