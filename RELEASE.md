# Release Process

GitHub is the source of truth for releases. PyPI/TestPyPI publishing happens from GitHub Actions when a version tag is pushed.

## One-Time Setup

Configure Trusted Publishing on TestPyPI and PyPI.

TestPyPI:

```text
https://test.pypi.org/manage/project/redakt/settings/publishing/
```

PyPI:

```text
https://pypi.org/manage/project/redakt/settings/publishing/
```

Use these values:

- Owner: `architjambhule66-debug`
- Repository: `redakt`
- Workflow for TestPyPI: `publish-testpypi.yml`
- Workflow for PyPI: `publish-pypi.yml`
- Environment for TestPyPI: `testpypi`
- Environment for PyPI: `pypi`

In GitHub, create environments named `testpypi` and `pypi`. For the `pypi` environment, require manual approval before deployment.

## Version Rules

The Git tag must match the version in `pyproject.toml`.

Examples:

- `version = "0.1.1rc1"` must be released with tag `v0.1.1rc1`.
- `version = "0.1.1"` must be released with tag `v0.1.1`.

The publish workflows fail before uploading if the tag and package version do not match.

## TestPyPI Release

Use release candidate tags for TestPyPI.

```bash
uv run pytest

# Update pyproject.toml first:
# version = "0.1.1rc1"

git add pyproject.toml
git commit -m "bump version to 0.1.1rc1"
git tag v0.1.1rc1
git push origin main
git push origin v0.1.1rc1
```

Install from TestPyPI:

```bash
python3 -m venv /tmp/redakt-test
source /tmp/redakt-test/bin/activate
python -m pip install --upgrade pip

pip install \
  --index-url https://test.pypi.org/simple/ \
  --extra-index-url https://pypi.org/simple/ \
  "redakt[dashboard]==0.1.1rc1"

redakt redact "Email test@example.com"
redakt dashboard
```

## PyPI Release

Use stable tags for PyPI.

```bash
uv run pytest

# Update pyproject.toml first:
# version = "0.1.1"

git add pyproject.toml
git commit -m "bump version to 0.1.1"
git tag v0.1.1
git push origin main
git push origin v0.1.1
```

Install from PyPI:

```bash
python3 -m venv /tmp/redakt-prod-test
source /tmp/redakt-prod-test/bin/activate
python -m pip install --upgrade pip
pip install "redakt[dashboard]==0.1.1"

redakt redact "Email test@example.com"
redakt dashboard
```

## Local Build Check

Before tagging, verify the package locally:

```bash
uv run pytest
rm -rf dist
uv build
uv run --with twine twine check dist/*
```

## Important Notes

- PyPI and TestPyPI versions are immutable. If a version was uploaded once, bump to a new version.
- Do not publish from a dirty working tree.
- Publish release candidates to TestPyPI before publishing stable releases to PyPI.
- Use quoted extras in zsh: `"redakt[dashboard]"`.
