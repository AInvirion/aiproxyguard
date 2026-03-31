# Release Process

This document describes how to release a new version of AIProxyGuard.

## Prerequisites

- Push access to the repository
- GitHub CLI (`gh`) installed and authenticated

## Release Steps

### 1. Update Version

Edit `pyproject.toml` and update the version:

```toml
version = "X.Y.Z"
```

### 2. Update Changelog

Add a new section to `CHANGELOG.md`:

```markdown
## [X.Y.Z] - YYYY-MM-DD

### Added/Changed/Fixed
- Description of changes
```

Also update the comparison links at the bottom:

```markdown
[Unreleased]: https://github.com/AInvirion/aiproxyguard/compare/vX.Y.Z...HEAD
[X.Y.Z]: https://github.com/AInvirion/aiproxyguard/compare/vPREVIOUS...vX.Y.Z
```

### 3. Commit and Push

```bash
git add pyproject.toml CHANGELOG.md
git commit -m "chore: bump version to X.Y.Z"
git push origin main
```

### 4. Create and Push Tag

```bash
git tag vX.Y.Z
git push origin --tags
```

This triggers the `docker-publish.yml` workflow which:
- Builds multi-arch images (amd64, arm64)
- Pushes `aiproxyguard:X.Y.Z` to Docker Hub and GHCR

### 5. Create GitHub Release

```bash
gh release create vX.Y.Z --title "vX.Y.Z" --notes "Release notes here"
```

Or use the GitHub web UI to create a release from the tag.

Creating a GitHub release triggers the workflow again and:
- Updates the `latest` tag on Docker Hub and GHCR

## Published Images

After a full release, these images are available:

| Registry | Image |
|----------|-------|
| Docker Hub | `ovalenzuela/aiproxyguard:X.Y.Z` |
| Docker Hub | `ovalenzuela/aiproxyguard:latest` |
| GHCR | `ghcr.io/ainvirion/aiproxyguard:X.Y.Z` |
| GHCR | `ghcr.io/ainvirion/aiproxyguard:latest` |

## Quick Release Script

```bash
VERSION="X.Y.Z"

# Commit, tag, push
git add pyproject.toml CHANGELOG.md
git commit -m "chore: bump version to ${VERSION}"
git tag v${VERSION}
git push origin main --tags

# Create release (updates 'latest' tag)
gh release create v${VERSION} --title "v${VERSION}" --generate-notes
```

## Monitoring

Check workflow status:
```bash
gh run list --workflow=docker-publish.yml --limit=3
```

Watch a running workflow:
```bash
gh run watch <run-id> --exit-status
```
