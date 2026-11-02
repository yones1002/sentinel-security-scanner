# Changelog

All notable changes to Sentinel are documented in this file.

The format is based on Keep a Changelog, and this project uses semantic versioning.
Version `0.1.0` is reserved for the completed milestone 1 static preview described in
`docs/sentinel-architecture.md`. This package is not that release.

## [0.0.1] - 2026-11-02

### Added

- Package skeleton under `src/sentinel`.
- `sentinel version`, which prints the package version and exits 0.
- Tests for that command.
- GitHub Actions workflow that runs pytest on Python 3.12 and 3.13 with no Docker service.

### Not included

- Project detection, static scanning, dynamic scanning, reports, and the Docker sandbox.
  Those remain specified and are not implemented.
