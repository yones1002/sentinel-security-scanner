# Sentinel

Sentinel is a defensive application security scanner for source trees and local services the operator owns. Python is the language Sentinel is written in. Projects under analysis may use other languages.

**Scanning is not implemented.** The only working command in this repository is `sentinel version`.

The approved design is [docs/sentinel-architecture.md](docs/sentinel-architecture.md). This tree follows that document's PR plan. Pull request 1 is the package skeleton, the version command, and continuous integration.

## Status

The table below is the architecture support matrix. A cell is either `specified, not implemented` or `not planned in milestones 1–6`. No scanner is built.

Universal checks, each `specified, not implemented`, are not repeated as framework-specific analyzers:

- Surface filename and literal rules, milestone 1, are `specified, not implemented`.
- Semgrep, milestone 1, only when the operator has a local config, is `specified, not implemented`.
- OSV-Scanner lockfile advisories, milestone 2, are `specified, not implemented`.
- Trivy misconfiguration checks, milestone 2, are `specified, not implemented`.
- Origin-level dynamic checks, milestones 4 and 5, are `specified, not implemented`.

| Row | Detection | Static checks | Dynamic start | Dynamic checks | Status today |
| --- | --- | --- | --- | --- | --- |
| Laravel | Milestone 1 marker rules. specified, not implemented. | None beyond the universal surface scanner. specified, not implemented. | Milestone 4 allowlist when `artisan` and `vendor/` both exist. specified, not implemented. | No Laravel-specific dynamic check. Origin-level checks apply only if that plan starts. specified, not implemented. | specified, not implemented |
| WordPress | Milestone 1 core markers. specified, not implemented. | Filename check for `wp-config.php` only. specified, not implemented. | not planned in milestones 1–6. | not planned in milestones 1–6. | specified, not implemented |
| Plain PHP | Milestone 1, and only a WordPress plugin directory when core markers are absent. specified, not implemented. | None beyond the universal surface scanner. specified, not implemented. | not planned in milestones 1–6. | not planned in milestones 1–6. | specified, not implemented |
| Go | Milestone 1 `go.mod`. specified, not implemented. | None beyond the universal surface scanner. specified, not implemented. | not planned in milestones 1–6. | not planned in milestones 1–6. | specified, not implemented |
| Django | Milestone 1 `manage.py` or a `django` dependency. specified, not implemented. | None beyond the universal surface scanner. A Django rule pack is not planned in milestones 1–6. | not planned in milestones 1–6. | not planned in milestones 1–6. | specified, not implemented |
| Flask | Milestone 1 `flask` dependency. specified, not implemented. | None beyond the universal surface scanner. specified, not implemented. | Milestone 1 planner and milestone 4 runner for one module-level `Flask()` assignment. specified, not implemented. | No Flask-specific dynamic check. specified, not implemented. | specified, not implemented |
| FastAPI | Milestone 1 `fastapi` dependency. specified, not implemented. | None beyond the universal surface scanner. specified, not implemented. | Milestone 1 planner and milestone 4 runner for one module-level `FastAPI()` assignment. specified, not implemented. | No FastAPI-specific dynamic check. specified, not implemented. | specified, not implemented |
| Plain Python | Milestone 1 Python manifest, frameworks empty. specified, not implemented. | Bandit fallback, milestone 2, only when Semgrep did not run. specified, not implemented. | Only when the Flask or FastAPI start rule matches. specified, not implemented. | No Python-specific dynamic analyzer. specified, not implemented. | specified, not implemented |
| Express | Milestone 1 exact `express` dependency. specified, not implemented. | None beyond the universal surface scanner. specified, not implemented. | An Express-specific start is not planned in milestones 1–6. The plain Node plan may apply. specified, not implemented. | No Express-specific dynamic check. specified, not implemented. | specified, not implemented |
| NestJS | Milestone 1 exact `@nestjs/core` dependency. specified, not implemented. | None beyond the universal surface scanner. specified, not implemented. | not planned in milestones 1–6. | not planned in milestones 1–6. | specified, not implemented |
| Plain Node | Milestone 1 bare `package.json`. specified, not implemented. | None beyond the universal surface scanner. specified, not implemented. | Milestone 4 `node server.js` or `node index.js`. specified, not implemented. | No Node-specific dynamic check. specified, not implemented. | specified, not implemented |
| Spring Boot | Milestone 1 Maven or Gradle Spring Boot markers. specified, not implemented. | None beyond the universal surface scanner. specified, not implemented. | not planned in milestones 1–6. | not planned in milestones 1–6. | specified, not implemented |
| ASP.NET Core | Milestone 1 web SDK markers. specified, not implemented. | None beyond the universal surface scanner. specified, not implemented. | not planned in milestones 1–6. | not planned in milestones 1–6. | specified, not implemented |
| Rails | Milestone 1 `rails` gem plus a route or `bin/rails` file. specified, not implemented. | None beyond the universal surface scanner. specified, not implemented. | not planned in milestones 1–6. | not planned in milestones 1–6. | specified, not implemented |
| React | Milestone 1 exact `react` dependency, omitted when an application framework matches the same directory. specified, not implemented. | None beyond the universal surface scanner. specified, not implemented. | not planned in milestones 1–6. | not planned in milestones 1–6. | specified, not implemented |
| Vue | Milestone 1 exact `vue` dependency. specified, not implemented. | None beyond the universal surface scanner. specified, not implemented. | not planned in milestones 1–6. | not planned in milestones 1–6. | specified, not implemented |
| Angular | Milestone 1 `@angular/core` or `angular.json`. specified, not implemented. | None beyond the universal surface scanner. specified, not implemented. | not planned in milestones 1–6. | not planned in milestones 1–6. | specified, not implemented |
| Repository root | Milestone 1 synthetic root component when no rule selects the root. specified, not implemented. | The universal surface scanner runs once here. specified, not implemented. | A start plan exists only when the root itself matches an allowlisted plan. specified, not implemented. | Path-mode origin checks use the root when it was not suppressed. specified, not implemented. | specified, not implemented |

## Requirements

Python 3.12 or 3.13.

Runtime dependency in this version: Typer. Rich and Pydantic are named in the architecture for later milestone 1 work. They are not dependencies of this version because nothing imports them yet.

## Install

```bash
python -m pip install -e ".[dev]"
```

## Usage

```bash
sentinel version
```

The command prints the package version, such as `0.0.1`, and exits 0. `python -m sentinel version` does the same.

There is no `scan`, `detect`, or `report` command in this build.

## Tests

```bash
python -m pytest
```

GitHub Actions runs that command on `ubuntu-latest` for CPython 3.12 and 3.13. The workflow does not start a Docker service.

## License

MIT. See [LICENSE](LICENSE).
