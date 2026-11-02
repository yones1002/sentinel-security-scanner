# Development log

This log records completed work, decisions made while implementing, test results, and commit hashes. It does not list planned work as finished.

## 2026-11-02 — PR 1 package skeleton

Milestone 1, pull request 1 only. Later pull requests have not been started.

### Completed

- Approved architecture committed without scanner code.
- Package `sentinel` version `0.0.1` under `src/sentinel`.
- `sentinel version` and `python -m sentinel version` print `0.0.1` and exit 0.
- Typer is kept as a command group with an explicit callback. A single registered command would otherwise replace the program, and `sentinel version` would not exist.
- Version `0.1.0` is not used. That tag is reserved for the finished milestone 1 static preview.
- Rich and Pydantic are not dependencies yet. Nothing in this pull request imports them.
- GitHub Actions runs pytest on `ubuntu-latest` for Python 3.12 and 3.13 and does not start Docker.
- `main` was not updated.

### Tests

Local interpreter: Python 3.13.7. Python 3.12 is not installed on this machine, so 3.12 was not run here. The workflow is what runs 3.12.

```text
tests/test_version.py ....
4 passed in 0.07s
```

`sentinel version` printed `0.0.1`. Ruff is declared in the dev extra. Its wheel download failed in this environment, so Ruff was not executed. The CI workflow installs the dev extra and runs pytest. It does not invoke Ruff.

### Git

| Commit | Hash | Branch at creation |
| --- | --- | --- |
| docs: add the approved Sentinel architecture | `5a9b12c1d3061330ae3ea101e87990a49bf9f0cf` | `develop` |
| feat: initialize Sentinel package and version command | `87490a3d7b176d113631143032f5b9a531e25fc5` | `feature/pr-1-package-skeleton` |
| ci: run pytest on Python 3.12 and 3.13 | `8be972a12c6817f5124b2fcffe7988c58a0ae5de` | `feature/pr-1-package-skeleton` |

The development log commit is the commit that adds this file. Its hash is not written here.

### Known limitations

- No scan, detect, plugin, or report command.
- No findings, sandbox, or external security tools.
- GitHub CLI is not installed here, so a pull request was not opened from this environment.
- Remote `main` is still empty. Integration is on `develop`.
