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

## 2026-11-02 — PR 1 independent review

The reviewed range is `5a9b12c1d3061330ae3ea101e87990a49bf9f0cf..014c8447ef7fad199628770088d27633caa50b43`. No product bug was found. Two suggestions were fixed in later commits. PR 2 has not been started.

### Review result

- `pyproject.toml`, the Typer command group, README, CHANGELOG, and the MIT license matched the approved PR 1 scope.
- The version tests did not run the installed `sentinel` console script. A broken `[project.scripts]` entry point could still pass.
- CI installed Ruff and did not run it. The existing Python 3.12 and 3.13 jobs were already green.

### Fixes

- `tests/test_version.py` runs the console script installed next to the current interpreter and strips `PYTHONPATH`.
- `.github/workflows/ci.yml` checks `sentinel version` and `python -m sentinel version` against `sentinel.__version__`, then runs `python -m ruff check src tests`.

### Tests

Local interpreter: Python 3.13.7. Python 3.12 is not installed on this machine.

```text
ruff 0.17.3
All checks passed!
5 passed in 0.13s
```

`sentinel version` and `python -m sentinel version` printed `0.0.1`.

GitHub Actions on `c6e6dd3db6760ae183e0d0b4f24ea32cddc5d519`, after these fixes:

| Run | Branch | Result |
| --- | --- | --- |
| [41447429738](https://github.com/yones1002/sentinel-security-scanner/actions/runs/41447429738) | `develop` | success |
| [41447403481](https://github.com/yones1002/sentinel-security-scanner/actions/runs/41447403481) | `feature/pr-1-package-skeleton` | success |

On both runs, `test (3.12)` and `test (3.13)` completed with success. Install, entry-point check, Ruff, and pytest each succeeded.

### Git

| Commit | Hash |
| --- | --- |
| docs: record PR 1 in the development log | `014c8447ef7fad199628770088d27633caa50b43` |
| test: exercise the installed sentinel console script | `90ae811009cab5c95ea607f392954dfce0ba125c` |
| ci: check entry points and run Ruff | `c6e6dd3db6760ae183e0d0b4f24ea32cddc5d519` |

This review entry is committed after those hashes. Its own hash is not written here.
