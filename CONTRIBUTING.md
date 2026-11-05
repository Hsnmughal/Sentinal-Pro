# Contributing to Sentinal Pro

Thanks for helping. Sentinal Pro is a local-first monitor: it records what programs and repositories publish, shows the difference, and exports the evidence. Contributions that improve those three things are welcome.

## Licensing of contributions

Sentinal Pro is source-available under the [PolyForm Noncommercial License 1.0.0](LICENSE). By opening a pull request you agree that your contribution is licensed under the same terms, and that it may be distributed as part of the project under those terms. Do not contribute code you cannot license this way, and do not paste code from a project whose license is incompatible.

## Setup

Use Python 3.11 or newer and follow the virtual-environment setup in [README.md](README.md). Then install the development tools:

```console
python -m pip install -e ".[dev]"
```

## Checks to run before a pull request

```console
python -m build --outdir .runtime/dist
python scripts/smoke_install.py --wheel-dir .runtime/dist
python scripts/check_release.py
```

CI runs the installed-wheel smoke test on Windows, Linux, and macOS with Python 3.11 and 3.13.

## What belongs in a change

- A focused fix or feature. Behavior changes should stay covered by tests in your working copy.
- Tests that use fixtures or local HTTP servers, never live platforms or personal credentials.
- Adapter changes that keep persisted source types and event identifiers stable, so existing local databases do not re-emit historical changes.
- Database migrations that stay compatible with users' existing `sentinal.db`.

## What must never be committed

- `.env`, local configuration, SQLite databases or backups.
- Generated `platforms/` watchlist exports.
- Local tooling settings, editor state, or credentials of any kind.
- Recorded patches or program data that you are not permitted to publish.
- The test suite and its fixtures. `tests/` is ignored on purpose; keep it in your working copy.

Tests must be able to run with no network access to live sources. If a change needs a new HTTP interaction, add a local fixture server.

## Reporting problems

- Bugs, UX issues, and feature requests: open an issue with the app version, OS, and minimal reproduction steps against disposable data.
- Security issues: follow [SECURITY.md](SECURITY.md). Never open a public issue containing secrets, private repository names, or exploit details.
- Findings in the projects you monitor: those belong with the project's own disclosure process, not this repository.

## Style

Match the surrounding code. Keep the localhost single-user trust model explicit, keep source adapters independent of the monitoring engine, and prefer bounded responses and explicit failure states over silent fallbacks.
