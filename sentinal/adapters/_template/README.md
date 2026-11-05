# Adapter template

Copy this directory to `sentinal/adapters/<your-platform>/`, rename the package, and edit
`adapter.toml` and `adapter.py`. Nothing outside your new directory needs to change: the
scheduler job, the CLI `--source` choice, the dashboard button and the scoring entries all
follow from the manifest.

The directory name must equal the manifest's `source_type` — the loader enforces it.

Never record credentials, API keys, tokens, private keys or private configuration in the
`before`/`after` values or in the patch text your adapter stores. Those recorded values are
evidence: the dashboard, the export manifest and the MCP server present them as recorded,
without generic redaction. See "Recorded before/after values" in `docs/mcp.md`.

Delete `README.md` when you copy; anything beginning with `_` is ignored by discovery, which
is why this template does not register as a platform.

See "Adding a platform" in the project README for the full walkthrough.
