# Configuration

`sentinal init` creates `config.toml` from the packaged default. `sentinal run`
and `sentinal serve` also create it if it is missing. Existing configuration is
never overwritten. Paths for the SQLite database and generated watchlist exports
are resolved relative to the configuration file, so a separate local directory
can be used:

```console
sentinal --config ./local/config.toml init
sentinal --config ./local/config.toml run
```

The default configuration enables the public Immunefi catalogue. Discovery adds
program-page targets, and observed repository links add GitHub targets. No fake
repositories, bounty URLs, or proxy addresses are scheduled by default. Initial
discovery/baselining takes time, particularly with unauthenticated GitHub limits.

## Credentials

Copy `.env.example` to `.env` next to your config and set your own optional
`GITHUB_TOKEN`. Existing process environment variables take precedence. Restart
after changing credentials or HTTP limits. The app can monitor public GitHub
repositories without a token, subject to the source's lower unauthenticated quota.

RPC URLs are only needed for manual on-chain checks. No Etherscan key is required.
See the chain-specific names in `.env.example`. Secrets remain outside the
configuration templates and are used for the corresponding configured services.

## Manual on-chain checks

Scoped contract addresses are discovered from recognized explorer links or an
explicit address plus chain ID. Discovery never makes RPC requests. Addresses on
different chains remain distinct, and ambiguous addresses are not assigned to a
chain by guessing.

Programs with supported scoped EVM assets show **Check on-chain** in their side
panel. The button requires an active program with recorded code/program changes
and at least one configured RPC endpoint. Programs without supported scoped
assets have no button. The default recognized explorer chains and variables are:

| Chain | Environment variable |
|---|---|
| Ethereum | `ETH_RPC_URL` |
| Arbitrum | `ARBITRUM_RPC_URL` |
| Optimism | `OPTIMISM_RPC_URL` |
| Base | `BASE_RPC_URL` |
| Polygon | `POLYGON_RPC_URL` |
| BNB Chain | `BSC_RPC_URL` |
| Avalanche | `AVALANCHE_RPC_URL` |
| Gnosis | `GNOSIS_RPC_URL` |

An explicit scoped EVM chain ID outside this list uses `EVM_<chain-id>_RPC_URL`.
Restart after setting RPC credentials. The checker verifies the endpoint's chain
ID before reading contract storage and pins each chain's reads to a block.

The first successful implementation-slot observation saves a per-program
baseline. Later clicks compare against that baseline and add implementation
address changes to the program's Code changes feed. Other programs' baselines
are not advanced, even if they share an address. Repeat clicks while a check is
running do not create duplicate work. Source limits still apply; failed checks
require another click rather than an automatic retry.

Only the direct ERC-1967 implementation slot is currently supported. Ordinary
contracts, addresses without code, and proxies using other mechanisms produce
an explicit result rather than a fabricated upgrade. These checks do not fetch
implementation source-code diffs and cannot reconstruct upgrades before the
first baseline or an upgrade reverted between checks.

There is no automatic on-chain polling, initial RPC scan, or automatic check
triggered by code/program changes. Scheduled/manual **Poll all** actions exclude
on-chain targets. The page's background refresh only reads saved check results.

## Add a repository

Append a protocol block, replacing the example repository with one you want to
monitor:

```toml
[[protocols]]
id = "my-project"
name = "My project"
priority = "normal"

[protocols.github]
repositories = ["YOUR_ORG/YOUR_REPOSITORY"]
token_env = "GITHUB_TOKEN"
# branch = "main"  # Omit to use the repository's default branch.
```

Config entries seed the SQLite watchlist. The database owns discovered programs
and their state after import; editing a seed does not reset historical baselines.

Default repository cadences are high: 10 minutes, normal: 30 minutes, dormant:
3 hours. The catalogue refreshes hourly; program pages default to four-hour
checks. Request budgets, concurrency, and source cooldowns also affect when a
check can run. Manual refresh controls obey those limits.

The GitHub adapter currently filters many non-runtime paths by default. To monitor
all repository paths, set `include_paths = ["*"]` in its configuration. More
specific patterns can limit the files of interest. This affects future polling;
it does not reconstruct missing patches in old observations.

## Local files and stopping

`config.toml`, `.env`, SQLite databases/backups, and `platforms/` exports are local
state and ignored by Git. Stop the foreground process with **Ctrl+C**. Keep those
files to resume the same baselines and cooldowns on restart. Back up local state
with the server stopped so SQLite's database and any WAL files remain consistent.

An empty Code changes or Program changes section means no such change has been
recorded yet; the first successful poll only establishes a baseline. Source
failures and cooldowns are shown in the dashboard's monitoring details.

## Source failures and recovery

A missing production reference or release tag leaves repository head monitoring
enabled. Monitoring details show the unavailable reference, and subsequent
scheduled checks clear the warning when it returns. A missing configured branch
is retried without permanently blocking the whole repository.

Confirmed unavailable repositories and program URLs are shown as stopped checks.
Use **Retry now**, the corresponding source refresh, or **Poll all** to recheck
them after fixing access or configuration. Source request limits still apply.
The first run after upgrading older databases also rechecks historical blocks,
because earlier versions did not distinguish missing tags from missing repositories.

Incomplete or malformed program responses retain the last good baseline and
targets. Custom bounty JSON endpoints must return complete snapshots: include
all previously supplied policy fields, using explicit empty lists/objects or null
values where supported to remove data. Missing fields are reported as source
errors rather than interpreted as published removals.

Temporary SQLite locking and I/O errors retry with backoff. The scheduler recovers
checks whose completion could not be saved. Permanent database errors stop the
scheduler and retain the failure reason in monitoring status. Browser API requests
have a 15-second deadline covering both headers and JSON bodies.

## Diff provenance after upgrading

Large comparisons may contain both full comparison patches and individual commit
patches for files omitted from the source's comparison list. Each commit patch
shows its parent and commit revisions in the dashboard and ZIP manifest. These
are separate recorded patches; do not combine them into a single base/head patch.

Older patches lacked enough provenance to distinguish these cases reliably.
They are retained with an **unverified coverage** label and `.unverified.diff`
filenames after migration. Existing event IDs, review notes, and stored baselines
are preserved. Changes that older versions failed to record cannot be reconstructed
from local state alone.

## Program ownership and shared sources

Policy snapshots, scope, and derived targets belong to a specific watched program.
Programs can share a protocol ID across platforms without sharing policies.
A shared policy URL is requested once, then baselines and changes are saved
independently for each associated program. Cached responses also catch up older
subscribers and establish baselines for newly added subscribers. URL changes use
a full request rather than reusing another resource's cache validator.

The ownership migration keeps existing event IDs and review notes. Unambiguous
legacy snapshots are assigned to their program and structured scope is repaired.
Ambiguous snapshots and history remain stored without guessing their owner.
Uncertain derived scope and automatically discovered targets are deactivated
until a successful program-specific refresh establishes a new baseline; manual
targets are preserved. Previously missing events cannot be reconstructed.

When `branch` is omitted, each GitHub poll conditionally checks repository metadata
and follows default-branch changes even if the previous branch remains accessible.
An explicit `branch` remains pinned. The first published release after a baseline
with no releases, and disappearance of the latest published release, are recorded
as release changes. Where a comparison has no release on one side, the dashboard
and ZIP manifest explain why no file patches can be supplied.

Manual checks keep a process-local terminal state if saving completion/error
fails. Dashboard reads reconcile it once storage returns, making the action
retryable without restarting. Only the terminal status is retried: committed
baselines/events stay together and failed commits do not advance baselines.

## Resource protections (v0.1.3)

Under `[polling.http]`, `request_timeout_seconds` bounds each network call
(default 15 seconds), and `max_response_bytes` caps each remote HTTP response
(default 16777216 bytes = 16 MiB; allowed 65536 to 67108864). Responses
above this size cause a logged job failure instead of unbounded buffering.
The local dashboard permits up to 16 simultaneous HTTP request threads and
uses 10-second accepted-connection socket timeouts. These are hard-coded in
`LocalHTTPServer` for this release; exceeding the thread limit gives HTTP 503.
`/api/health` returns 503 when the configured monitoring scheduler stops or
fails, while the dashboard-only `serve` command has no scheduler.
