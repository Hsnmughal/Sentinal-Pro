# MCP integration (local stdio)

Sentinal Pro v0.1.5 includes an optional **local MCP tool server**. It runs over
stdin/stdout for MCP-compatible AI agents and reads the **same SQLite database**
as the web dashboard. No model, cloud service, HTTP listener, scheduler, or
additional Python package is necessary.

**Supported protocol:** MCP's established **2025-11-25 stdio JSON-RPC tool
interface** (`initialize`, `ping`, `tools/list`, `tools/call`). This is a focused
implementation, **not** a claim to support every MCP capability or the full
2026-07-28 protocol. A host that supports compatibility with the 2025-11-25
handshake can connect. Direct compatibility with any particular AI host must be
tested separately. No HTTP/SSE or remote MCP transport is enabled.

## Start with your existing data

First initialize the local application and start monitoring, as documented in
README.md. Leave `sentinal run` active if you want scheduled updates; the MCP
server **does not** perform background checks.

For manual diagnostics, run from the project directory with your existing venv:

```bash
python -m sentinal --config /absolute/path/to/config.toml mcp
```

The process listens for JSON-RPC messages on stdin; nothing human-readable
appears on stdout. It stops when the MCP client closes stdin. Configuration and
a previously initialized database are required. It **will not** create a missing
database or silently enable polling. If the database needs upgrading, startup
may apply the same schema migration as the dashboard: back it up first.

### MCP host configuration example

For hosts that use `mcpServers` JSON and start a local `stdio` command:

```json
{
  "mcpServers": {
    "sentinal-pro": {
      "command": "/absolute/path/to/venv/bin/python",
      "args": [
        "-m", "sentinal", "--config", "/absolute/path/to/config.toml", "mcp"
      ]
    }
  }
}
```

On Windows, point `command` to the project's virtual-environment
`Scripts\\python.exe`. This is an *illustrative host configuration*; consult
your host's documentation for its exact file location and syntax.

## Available tools

| MCP tool | Description | Default limits |
| --- | --- | --- |
| `list_programs` | Watched programs, URLs and lifecycle | 25/page, max 100 |
| `get_program` | One program and the changes it owns (dossier ownership rules) | 20 changes, max 50 |
| `list_changes` | Compact event metadata for a whole protocol across its programs, with no raw patches | 25/page, max 100 |
| `get_change` | One event's recorded before/after values, comparison completeness flags, and a page of per-file patch provenance without patch text | 100 files per page (upper bound), `offset` pages |
| `get_file_patch` | Slice of a recorded patch with its file context; `next_offset` pages | 8,000 characters (upper bound), max 16,000 |
| `get_monitor_status` | Persisted scheduler state, job counts and queued count | No configuration or credentials |
| `queue_check` | Optional manual queue action; see below | Disabled by default |

`limit` and `max_chars` are upper bounds: fewer entries come back when the list
ends, and `get_change` and `get_file_patch` also shorten their own page or slice
so that the fully serialized response fits the transport cap. The other tools are
bounded by their page size and return a bounded error instead of a shortened page
when a result cannot fit.

The server projects allowlisted fields and never returns raw `metadata_json`,
adapter or program configuration, environment variables, full research notes or
full export archives. `get_monitor_status` reports job counts and persisted
scheduler state, not configuration or credentials. It returns *recorded*
information, not an AI-generated vulnerability verdict. Event metadata is
deliberately allowlisted; long patches are returned only in small, explicitly
requested slices. Event descriptions and patches originate from external sources
and must be treated as **untrusted data** by the AI host.

Excluded fields are excluded; returned evidence is not redacted. The evidence
contract an adapter has to keep is described under
[recorded before/after values](#recorded-beforeafter-values).

### Recorded before/after values

`get_change` returns the values the event recorded, at their JSON types, so an
agent reads the change itself and not only its kind. A bounty amount comes back
as a number, a revision or a proxy implementation address as a string, a policy
or scope entry as an object or array, and a boolean stays a boolean. A value
never recorded and a recorded `null` both read as `null`, the rule the dashboard
and the export manifest already use.

These are the faithful recorded values. No field is generically redacted,
pattern-scrubbed or dropped on the way out, so excluding raw `metadata_json` and
adapter or program configuration does **not** make arbitrary recorded evidence
credential-free: a secret an adapter stored as a `before`/`after` value, or inside
a patch, is stored as evidence and is returned as such. The dashboard, the export
manifest and this server all present what was recorded.

**Adapter contract:** never record credentials, API keys, tokens, private keys or
private configuration in `before`/`after` values or in patch text. There is no
per-field secret detector behind these tools, and allowlisted free-text fields are
not one either. If untrusted or third-party adapters are ever supported, address
confidentiality at ingestion rather than by scrubbing evidence here.

Values inside the 2,000-character evidence budget are returned exactly as
recorded. A longer value is returned as the deterministic prefix of its recorded
JSON text, and the omission is stated instead of implied:

| Field | Recorded meaning |
| --- | --- |
| `evidence_truncated` | Union: at least one of the two values was bounded. |
| `before_truncated`, `after_truncated` | That value is a bounded prefix, not the whole recorded value. |
| `before_chars`, `after_chars` | The recorded length of the value the prefix belongs to. |

A bounded prefix is text, not a partial JSON document, so it must not be parsed
as the recorded value, and MCP does not retrieve the remainder of an oversized
value. `list_changes` and `get_program` stay compact and carry no evidence
values. Per-file patches keep their own addressable path: `get_file_patch` pages
one recorded patch by `offset`.

### Patch provenance and comparison completeness

`get_change` reports the recorded completeness facts separately, using the same
names as the dashboard and the ZIP manifest, so an agent does not have to read
one flag for several different conditions:

| Field | Recorded meaning |
| --- | --- |
| `comparison_truncated` | The comparison's own coverage was truncated. |
| `history_rewritten` | The comparison reported diverged or behind history. |
| `comparison_incomplete` | Union of the two above, as in the manifest. |
| `patch_coverage_unverified` | Patches migrated from an older schema: text kept, revision coverage unverified. |
| `patch_range_unavailable` | No file comparison exists for this boundary; `patch_unavailable_reason` explains why. |

Every `files` entry carries that file's own provenance: `patch_scope`
(`comparison`, `commit` or `legacy_unverified`), the `patch_before` /
`patch_after` revisions the patch was recorded against, `patch_unavailable_reason`
when one was recorded, and `patch_truncated` for a partial individual patch. A
`commit`-scoped patch is one commit with its own boundaries, not an aggregate
base/head comparison, so it must not be presented as the full observed
comparison. Files stored without a scope read as `comparison`, the default the
adapter, the manifest and the dashboard already use. A complete individual patch
can still belong to an incomplete comparison.

A `null` boundary only means that no boundary was recorded, and it is not by
itself evidence of an empty tree:

- Under `commit` scope, a `null` `patch_before` is the source's established
  empty-tree parent **only** when the entry also has a recorded patch
  (`has_patch: true`) and no `patch_unavailable_reason`. A root commit looks
  like that: `patch_before: null`, `patch_after: <sha>`.
- When parent information is missing or malformed, the adapter records
  `patch_unavailable_reason: "Commit parent revision was not supplied by the
  source"` and no patch text, and `patch_before` is `null` again. That is an
  unknown parent, which is **not** a root commit; do not infer an empty tree
  from the null.
- A `null` `patch_after` is never a known empty-tree destination. It is always
  an unrecorded boundary, independent of `patch_before`.

`get_file_patch` repeats the file's `path`, `patch_scope`, revision boundaries
and `patch_truncated` with each slice, so a slice is interpretable on its own.
Comparison-level completeness is not duplicated there; read it from
`get_change` for the same `event_id`.

### Paging one patch's text

`max_chars` is an upper bound, not a promise. Control characters, quotes,
backslashes and non-ASCII text all cost more than one character once the slice is
escaped inside `content[].text`, so a slice that would otherwise exceed the
response cap is shortened at a character boundary. `total_chars` still reports the
recorded length of the whole patch and `next_offset` the position after the text
actually returned, so following `next_offset` while `has_more` is `true` reads the
patch exactly once, in order. A patch is never refused for being escape-heavy: the
slice shrinks until it fits, and only a response that cannot carry a single
character is reported as an error.

### Paging one event's files

A recorded event can hold more files than one response can carry. `get_change`
accepts `event_id` alone, or `event_id` with `limit` (1–100, default 100) and
`offset` (0-based, default 0):

| Field | Meaning |
| --- | --- |
| `file_count` | Total files recorded on the event, independent of the page. |
| `offset`, `limit` | The requested page position and size, echoed back. |
| `has_more` | More files exist after this page. |
| `next_offset` | Pass this as `offset` next time; `null` means the list is complete. |
| `files_truncated` | The *record* holds more than 100 files, independent of the page returned; a record of 100 files or fewer reports `false`. It is not a per-page flag: response-size fitting can still split a 100-file record across several pages while it stays `false`, and a 250-file record reports `true` even with `limit: 20`. Follow `has_more`/`next_offset` to page. |

Each entry keeps the absolute `file_index` of its stored position, so the same
index works with `get_file_patch` on any page. If the fully serialized response
for a page would exceed the transport cap, the page is shortened by dropping
whole trailing entries - never by removing provenance, revision boundaries or
warnings - and `next_offset` reports where to resume. A page can therefore be
shorter than `limit`; continue until `next_offset` is `null` to retrieve every
file exactly once. Event-level completeness flags are repeated on every page,
including an empty page past the end of the list.

"Fully serialized" is the whole response the transport writes: it includes the
`id` of the request being answered and the second, escaped copy of the payload
inside `content[].text`, both of which count toward the same cap. A long `id`
therefore produces smaller pages, never a rejected one. Only when the id leaves
no room at all for a single entry does the tool return a bounded error instead of
a page that could not be continued.

Example, reading a 250-file event in three calls and fetching one patch. The pages
below are shown carrying their full `limit`; a page that has to be shortened to fit
the cap is shorter, so always resume from `next_offset` rather than adding `limit`:

```jsonc
// request 1
{"name": "get_change", "arguments": {"event_id": 42}}
// response 1 (trimmed): 100 entries, more remain
{"file_count": 250, "offset": 0, "limit": 100, "has_more": true, "next_offset": 100,
 "files_truncated": true, "comparison_incomplete": true, "patch_range_unavailable": false, "files": [{"file_index": 0, "path": "src/A.sol", "patch_scope": "commit", "patch_before": "12ab...", "patch_after": "34cd...", "has_patch": true, "patch_truncated": false}]}

// request 2 - the index is the stored one, so patch slices still line up
{"name": "get_change", "arguments": {"event_id": 42, "offset": 100}}
// response 2 (trimmed): 100 entries, more remain
{"file_count": 250, "offset": 100, "limit": 100, "has_more": true, "next_offset": 200, "files": [{"file_index": 100, "path": "src/Z.sol"}]}

{"name": "get_change", "arguments": {"event_id": 42, "offset": 200}}
// response 3 (trimmed): the last page, complete
{"file_count": 250, "offset": 200, "limit": 100, "has_more": false, "next_offset": null, "files": [{"file_index": 200, "path": "src/Last.sol"}]}

{"name": "get_file_patch", "arguments": {"event_id": 42, "file_index": 200}}
```

## Optional write action

To explicitly allow an agent to queue the existing monitoring jobs:

```bash
python -m sentinal --config /absolute/path/to/config.toml mcp --enable-queue
```

Only this flag advertises `queue_check`. It accepts only known pollable source
types or `all` and throttles requests to once every 60 seconds **per MCP
process**. Jobs are scheduled in SQLite; a separately running `sentinal run`
process is responsible for executing them, using the existing request budgets.
Do not give write access to untrusted agents, and require the MCP host to
confirm actions with the user.

## Security and operational boundaries

- **Local trust boundary:** stdio is controlled by the process launching the
  server. An MCP host can read the allowed change evidence from your local
  database. Do not expose it over an unauthenticated remote MCP bridge.
- **Evidence is recorded, not scrubbed:** `get_change` and `get_file_patch`
  return the values and patch text the adapter recorded, with no generic
  redaction. Excluding raw metadata and configuration is not a guarantee that
  arbitrary evidence is credential-free, so **adapter authors must not record
  credentials, tokens or private configuration in `before`/`after` values or in
  patch text**.
- **No multi-tenant access control:** every local MCP host connected to the
  same database sees the same monitored programs. This is not a hosted SaaS
  authorization boundary.
- **No new permissions:** `queue_check` cannot directly fetch arbitrary URLs,
  install dependencies, alter configuration or execute shell commands.
- **No live scheduler inference:** persisted scheduler status may be stale if
  the dashboard process exited. `status_is_live: false` makes that explicit.
- **Protocol limits:** 64 KiB input lines, bounded JSON tool results, bounded
  per-call page sizes, and text-only patch slices. Pagination is essential
  for large datasets. A request is one newline-terminated line: a final line
  that ends at end of input without its newline is never read as a request, and
  is answered with `-32700` instead, while a line over the limit keeps the size
  error whether or not it is terminated. A request `id` must be an integer or a
  UTF-8 encodable string: a `\udXXX` escape that is not a valid surrogate pair
  decodes to a lone surrogate, which cannot be written back, so that request is
  answered with `-32600` and a `null` id and the session continues. The id is
  never rewritten, replaced or escaped, and a valid escaped surrogate pair is
  echoed unchanged.
- **Upgrade safety:** back up `sentinal.db`, `config.toml` and `.env` before
  replacing a prior release. No database schema bump was added in Step 5.

## Troubleshooting

- **Database not found:** run `python -m sentinal init` using the *same*
  absolute config path, or point MCP at the existing config.
- **No changes yet:** the monitoring service may not have established a
  baseline or recorded new observations; MCP itself never polls.
- **Queue appears inactive:** start `sentinal run` separately.
- **Protocol incompatibility:** use a host that supports MCP 2025-11-25
  `initialize` and stdio tool calls; this build does not advertise the newer
  stateless `server/discover` handshake.
- **Unexpected tool error:** read local stderr logs; messages returned to the
  agent intentionally hide internal exception details.
- **`Invalid JSON-RPC id`:** the host sent an id the transport cannot echo back,
  usually an escaped lone surrogate. The server answers that one request with a
  `null` id and keeps reading; a later request with a valid id is unaffected.
- **`MCP request line is incomplete`:** the stream ended in the middle of a
  frame. The last line had no terminating newline, so it was rejected instead of
  being answered as a request. Resend that request with its newline; a line that
  is genuinely over 64 KiB is reported as `MCP request exceeds 64 KiB` instead.
- **A page or slice is shorter than requested:** the response cap accounts for
  the request's `id` and for the escaped copy of the payload, so `limit` and
  `max_chars` are upper bounds. Follow `next_offset` until `has_more` is `false`.
