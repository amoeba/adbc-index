# AGENTS.md

Notes for AI agents working in this repo. Keep this up to date as decisions are made.

## Pre-release drivers

**Include them.** As of commit `56100e4`, we no longer filter out pre-release releases during
download/analysis. All non-draft releases are ingested and an `is_prerelease` boolean column is
written to `releases.parquet` for downstream filtering (e.g. in the HTML dashboard).

This also applies to drivers that are only available as pre-release versions in the `dbc` registry
(e.g. cassandra, presto at the time of writing). Use `dbc search --pre` to see the full driver
list, not just `dbc search`.

## Driver registry source of truth

Use `dbc search --json --pre` to get the authoritative list of drivers. Compare against
`drivers.toml` to find gaps.

### Known gaps (as of 2026-08-26)

All drivers from `dbc search --pre` are now covered in `drivers.toml`.

Notes on non-obvious driver sources:
- `chdb` — the ADBC driver lives in `chdb-io/chdb-core` (not the redirect repo `adbc-drivers/chdb`). Uses `artifact_filter = "*-libchdb.tar.gz"` to target dynamic libs only.

### chdb findings (2026-08-26)

- **Artifact**: `libchdb.so` (named `.so` even on macOS; goblin parses by magic bytes so this is fine)
- **Symbol profile**: Exports only `AdbcDriverInit` — the single-entrypoint style (ADBC 1.1+). No individual `AdbcDatabase*` / `AdbcConnection*` etc. exports. This is intentional and real, not a stub.
- **ADBC support added**: between v26.5.0 (no ADBC symbols at all) and v26.5.1-rc.3 (first appearance of `AdbcDriverInit`). Versions 26.1.0, 26.3.0, 26.5.0 have 0 Adbc* symbols — useful historical data showing when support was added.
- **Artifact sizes**: 130–540 MB uncompressed per platform. 8 releases × 4 platforms = 32 artifacts, ~16 GB total in cache.

## Bug fixed: download manager was extracting tarballs into cache (2026-08-26)

The `extract_tar_gz` helper in `src/download/manager.rs` was unpacking every `.tar.gz` into the same cache directory alongside the archive. This was a leftover from before the analyze step was refactored to extract to `/tmp`. The extracted files had no `.sha256` sidecars and were never read by the analyze step — pure waste.

**Fix**: removed both `extract_tar_gz` calls from `download_task` and deleted the function entirely. Also removed the now-unused `flate2`/`tar` imports.

This freed ~11 GB of stray extracted files from the cache (27 GB → 16 GB).

Drivers in `drivers.toml` **not in the `dbc` registry** (even with `--pre`):
- `athena` — `dbc info athena` returns "not found". Keep in `drivers.toml` for now since we have cached releases; investigate whether it was renamed or removed from the registry.

### Private registry drivers

`oracle`, `sap-hana`, and `teradata` show `"registry":"private"` in `dbc search`. We can still
index their public GitHub releases; no special handling needed beyond what's already in
`drivers.toml`.

## GITHUB_TOKEN

Required for the `download` and `analyze` commands. Must be set as an environment variable.
Also required to resolve GitHub URLs for new drivers (API calls to api.github.com).
