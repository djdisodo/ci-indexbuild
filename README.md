# Alpine R2 Repo Indexer

This repository rebuilds Alpine `APKINDEX.tar.gz` in Cloudflare R2 with a dirty-flag model and safe prune flow.

Core behavior:

- only reindex paths marked dirty,
- keep only the latest package version per package name,
- allow only one workflow run at a time and keep the newest run,
- publish index before remote deletions to avoid broken repositories,
- optionally sign generated `APKINDEX.tar.gz`,
- verify package signatures against trusted public keys stored in this repository.

## Architecture

Main components:

- workflow: `.github/workflows/reindex.yml`
- main processor: `scripts/reindex_dirty.py`
- stale-run guard: `scripts/ensure_latest_run.sh`
- credential allowlist validator: `scripts/validate_trusted_credentials.py`
- dirty-flag queue worker: `cloudflare/dirty-flag-worker`
- trusted keyring: `trusted/apk-keys/`

High-level flow:

1. R2 object-create event for `.apk` under `alpine/` arrives.
2. Cloudflare worker writes marker object to `_state/dirty/<repo_path>.dirty`.
3. GitHub workflow starts (`repository_dispatch` or `workflow_dispatch`).
4. Workflow processes dirty paths, rebuilds indices, prunes old packages, clears marker if no race.

## Usage

### 1) Configure GitHub variables and secrets

Repository variables:

- `R2_ACCOUNT_ID`
- `R2_BUCKET`
- `REPO_PREFIX` (optional, default `alpine/`)
- `STATE_PREFIX` (optional, default `_state/dirty/`)
- `TRUSTED_APK_KEYS_DIR` (optional, default `trusted/apk-keys`)
- `SIGN_REPO_INDEX` (optional, `0` or `1`, default `0`)
- `APK_REPO_SIGNING_KEY_PUBLIC_NAME` (optional, passed to `abuild-sign -p`)

Repository secrets:

- `R2_ACCESS_KEY_ID`
- `R2_SECRET_ACCESS_KEY`
- `APK_REPO_SIGNING_KEY` (required only when `SIGN_REPO_INDEX=1`)

Security note:

- `APK_REPO_SIGNING_KEY_B64` is read from GitHub Secret only, decoded to a temporary runner file, and removed in cleanup.

### 2) Configure trusted APK keys

Place trusted `.pub` keys in:

- `trusted/apk-keys/`

This repository already includes official Alpine keys used by the current test dataset.

During processing:

- packages are verified with `apk --no-network --keys-dir /trusted-keys verify ...`
- index generation also uses trusted keys (`apk --no-network --keys-dir /trusted-keys index ...`)

### 3) Configure dirty-flag worker

Bootstrap (recommended):

```bash
cd cloudflare/dirty-flag-worker
npm install
./setup.sh \
  --api-token "<cloudflare_api_token>" \
  --account-id "<cloudflare_account_id>" \
  --bucket "<r2_bucket_name>" \
  --queue "alpine-r2-events" \
  --enable-delete-events 0
```

Token permissions needed:

- Workers Scripts: Edit
- Queues: Edit
- R2: Edit

`--enable-delete-events 0` is the default recommended mode (mark dirty on create/update only).

### 4) Trigger indexing

Supported events:

- `repository_dispatch` with type `alpine-reindex`
- `workflow_dispatch`

`workflow_dispatch` inputs (GitHub Web UI):

- `targets` (optional): comma-separated repo paths such as `alpine/v3.23/main/riscv64`
- `force_reindex` (optional, default `false`): when `true`, the run ignores dirty-marker selection and processes only `targets` (mapped to `--explicit-only`)

Force reindex example from Web UI:

1. Open **Actions** -> **Reindex Repo** -> **Run workflow**.
2. Set `targets` to one or more paths (comma-separated).
3. Set `force_reindex` to `true`.

Optional target keys in payload:

- `path`, `paths`, `prefix`, `prefixes`, `target`, `targets`

If payload targets are provided, they are merged with current dirty markers.

Example dispatch payload:

```json
{
  "event_type": "alpine-reindex",
  "client_payload": {
    "paths": [
      "alpine/v3.20/main/x86_64",
      "alpine/v3.20/community/x86_64"
    ]
  }
}
```

## Implementation details

### Dirty marker model

- dirty marker exists: `dirty=true`
- marker absent: `dirty=false`
- key format: `_state/dirty/<repo_path>.dirty`

Race-safe clear behavior:

1. load marker ETag at selection time,
2. after successful processing, read current ETag again,
3. clear only if unchanged,
4. if changed, leave marker for next run.

### Concurrency and latest-run semantics

In workflow:

- `concurrency.group = alpine-reindex-global`
- `cancel-in-progress = true`

Additional stale-run guard:

- `scripts/ensure_latest_run.sh` checks latest run via GitHub API and skips stale execution.

### Reindex and prune algorithm

For each target path:

1. pull all `.apk` from R2 path to local temp dir,
2. verify package signatures against trusted keyring,
3. build initial `APKINDEX.tar.gz`,
4. parse `APKINDEX` entries (`P`, `V`),
5. choose latest version per package via `apk version -t`,
6. delete old package versions locally,
7. rebuild final `APKINDEX.tar.gz`,
8. optionally sign index with `abuild-sign`,
9. upload index to R2 (skip upload if content hash unchanged),
10. delete old package objects remotely,
11. clear marker when safe.

### Cancellation safety

Critical order is intentional:

1. build final index,
2. upload final index,
3. delete old remote packages.

If job is canceled mid-run, repository remains usable. Worst case is extra old packages left behind.

### API usage minimization

- process only selected dirty paths,
- list objects by path prefix only,
- skip index upload when `content-sha256` metadata already matches,
- bulk-delete remote keys in batches (up to 1000 keys/request).

## Local operations

### Dry-run processor

```bash
python3 -m pip install -r scripts/requirements.txt
python3 scripts/reindex_dirty.py \
  --bucket "<bucket>" \
  --account-id "<account-id>" \
  --repo-prefix "alpine/" \
  --state-prefix "_state/dirty/" \
  --trusted-keys-dir "trusted/apk-keys" \
  --dry-run
```

### `act` CI test

```bash
mkdir -p .act-tmp
cat > .act-tmp/event.json <<'JSON'
{"path":"alpine/v3.20/main/x86_64"}
JSON

cat > .act-tmp/secrets.env <<'ENV'
R2_ACCOUNT_ID=<account_id>
R2_BUCKET=<bucket>
R2_ACCESS_KEY_ID=<access_key>
R2_SECRET_ACCESS_KEY=<secret_key>
ENV

TMPDIR="$PWD/.act-tmp" act workflow_dispatch \
  -W .github/workflows/reindex.yml \
  -j reindex \
  --bind \
  --pull=false \
  -P ubuntu-latest=catthehacker/ubuntu:act-latest \
  --eventpath .act-tmp/event.json \
  --secret-file .act-tmp/secrets.env \
  --env TMPDIR="$PWD/.act-tmp"
```

## Repository trust policy

Trusted credential inventory file:

- `.github/trusted-credentials.json`

Enforcement script:

- `scripts/validate_trusted_credentials.py`

If new credential-like env vars are introduced, add them to the trusted inventory intentionally.
