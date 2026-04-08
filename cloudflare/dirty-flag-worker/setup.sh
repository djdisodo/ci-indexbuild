#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "${SCRIPT_DIR}"

usage() {
  cat <<'USAGE'
Usage:
  ./setup.sh \
    --api-token <cloudflare_api_token> \
    --account-id <cloudflare_account_id> \
    --bucket <r2_bucket_name> \
    [--queue <queue_name>] \
    [--alpine-prefix <prefix>] \
    [--dirty-prefix <prefix>] \
    [--apk-suffix <suffix>] \
    [--rule-description <text>] \
    [--enable-delete-events <0|1>] \
    [--delete-existing-queue-rules <0|1>]

Environment variable fallbacks are also supported:
  CLOUDFLARE_API_TOKEN
  ACCOUNT_ID
  BUCKET_NAME
  QUEUE_NAME
  ALPINE_PREFIX
  DIRTY_PREFIX
  APK_SUFFIX
  RULE_DESCRIPTION
  ENABLE_DELETE_EVENTS
  DELETE_EXISTING_QUEUE_RULES
USAGE
}

API_TOKEN="${CLOUDFLARE_API_TOKEN:-}"
ACCOUNT_ID="${ACCOUNT_ID:-}"
BUCKET_NAME="${BUCKET_NAME:-}"
QUEUE_NAME="${QUEUE_NAME:-alpine-r2-events}"
ALPINE_PREFIX="${ALPINE_PREFIX:-alpine/}"
DIRTY_PREFIX="${DIRTY_PREFIX:-_state/dirty/}"
APK_SUFFIX="${APK_SUFFIX:-.apk}"
RULE_DESCRIPTION="${RULE_DESCRIPTION:-alpine repo apk change notifications}"
ENABLE_DELETE_EVENTS="${ENABLE_DELETE_EVENTS:-0}"
DELETE_EXISTING_QUEUE_RULES="${DELETE_EXISTING_QUEUE_RULES:-1}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --api-token)
      API_TOKEN="${2:-}"
      shift 2
      ;;
    --account-id)
      ACCOUNT_ID="${2:-}"
      shift 2
      ;;
    --bucket)
      BUCKET_NAME="${2:-}"
      shift 2
      ;;
    --queue)
      QUEUE_NAME="${2:-}"
      shift 2
      ;;
    --alpine-prefix)
      ALPINE_PREFIX="${2:-}"
      shift 2
      ;;
    --dirty-prefix)
      DIRTY_PREFIX="${2:-}"
      shift 2
      ;;
    --apk-suffix)
      APK_SUFFIX="${2:-}"
      shift 2
      ;;
    --rule-description)
      RULE_DESCRIPTION="${2:-}"
      shift 2
      ;;
    --enable-delete-events)
      ENABLE_DELETE_EVENTS="${2:-}"
      shift 2
      ;;
    --delete-existing-queue-rules)
      DELETE_EXISTING_QUEUE_RULES="${2:-}"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

if [[ -z "${API_TOKEN}" ]]; then
  echo "Missing API token. Use --api-token or CLOUDFLARE_API_TOKEN." >&2
  exit 1
fi
if [[ -z "${ACCOUNT_ID}" ]]; then
  echo "Missing account id. Use --account-id or ACCOUNT_ID." >&2
  exit 1
fi
if [[ -z "${BUCKET_NAME}" ]]; then
  echo "Missing bucket. Use --bucket or BUCKET_NAME." >&2
  exit 1
fi
if [[ "${DELETE_EXISTING_QUEUE_RULES}" != "0" && "${DELETE_EXISTING_QUEUE_RULES}" != "1" ]]; then
  echo "--delete-existing-queue-rules must be 0 or 1" >&2
  exit 1
fi
if [[ "${ENABLE_DELETE_EVENTS}" != "0" && "${ENABLE_DELETE_EVENTS}" != "1" ]]; then
  echo "--enable-delete-events must be 0 or 1" >&2
  exit 1
fi

export CLOUDFLARE_API_TOKEN="${API_TOKEN}"
export CLOUDFLARE_ACCOUNT_ID="${ACCOUNT_ID}"

CONFIG_FILE="$(mktemp -t wrangler-config-XXXXXX.toml)"
cleanup() {
  rm -f "${CONFIG_FILE}"
}
trap cleanup EXIT

cat > "${CONFIG_FILE}" <<CONFIG
name = "alpine-dirty-flag-worker"
main = "${SCRIPT_DIR}/src/index.ts"
compatibility_date = "2026-04-01"
account_id = "${ACCOUNT_ID}"

[vars]
ALPINE_PREFIX = "${ALPINE_PREFIX}"
DIRTY_PREFIX = "${DIRTY_PREFIX}"

[[r2_buckets]]
binding = "REPO_BUCKET"
bucket_name = "${BUCKET_NAME}"

[[queues.consumers]]
queue = "${QUEUE_NAME}"
max_batch_size = 100
max_batch_timeout = 5
CONFIG

echo "[auth] verifying token"
npx wrangler whoami --config "${CONFIG_FILE}" >/dev/null

echo "[queue] ensuring queue exists: ${QUEUE_NAME}"
set +e
queue_output="$(npx wrangler queues create "${QUEUE_NAME}" --config "${CONFIG_FILE}" 2>&1)"
queue_rc=$?
set -e
if [[ ${queue_rc} -ne 0 ]]; then
  if grep -qiE "already exists|already taken|A queue with this name already exists" <<<"${queue_output}"; then
    echo "[queue] already exists"
  else
    echo "${queue_output}" >&2
    exit ${queue_rc}
  fi
else
  echo "${queue_output}"
fi

if [[ "${DELETE_EXISTING_QUEUE_RULES}" == "1" ]]; then
  echo "[r2] deleting existing notification rules bound to queue: ${QUEUE_NAME}"
  set +e
  delete_output="$(npx wrangler r2 bucket notification delete "${BUCKET_NAME}" --queue "${QUEUE_NAME}" --config "${CONFIG_FILE}" 2>&1)"
  delete_rc=$?
  set -e
  if [[ ${delete_rc} -ne 0 ]]; then
    if grep -qiE "No notification rules|not found|404" <<<"${delete_output}"; then
      echo "[r2] no existing rules to delete"
    else
      echo "${delete_output}" >&2
      exit ${delete_rc}
    fi
  else
    echo "${delete_output}"
  fi
fi

echo "[r2] creating object-create notification rule"
npx wrangler r2 bucket notification create "${BUCKET_NAME}" \
  --event-type object-create \
  --prefix "${ALPINE_PREFIX}" \
  --suffix "${APK_SUFFIX}" \
  --queue "${QUEUE_NAME}" \
  --description "${RULE_DESCRIPTION} (create)" \
  --config "${CONFIG_FILE}"

if [[ "${ENABLE_DELETE_EVENTS}" == "1" ]]; then
  echo "[r2] creating object-delete notification rule"
  npx wrangler r2 bucket notification create "${BUCKET_NAME}" \
    --event-type object-delete \
    --prefix "${ALPINE_PREFIX}" \
    --suffix "${APK_SUFFIX}" \
    --queue "${QUEUE_NAME}" \
    --description "${RULE_DESCRIPTION} (delete)" \
    --config "${CONFIG_FILE}"
else
  echo "[r2] skip object-delete notification rule (ENABLE_DELETE_EVENTS=0)"
fi

echo "[deploy] deploying worker"
npx wrangler deploy --config "${CONFIG_FILE}"

echo "[verify] current rules"
npx wrangler r2 bucket notification list "${BUCKET_NAME}" --config "${CONFIG_FILE}"

echo "[done] worker + queue notifications are configured"
