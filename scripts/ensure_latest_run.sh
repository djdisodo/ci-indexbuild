#!/usr/bin/env bash
set -euo pipefail

if [[ -z "${GITHUB_TOKEN:-}" ]]; then
  echo "false"
  exit 0
fi

workflow_path="${GITHUB_WORKFLOW_REF#${GITHUB_REPOSITORY}/}"
workflow_path="${workflow_path%%@*}"
api_url="https://api.github.com/repos/${GITHUB_REPOSITORY}/actions/workflows/${workflow_path}/runs?event=${GITHUB_EVENT_NAME}&per_page=1"

latest_run_id="$(
  curl -fsSL \
    -H "Authorization: Bearer ${GITHUB_TOKEN}" \
    -H "Accept: application/vnd.github+json" \
    "${api_url}" | jq -r '.workflow_runs[0].id // empty'
)"

if [[ -n "${latest_run_id}" && "${latest_run_id}" != "${GITHUB_RUN_ID}" ]]; then
  echo "true"
else
  echo "false"
fi
