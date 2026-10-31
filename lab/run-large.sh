#!/usr/bin/env bash
# Large-stream differential matrix for CVE-2026-111497 (HTTP2Shell) research.
# Generates the block-switch-exhaustion trigger inside a pinned container,
# then feeds it to the vulnerable/fixed pair in three modes (one-shot sync,
# streaming whole, streaming chunked) under an external timeout. Decoder
# hangs, CPU spins and memory-corruption crashes all stay observable through
# the exit code; clean rejections arrive as JSON lines.
#
# Env overrides: VULN_IMAGE, FIXED_IMAGE, PROBE_TIMEOUT, COMMANDS
set -uo pipefail
cd "$(dirname "$0")/.."

VULN_IMAGE="${VULN_IMAGE:-node:24.22.0}"
FIXED_IMAGE="${FIXED_IMAGE:-node:24.22.1}"
PROBE_TIMEOUT="${PROBE_TIMEOUT:-120}"
COMMANDS="${COMMANDS:-16777216}"
RESULTS_DIR="lab/results"
TRIGGER="lab/triggers/blockswitch-flood.br"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
OUT="$RESULTS_DIR/large-matrix-$STAMP.log"

mkdir -p "$RESULTS_DIR" lab/triggers

echo "== generating trigger (commands=$COMMANDS) inside $FIXED_IMAGE ==" | tee "$OUT"
docker run --rm --user "$(id -u):$(id -g)" -v "$PWD/lab:/lab" \
  "$FIXED_IMAGE" node /lab/gen-trigger.js "/lab/triggers/blockswitch-flood.br" \
  --commands "$COMMANDS" 2>&1 | tee -a "$OUT"

run_case() { # <image> <mode>
  local img="$1" mode="$2"
  echo "== $img :: $mode ==" | tee -a "$OUT"
  docker run --rm -v "$PWD/lab:/lab" "$img" \
    timeout "$PROBE_TIMEOUT" node /lab/probe-large.js "/$TRIGGER" --mode "$mode" 2>&1 | tee -a "$OUT"
  echo "exit=${PIPESTATUS[0]}" | tee -a "$OUT"
}

for img in "$VULN_IMAGE" "$FIXED_IMAGE"; do
  for mode in sync stream-whole stream-chunked; do
    run_case "$img" "$mode"
  done
done

echo "== matrix written to $OUT ==" | tee -a "$OUT"
