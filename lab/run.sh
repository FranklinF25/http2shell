#!/usr/bin/env bash
# Differential matrix runner for the CVE-2026-111497 (HTTP2Shell) lab.
# Executes the probe inside pinned official Node images under an external
# timeout, so hangs (decoder waiting for input) and CPU spins (C-level loop)
# are both observable, and records everything to lab/results/.
#
# Env overrides: VULN_IMAGE, FIXED_IMAGE, PROBE_TIMEOUT
set -uo pipefail
cd "$(dirname "$0")/.."

VULN_IMAGE="${VULN_IMAGE:-node:24.22.0}"
FIXED_IMAGE="${FIXED_IMAGE:-node:24.22.1}"
PROBE_TIMEOUT="${PROBE_TIMEOUT:-10}"
RESULTS_DIR="lab/results"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
OUT="$RESULTS_DIR/matrix-$STAMP.log"

mkdir -p "$RESULTS_DIR"

echo "== corpus generation inside $FIXED_IMAGE ==" | tee "$OUT"
docker run --rm -v "$PWD/lab:/lab" "$FIXED_IMAGE" node /lab/gen-control.js 2>&1 | tee -a "$OUT"

run_case() { # <image> <trigger-file>
  local img="$1" trig="$2"
  echo "== $img :: $(basename "$trig") ==" | tee -a "$OUT"
  docker run --rm -v "$PWD/lab:/lab" "$img" \
    timeout "$PROBE_TIMEOUT" node /lab/probe.js "/lab/triggers/$(basename "$trig")" 2>&1 | tee -a "$OUT"
  echo "exit=${PIPESTATUS[0]}" | tee -a "$OUT"
}

for img in "$VULN_IMAGE" "$FIXED_IMAGE"; do
  for trig in lab/triggers/*; do
    run_case "$img" "$trig"
  done
done

echo "== matrix written to $OUT =="
