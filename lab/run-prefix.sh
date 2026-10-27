#!/usr/bin/env bash
# Prefix-feed differential sweep for CVE-2026-111497 (see lab/prefix-probe.js).
# Sweeps k=1..13 prefixes of the hang13 trigger and the benign control across
# the vulnerable/fixed Node pair, recording every outcome verbatim.
#
# Docker-only: probes run inside pinned images under an external timeout.
# --user keeps any container write into the bind mount host-owned (lesson
# #2431: root-owned artifacts once blocked a merge).
#
# Env overrides: VULN_IMAGE, FIXED_IMAGE, WAIT_MS, TIMEOUT_S
set -uo pipefail
cd "$(dirname "$0")/.."

VULN_IMAGE="${VULN_IMAGE:-node:24.22.0}"
FIXED_IMAGE="${FIXED_IMAGE:-node:24.22.1}"
WAIT_MS="${WAIT_MS:-800}"
TIMEOUT_S="${TIMEOUT_S:-40}"
RESULTS_DIR="lab/results"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
OUT="$RESULTS_DIR/prefix-matrix-$STAMP.log"
MAX_K=13

mkdir -p "$RESULTS_DIR"
HOST_UID_GID="$(id -u):$(id -g)"

for img in "$VULN_IMAGE" "$FIXED_IMAGE"; do
  for trig in lab/triggers/hang13.br lab/triggers/control.br; do
    echo "== $img :: $(basename "$trig") (prefix sweep k=1..$MAX_K, wait ${WAIT_MS}ms, no end()) ==" | tee -a "$OUT"
    docker run --rm --user "$HOST_UID_GID" -v "$PWD/lab:/lab" "$img" \
      timeout "$TIMEOUT_S" node /lab/prefix-probe.js "/lab/triggers/$(basename "$trig")" "$WAIT_MS" "$MAX_K" 2>&1 | tee -a "$OUT"
    echo "exit=${PIPESTATUS[0]}" | tee -a "$OUT"
  done
done

echo "== written to $OUT =="
