#!/usr/bin/env bash
# HTTP response-class differential matrix for CVE-2026-111497 (HTTP2Shell).
# Builds the Express 5 + body-parser 2 exposure endpoint on top of BOTH pinned
# Node images, starts them on an isolated docker network, and runs the
# original scanner client (methodology of the public node2shell-scanner)
# against both. Everything is loopback-lab only; results go to lab/results/.
#
# Env overrides: VULN_IMAGE, FIXED_IMAGE
set -uo pipefail
cd "$(dirname "$0")/.."

VULN_IMAGE="${VULN_IMAGE:-node:24.22.0}"
FIXED_IMAGE="${FIXED_IMAGE:-node:24.22.1}"
RESULTS_DIR="lab/results"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
OUT="$RESULTS_DIR/http-scan-$STAMP.log"
NET="http2shell-net-$STAMP"

mkdir -p "$RESULTS_DIR"

cleanup() {
  docker rm -f http2shell-vuln http2shell-fixed >/dev/null 2>&1 || true
  docker network rm "$NET" >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "== building endpoints (vuln=$VULN_IMAGE fixed=$FIXED_IMAGE) ==" | tee "$OUT"
docker build -q --build-arg BASE_IMAGE="$VULN_IMAGE" -t http2shell-http:vuln lab/http 2>&1 | tee -a "$OUT"
docker build -q --build-arg BASE_IMAGE="$FIXED_IMAGE" -t http2shell-http:fixed lab/http 2>&1 | tee -a "$OUT"

echo "== generating probe ==" | tee -a "$OUT"
docker run --rm --user "$(id -u):$(id -g)" -v "$PWD/lab:/lab" \
  "$FIXED_IMAGE" node /lab/gen-trigger.js /lab/triggers/blockswitch-flood.br 2>&1 | tee -a "$OUT"

docker network create "$NET" >/dev/null

echo "== starting endpoints ==" | tee -a "$OUT"
docker run -d --rm --name http2shell-vuln --network "$NET" http2shell-http:vuln >/dev/null
docker run -d --rm --name http2shell-fixed --network "$NET" http2shell-http:fixed >/dev/null

# Wait for both endpoints to listen (bounded).
for i in $(seq 1 30); do
  if docker run --rm --network "$NET" "$FIXED_IMAGE" node -e '
    const http = require("http");
    let left = 2;
    for (const h of ["http2shell-vuln", "http2shell-fixed"]) {
      http.get(`http://${h}:3000/health`, (r) => { r.resume(); done(); }).on("error", done);
    }
    function done() { if (--left === 0) process.exit(0); }
    setTimeout(() => process.exit(1), 2000);
  ' >/dev/null 2>&1; then break; fi
  sleep 1
done

echo "== scan ==" | tee -a "$OUT"
docker run --rm --network "$NET" -v "$PWD/lab:/lab:ro" "$FIXED_IMAGE" \
  timeout 300 node /lab/http/scan.js \
  --target vuln=http://http2shell-vuln:3000 \
  --target fixed=http://http2shell-fixed:3000 \
  --probe /lab/triggers/blockswitch-flood.br 2>&1 | tee -a "$OUT"
echo "exit=${PIPESTATUS[0]}" | tee -a "$OUT"

echo "== written to $OUT ==" | tee -a "$OUT"
