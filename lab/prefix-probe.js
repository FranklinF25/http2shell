'use strict';
// Prefix-feed oracle sweep for CVE-2026-111497 (HTTP2Shell) research.
// For k = 1..maxK: feed the FIRST k bytes of the trigger to a fresh streaming
// Brotli decoder WITHOUT ending the writable side, wait a bounded time, and
// record what happened. Outcome kinds:
//   'error'  — the decoder rejected those bytes (code/errno verbatim)
//   'parked' — no event within the wait window: the decoder returned
//              NEEDS_MORE_INPUT and is waiting for bytes that never come
//   'ok'     — decoded fully without end() (not expected for this corpus)
// Differential hypothesis (Engram #2427): at some k* the fixed build errors
// (ideally ERR__ERROR_FORMAT_BLOCK_SWITCH, errno -17) while the vulnerable
// build parks. Runs INSIDE a pinned lab container under an external timeout.
//
// Usage: node prefix-probe.js <file> [waitMs] [maxK]

const zlib = require('zlib');
const fs = require('fs');

const file = process.argv[2];
if (!file) {
  console.error('usage: node prefix-probe.js <file> [waitMs] [maxK]');
  process.exit(2);
}
const WAIT_MS = Number(process.argv[3] || 800);
const buf = fs.readFileSync(file);
const MAX_K = Math.min(Number(process.argv[4] || buf.length), buf.length);

const meta = { node: process.version, inBytes: buf.length, waitMs: WAIT_MS };
const line = (prefixBytes, kind, extra) =>
  console.log(JSON.stringify(Object.assign({ prefixBytes, kind }, meta, extra)));

let k = 1;
const next = () => {
  if (k > MAX_K) process.exit(0);
  const stream = zlib.createBrotliDecompress();
  let settled = false;
  let outBytes = 0;
  let parkTimer = null;
  const done = (kind, extra) => {
    if (settled) return;
    settled = true;
    clearTimeout(parkTimer);
    stream.destroy();
    line(k, kind, Object.assign({ outBytes }, extra));
    k += 1;
    setImmediate(next);
  };
  stream.on('data', (c) => { outBytes += c.length; });
  stream.on('end', () => done('ok', {}));
  stream.on('error', (e) => done('error', {
    name: e.name,
    code: e.code === undefined ? null : e.code,
    errno: e.errno === undefined ? null : e.errno,
    message: e.message,
  }));
  stream.write(buf.subarray(0, k)); // deliberately NO end(): the oracle's core
  parkTimer = setTimeout(() => done('parked', {}), WAIT_MS);
};
next();
