'use strict';
// Differential probe for CVE-2026-111497 (HTTP2Shell) research.
// Feeds one brotli stream to Node's bundled zlib brotli decoder and prints one
// structured JSON line per decode mode. Runs INSIDE a pinned lab container,
// always under an external `timeout`, so both observable failure shapes are
// captured: a decoder blocked waiting for more input (stream-silent) and a
// decoder stuck in a C-level loop (killed by timeout, exit 124).
//
// Usage: node probe.js <file-or-hex>

const zlib = require('zlib');
const fs = require('fs');
const crypto = require('crypto');

const arg = process.argv[2];
if (!arg) {
  console.error('usage: node probe.js <file-or-hex>');
  process.exit(2);
}

let buf = null;
const looksLikeHex = /^[0-9a-fA-F]+$/.test(arg) && arg.length % 2 === 0 && arg.length <= 8192;
if (looksLikeHex && !fs.existsSync(arg)) {
  buf = Buffer.from(arg, 'hex');
} else {
  buf = fs.readFileSync(arg);
}

const meta = { node: process.version, inBytes: buf.length };
const line = (mode, kind, extra) =>
  console.log(JSON.stringify(Object.assign({ mode, kind }, meta, extra)));

// --- Mode 1: one-shot synchronous decode -------------------------------
try {
  const out = zlib.brotliDecompressSync(buf);
  line('sync', 'ok', {
    outBytes: out.length,
    sha256: crypto.createHash('sha256').update(out).digest('hex'),
  });
} catch (e) {
  line('sync', 'error', {
    name: e.name,
    code: e.code === undefined ? null : e.code,
    errno: e.errno === undefined ? null : e.errno,
    message: e.message,
  });
}

// --- Mode 2: streaming decode with a bounded wait ----------------------
// A fake NEEDS_MORE_INPUT from the vulnerable path never errors and never
// finishes: the transform just keeps waiting for bytes that will not come.
// That shape is reported as 'stream-silent' after WAIT_MS.
const WAIT_MS = 3000;
let settled = false;
let timer = null;
const finish = (kind, extra) => {
  if (settled) return;
  settled = true;
  if (timer) clearTimeout(timer);
  line('stream', kind, extra);
};

const stream = zlib.createBrotliDecompress();
const chunks = [];
stream.on('data', (c) => chunks.push(c));
stream.on('end', () => {
  const out = Buffer.concat(chunks);
  finish('ok', { outBytes: out.length, sha256: crypto.createHash('sha256').update(out).digest('hex') });
});
stream.on('error', (e) =>
  finish('error', {
    name: e.name,
    code: e.code === undefined ? null : e.code,
    errno: e.errno === undefined ? null : e.errno,
    message: e.message,
  })
);
stream.end(buf);
timer = setTimeout(() => finish('stream-silent', { waitedMs: WAIT_MS }), WAIT_MS);
