'use strict';
// Feed a (potentially large) Brotli stream to Node's bundled decoder in one
// of three modes and print one structured JSON line with the outcome:
//
//   --mode sync           one-shot zlib.brotliDecompressSync
//   --mode stream-whole   zlib.createBrotliDecompress, end(buffer)
//   --mode stream-chunked zlib stream fed in bounded chunks with event-loop
//                         yields between writes (forces the safe path), end
//
// Failure shapes that matter for CVE-2026-111497:
//   error                 clean rejection with a code (e.g.
//                         ERR__ERROR_FORMAT_BLOCK_SWITCH on fixed builds)
//   stream-silent         decoder parked: no end, no error, no output event
//   (external timeout)    hard hang / CPU spin inside the C decoder
//   (exit 139/134)        memory-corruption crash inside the C decoder
//
// Usage: node probe-large.js <file> --mode <sync|stream-whole|stream-chunked>
//                            [--chunk-kb 64] [--wait-ms 20000]

const zlib = require('zlib');
const fs = require('fs');
const crypto = require('crypto');

const argv = process.argv.slice(2);
let file = null;
let mode = 'sync';
let chunkKb = 64;
let waitMs = 20000;
for (let i = 0; i < argv.length; i++) {
  const a = argv[i];
  if (a === '--mode') mode = argv[++i];
  else if (a === '--chunk-kb') chunkKb = parseInt(argv[++i], 10);
  else if (a === '--wait-ms') waitMs = parseInt(argv[++i], 10);
  else if (!a.startsWith('--') && file === null) file = a;
}
if (!file || !['sync', 'stream-whole', 'stream-chunked'].includes(mode)) {
  console.error('usage: node probe-large.js <file> --mode <sync|stream-whole|stream-chunked> [--chunk-kb N] [--wait-ms N]');
  process.exit(2);
}

const buf = fs.readFileSync(file);
const meta = {
  mode,
  node: process.version,
  inBytes: buf.length,
  sha256: crypto.createHash('sha256').update(buf).digest('hex'),
};

const emit = (kind, extra) => {
  console.log(JSON.stringify(Object.assign({ kind }, meta, extra || {})));
  if (pendingTimer) clearTimeout(pendingTimer);
  process.exit(0);
};
const errFields = (e) => ({
  name: e.name,
  code: e.code === undefined ? null : e.code,
  errno: e.errno === undefined ? null : e.errno,
  message: e.message,
});

let pendingTimer = null;

if (mode === 'sync') {
  try {
    const out = zlib.brotliDecompressSync(buf);
    emit('ok', { outBytes: out.length });
  } catch (e) {
    emit('error', errFields(e));
  }
} else {
  const stream = zlib.createBrotliDecompress();
  const chunks = [];
  let outBytes = 0;
  let settled = false;
  const finish = (kind, extra) => {
    if (settled) return;
    settled = true;
    emit(kind, extra);
  };
  stream.on('data', (c) => {
    outBytes += c.length;
    if (outBytes > (1 << 30)) stream.destroy(); // never exceed 1 GiB output
  });
  stream.on('end', () => finish('ok', { outBytes }));
  stream.on('error', (e) => finish('error', errFields(e)));

  pendingTimer = setTimeout(() => finish('stream-silent', { waitedMs: waitMs, outBytes }), waitMs);

  if (mode === 'stream-whole') {
    stream.end(buf);
  } else {
    const chunk = chunkKb * 1024;
    let off = 0;
    const writeNext = () => {
      if (settled) return;
      if (off >= buf.length) {
        stream.end();
        return;
      }
      const slice = buf.subarray(off, off + chunk);
      off += chunk;
      const ok = stream.write(slice);
      if (ok) {
        setImmediate(writeNext);
      } else {
        stream.once('drain', () => setImmediate(writeNext));
      }
    };
    setImmediate(writeNext);
  }
}
