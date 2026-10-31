'use strict';
// Original black-box scanner client for CVE-2026-111497 (HTTP2Shell)
// research, replicating the public scanner METHODOLOGY (no third-party
// code): bounded one-byte controls to learn the endpoint's response
// classes, then a single full-size block-switch-exhaustion probe with
// `Expect: 100-continue`, then a control repeat for stability. The verdict
// follows the public class logic (vulnerable only when the full probe
// reaches the valid route-response class and the endpoint stays stable),
// but every raw signal — status, error type, message, timing — is recorded
// so pair differences at message level are visible too.
//
// Usage: node scan.js --target vuln=http://vuln:3000 --target fixed=http://fixed:3000
//                  [--probe /lab/triggers/blockswitch-flood.br] [--timeout-ms 60000]
// Runs inside a lab container on the lab network; targets are loopback-lab
// servers only.

const http = require('http');
const zlib = require('zlib');
const fs = require('fs');
const crypto = require('crypto');

function parseArgs(argv) {
  const out = { targets: [], probe: '/lab/triggers/blockswitch-flood.br', timeoutMs: 60000 };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--target') out.targets.push(argv[++i]);
    else if (a === '--probe') out.probe = argv[++i];
    else if (a === '--timeout-ms') out.timeoutMs = parseInt(argv[++i], 10);
  }
  if (!out.targets.length) {
    console.error('usage: node scan.js --target name=http://host:port [--probe FILE] [--timeout-ms N]');
    process.exit(2);
  }
  return out;
}

function request(urlStr, { method = 'POST', headers = {}, body = null, bodyFile = null, timeoutMs }) {
  return new Promise((resolve) => {
    const t0 = process.hrtime.bigint();
    const u = new URL(urlStr);
    const req = http.request(
      { hostname: u.hostname, port: u.port, path: u.pathname + u.search, method, headers },
      (res) => {
        const chunks = [];
        let n = 0;
        res.on('data', (c) => {
          if (n < 65536) chunks.push(c);
          n += c.length;
        });
        res.on('end', () => {
          const bodyBuf = Buffer.concat(chunks);
          resolve({
            status: res.statusCode,
            bodyBytes: n,
            bodyHead: bodyBuf.subarray(0, 256).toString('utf8'),
            bodySha256: crypto.createHash('sha256').update(bodyBuf).digest('hex'),
            elapsedMs: Number(process.hrtime.bigint() - t0) / 1e6,
          });
        });
      }
    );
    req.setTimeout(timeoutMs, () => req.destroy(new Error('client-timeout')));
    req.on('error', (e) =>
      resolve({ status: 0, error: e.code || e.message, elapsedMs: Number(process.hrtime.bigint() - t0) / 1e6 })
    );
    if (bodyFile) {
      // With Expect: 100-continue Node buffers writes until the server
      // confirms; that is the behavior under test.
      req.setHeader('Expect', '100-continue');
      const rs = fs.createReadStream(bodyFile);
      rs.on('error', (e) => req.destroy(e));
      rs.pipe(req);
    } else if (body !== null) {
      req.end(body);
    } else {
      req.end();
    }
  });
}

async function classifyTarget(name, urlStr, opts) {
  const valid = zlib.brotliCompressSync(Buffer.from('{"a":1}'));
  const cases = [];
  const push = (id, r) => cases.push(Object.assign({ id }, r));

  // Controls: one byte (or one tiny valid stream) each.
  push('C1-valid-brotli-json', await request(urlStr + '/json', {
    headers: { 'content-type': 'application/json', 'content-encoding': 'br' },
    body: valid, timeoutMs: opts.timeoutMs,
  }));
  push('C2-malformed-brotli', await request(urlStr + '/json', {
    headers: { 'content-type': 'application/json', 'content-encoding': 'br' },
    body: Buffer.from([0x06]), timeoutMs: opts.timeoutMs,
  }));
  push('C3-no-json-content-type', await request(urlStr + '/json', {
    headers: { 'content-type': 'text/plain', 'content-encoding': 'br' },
    body: valid, timeoutMs: opts.timeoutMs,
  }));
  push('C4-unsupported-encoding', await request(urlStr + '/json', {
    headers: { 'content-type': 'application/json', 'content-encoding': 'gzip' },
    body: zlib.gzipSync(Buffer.from('{"a":1}')), timeoutMs: opts.timeoutMs,
  }));

  // Full-size probe.
  push('P-full-probe', await request(urlStr + '/json', {
    headers: { 'content-type': 'application/json', 'content-encoding': 'br' },
    bodyFile: opts.probe, timeoutMs: opts.timeoutMs,
  }));

  // Stability control.
  push('C1b-valid-brotli-json', await request(urlStr + '/json', {
    headers: { 'content-type': 'application/json', 'content-encoding': 'br' },
    body: valid, timeoutMs: opts.timeoutMs,
  }));

  const cls = (r) => (r.status === 0 ? `conn:${r.error}` : `http:${r.status}:${r.bodyHead.slice(0, 120)}`);
  const validClass = cls(cases.find((c) => c.id === 'C1-valid-brotli-json'));
  const malformedClass = cls(cases.find((c) => c.id === 'C2-malformed-brotli'));
  const probeClass = cls(cases.find((c) => c.id === 'P-full-probe'));
  const stable = cls(cases.find((c) => c.id === 'C1b-valid-brotli-json')) === validClass;

  // Public verdict logic: the probe must reach the VALID route-response
  // class (i.e. the decoder accepted the stream far enough that the route
  // answered), the malformed class must be distinct, endpoint stable after.
  const probeReachedValidClass = probeClass === validClass;
  const verdict = probeReachedValidClass && malformedClass !== validClass && stable
    ? 'vulnerable-by-class-logic'
    : 'not-distinguishable-by-class-logic';

  return { target: name, url: urlStr, cases, classes: { validClass, malformedClass, probeClass }, stable, verdict };
}

async function main() {
  const opts = parseArgs(process.argv.slice(2));
  const results = [];
  for (const t of opts.targets) {
    const eq = t.indexOf('=');
    const name = t.slice(0, eq);
    const url = t.slice(eq + 1);
    const r = await classifyTarget(name, url, opts);
    results.push(r);
    console.log(JSON.stringify(r));
  }
  if (results.length >= 2) {
    const [a, b] = results;
    const signals = {};
    const maxLen = Math.max(a.cases.length, b.cases.length);
    for (let i = 0; i < maxLen; i++) {
      const ca = a.cases[i];
      const cb = b.cases[i];
      if (!ca || !cb) continue;
      const differs =
        JSON.stringify({ ...ca, elapsedMs: 0 }) !== JSON.stringify({ ...cb, elapsedMs: 0 });
      signals[ca.id] = {
        differs,
        vuln: { status: ca.status, error: ca.error || null, bodyHead: ca.bodyHead, elapsedMs: Math.round(ca.elapsedMs) },
        fixed: { status: cb.status, error: cb.error || null, bodyHead: cb.bodyHead, elapsedMs: Math.round(cb.elapsedMs) },
      };
    }
    console.log(JSON.stringify({ comparison: { targets: [a.target, b.target], signals } }));
  }
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
