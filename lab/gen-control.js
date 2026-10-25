'use strict';
// Generates the trigger corpus inside the lab container. Docker-only
// convention: nothing security-relevant is generated or executed on the host.
const fs = require('fs');
const path = require('path');
const zlib = require('zlib');

const dir = '/lab/triggers';
fs.mkdirSync(dir, { recursive: true });

// Benign control: a valid brotli stream that must decode on every version.
// Sanity oracle for the harness itself — if this fails, the lab is broken,
// not the decoder under test.
const payload = Buffer.from('http2shell differential lab - benign control payload\n', 'utf8');
fs.writeFileSync(path.join(dir, 'control.br'), zlib.brotliCompressSync(payload));

// 13-byte hang trigger recorded verbatim in the research map (Engram #2427):
// drives the decoder into a state that reports NEEDS_MORE_INPUT.
fs.writeFileSync(path.join(dir, 'hang13.br'), Buffer.from('42008008010020820120000400', 'hex'));

console.log('corpus:', fs.readdirSync(dir).join(', '));
