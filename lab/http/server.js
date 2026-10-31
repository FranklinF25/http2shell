'use strict';
// Exposure endpoint for CVE-2026-111497 (HTTP2Shell) HTTP-path research.
// Express 5 + body-parser 2 with `inflate: true` (the default): incoming
// request bodies with `Content-Encoding: br` are decompressed by body-parser
// through Node's bundled Brotli decoder before any application code or
// authentication runs. This is the documented public exposure path.
//
// Runs INSIDE a pinned lab container, loopback network only. The explicit
// error handler surfaces body-parser's error type and message so a black-box
// client can classify responses; nothing else is exposed.

const express = require('express');
const bodyParser = require('body-parser');

const app = express();
const jsonParser = bodyParser.json({ inflate: true, limit: '64mb' });

app.get('/health', (req, res) => res.json({ ok: true }));

app.post('/json', jsonParser, (req, res) => {
  res.json({ ok: true, received: JSON.stringify(req.body ?? null) });
});

// Research error handler: keeps the parser's error classification visible.
// eslint-disable-next-line no-unused-vars
app.use((err, req, res, next) => {
  res.status(err.status || 500).json({
    error: err.type || 'unknown',
    message: String(err.message || ''),
  });
});

const server = app.listen(3000, () => {
  console.log(JSON.stringify({ listening: true, node: process.version, pid: process.pid }));
});
server.keepAliveTimeout = 0; // fail fast on decoder crashes
