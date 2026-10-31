# Feature: large-stream-differential

First real differential signal on the Node pair (node:24.22.0 vs node:24.22.1)
using a large (~23 MB) crafted Brotli stream built from the now-public block-switch
mechanics of CVE-2026-111497, plus an HTTP response-class detection harness, plus
README research-line updates with the new public references.

## Specs

- S1: "Actualizar el README (research lines) con las referencias nuevas: root cause, RCE en oficiales, ITW/CISA, scanner."
- S2: "Reproducir el diferencial del par con un stream grande generado a partir del mecanismo público (chunked vs one-shot en 24.22.0/24.22.1) — sería la primera señal diferencial real de nuestro lab."
- S3: "Replicar la metodología del scanner (clases de respuesta) contra nuestro par Docker."
- Constraint (user approval L1): all three items are authorized together ("si vamos con las 3").
- Constraint (licensing): the public PoC repo (dimasma0305/CVE-2026-111497-POC) is
  "All rights reserved" — no code may be copied. Our generator and scanner are original
  implementations of the published technique (RFC 7932 + public root-cause write-ups).
- Lab rule (established): everything security-relevant runs inside pinned official
  Docker images; the host only orchestrates.

## Tasks

- T1 (S1): Update README research lines with Oct 22–28 public references. Route: inline. Commit: 5c6572b.
- T2 (S2): Original large-stream generator (lab/gen-trigger.js) validated stage by
  stage against the fixed decoder's error codes; run one-shot + chunked matrix on the
  pair (lab/run-large.sh); record first differential if any. Route: inline (iterative
  binary crafting needs parent context). Risk: none (Docker-contained probing of our
  own pinned images; no host execution of trigger bytes). Commit: a930e0c.
  RESULT: first real differential — vuln Z_BUF_ERROR -5 'unexpected end of file' vs
  fixed ERR__ERROR_FORMAT_BLOCK_SWITCH -17, all three feed modes, deterministic
  (two full runs, same sha256). Negative control: all-zeros flood payload rejected
  CL_SPACE on both -> differential is payload-shaped, not size-shaped.
- T3 (S3): HTTP response-class harness: Express 5 + body-parser endpoint pinned in
  both images (lab/http/), plus an original scanner client (lab/http/scan.js)
  replicating the one-byte-controls + full-probe response-class methodology. Route:
  inline (depends on T2 generator). Risk: none (loopback-only servers).
- T4 (S2, S3): Analysis write-up in lab/results + close feature. Route: inline.

Slice boundary: T1+T2 = 538 authored lines (2 commits). T3 (HTTP harness) and
T4 (analysis) form the next slices; each behavior lands with its own commit.

## Log

- L1: "si vamos con las 3" — approving the three proposed next steps.
- L2 (evidence 2026-10-31): public research since last check: root cause =
  DecodeBlockTypeAndLength max_block_type<=1 / block_length underflow (fast path) or
  NEEDS_MORE_INPUT lock (safe path); trigger size ~23 MB = 2^24 commands x 11 bits;
  RCE on official builds (Imperva arm64 Oct 22, ELLIO x86-64 Oct 25); CISA active-
  exploitation warning Oct 28; ELLIO ITW sample 23,069,983 bytes; public scanner
  methodology = one-byte controls + ~23 MB probe with Expect: 100-continue + response
  classes. PoC repo license is all-rights-reserved: technique only, no code copying.
