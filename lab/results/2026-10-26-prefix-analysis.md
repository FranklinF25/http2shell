# Prefix-feed sweep — NEGATIVE result (2026-10-26 16:15 UTC)

Raw evidence: `prefix-matrix-20261026T161537Z.log`.
Pair: `node:24.22.0` (vulnerable) vs `node:24.22.1` (fixed). k = 1..13, wait
800 ms per k, writable side never ended, external timeout never reached.

## Observed (facts)

| corpus | image | k = 1..8 | k = 9..13 |
|---|---|---|---|
| hang13.br | v24.22.0 (vuln) | parked | error `ERR__ERROR_FORMAT_CL_SPACE`, errno -6 |
| hang13.br | v24.22.1 (fixed) | parked | error `ERR__ERROR_FORMAT_CL_SPACE`, errno -6 |
| control.br | v24.22.0 | parked | parked |
| control.br | v24.22.1 | parked | parked |

Every cell is identical across the pair. All exits 0, no timeouts, no output
bytes produced at any k.

## Conclusion

The prefix-feed hypothesis is **refuted for this corpus on the Node pair**:
there is no k* where the vulnerable build parks in NEEDS_MORE_INPUT while the
fixed build errors. Per spec S4 of `odd/tasks/prefix-oracle.md`, no oracle
ships from this result.

## Reading (why — interpretation)

- The park→error boundary at k=8→9 is the moment the stream header parse
  completes: with byte 9 the context-map coding is complete enough for the
  CL_SPACE (context-length space) validation to fire — on BOTH builds. This
  13-byte sequence's header is itself invalid for Node's bundled decoder, so
  the decoder never advances into metablock commands; the vulnerable
  block-switch handling is never reached on either build.
- Structural consequence: a fake NEEDS_MORE_INPUT through the vulnerable path
  requires a stream whose HEADER is valid (valid context maps and block
  counts) with the invalid block switch encoded inside the command stream —
  exactly what the ~23 MB trigger constructs with zero-output
  dictionary-transform commands. A small probe with an invalid header errors
  identically on both builds; a small probe with a valid header and no
  commands parks identically. This closes the "small stuck-state probe" idea
  for the Node zlib pair in BOTH feed regimes: whole-fed (matrix of
  2026-10-25) and prefix-fed (this sweep).
- Where the recorded "13-byte hang" can still live: other consumers of the
  same C decoder with different versions or feed paths — the brotli CLI pair
  (1.2.0/1.2.1), PyPI `Brotli` 1.2.0/1.2.1 wheels, Bun 1.4.3/1.4.4. Future
  work: replicate this exact sweep against those pairs; the harness
  (`lab/prefix-probe.js`, `lab/run-prefix.sh`) is image-agnostic via
  VULN_IMAGE/FIXED_IMAGE.

## Harness validation

- Negative control parked at every k on both images, exactly as predicted.
- Error codes captured verbatim (`ERR__ERROR_FORMAT_CL_SPACE`, errno -6).
- Corpus bytes are the committed verbatim files; nothing regenerated.
