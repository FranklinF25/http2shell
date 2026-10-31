# http2shell

Security research on **CVE-2026-111497** (**Node2Shell** / HTTP2Shell /
Broccoli2Shell / Brotli2Shell): an out-of-bounds write in Google's Brotli C
decoder (`c/dec/decode.c`), affecting Brotli 1.0.3–1.2.0 (CVSS 4.0 **9.2**).

Part of the X2Shell research series (php2shell → regex2shell → http2shell).

## What is here right now

A **Docker-only differential lab** that probes Node's bundled Brotli decoder
across the vulnerable/fixed pair:

- `node:24.22.0` — vulnerable (vendored Brotli, pre-fix)
- `node:24.22.1` — fixed

`lab/probe.js` feeds each trigger to the decoder in two modes (one-shot sync and
streaming) and emits one structured JSON line per mode (`ok` / `error` /
`stream-silent`), always under an external `timeout` so decoder hangs and CPU
spins stay observable. `lab/run.sh` runs the full matrix across both images and
records every outcome to `lab/results/`.

### First matrix finding (2026-10-25)

The 13-byte "hang" trigger, fed whole and ended, **does not distinguish** the
pair: both images reject it identically with `ERR__ERROR_FORMAT_CL_SPACE`
(errno `-6`). This empirically confirms that small probes do not reach the
vulnerable branch through Node's zlib — a useful detection signal must come
from somewhere else. Raw evidence and reading:
[`lab/results/2026-10-25-analysis.md`](lab/results/2026-10-25-analysis.md).

## Public state (checked 2026-10-31)

Since 2026-10-22 the public picture changed substantially:

- **Root cause public**: the bug is in `DecodeBlockTypeAndLength()`. With a
  single block type (`num_block_types <= 1`) a block switch is illegal
  (RFC 7932) and the function returns `BROTLI_FALSE` without updating
  `block_length`. The fast path discards the return (CWE-252), `block_length`
  underflows to `UINT32_MAX` on the next decrement, and later
  `memmove16` writes past the ringbuffer (CWE-787). The safe (streaming)
  path misreads it as *needs more input* and locks at state 7/20 — the
  observable "hang" shape. The fix adds
  `BROTLI_DECODER_ERROR_FORMAT_BLOCK_SWITCH`.
  (Analysis: [m-compressors](https://m-compressors.github.io/2026/brotli-cve-2026-111497-mbrotli/),
  [Upwind](https://www.upwind.io/feed/http2shell-cve-2026-111497-one-brotli-bug-rce-across-the-http-stack).)
- **RCE on official builds**: [Imperva](https://www.imperva.com/blog/node2shell-from-brotli-data-to-remote-code-execution/)
  (arm64, via `fetch()` and Express 5 / body-parser 2) and
  [ELLIO](https://ellio.tech/en/blog/node2shell-cve-2026-111497-rce-on-stock-nodejs-builds/)
  (x86-64, official binaries, ASLR on, no debugger) both demonstrate code
  execution on stock `node:24.22.0`; `24.22.1` rejects the same inputs.
- **Exploited in the wild**: CISA warned of active exploitation on 2026-10-28;
  ELLIO sensors recorded a 23,069,983-byte exploit body targeting
  Node.js v24.22.0 x86-64 on 2026-10-26.
- **Detection state of the art** (`node2shell-scanner`, public): one-byte
  controls + a single ~23 MB Brotli probe (`Expect: 100-continue`) classified
  by endpoint response class. The ~23 MB size is not arbitrary: the public
  trigger mechanism floods 2^24 commands x 11 bits to force
  `block_length` exhaustion inside a header-valid stream.

These references explain our 2026-10-25/26 negative results: small
header-invalid probes die at `CL_SPACE` long before block-switch processing,
and in compliant streams `NBLTYPES=1` + the `MLEN` cap of 2^24 means
`block_length` never reaches 0 — a distinguishing signal requires a large,
crafted, header-valid stream.

## Usage

Requires Docker. Everything runs inside pinned official images; nothing
security-relevant executes on the host.

```bash
bash lab/run.sh        # small-probe matrix
bash lab/run-large.sh  # ~23 MB block-switch-exhaustion differential
bash lab/run-http.sh   # HTTP-path response-class/message oracle
```

Each run regenerates the corpus inside a container and writes a timestamped
matrix log under `lab/results/`.

## Research lines

- **Large-stream differential** — POSITIVE (2026-10-31): an original ~23 MB
  block-switch-exhaustion trigger (public technique, no copied code — the
  reference PoC repo is all-rights-reserved) yields the lab's first real
  differential, deterministic in all feed modes: vuln `Z_BUF_ERROR -5
  'unexpected end of file'` vs fixed `ERR__ERROR_FORMAT_BLOCK_SWITCH -17`.
  Through the full HTTP path (Express 5.3.0 + body-parser 2.3.0) both answer
  400 but the zlib message leaks into the response — a message-level
  black-box oracle, conditional on the app surfacing error details. Evidence:
  [`lab/results/2026-10-31-large-stream-analysis.md`](lab/results/2026-10-31-large-stream-analysis.md).
- **Prefix-feed oracle** — tested and NEGATIVE on the Node pair (2026-10-26),
  and now causally explained by the public root cause (see above): small
  header-invalid probes can never reach the vulnerable branch. Bounded-cost
  behavioral detection via small probes is closed. Evidence:
  [`lab/results/2026-10-26-prefix-analysis.md`](lab/results/2026-10-26-prefix-analysis.md).
- Deterministic single-shot remote exploitation (heap-side stabilization of
  the OOB write).
- Python-side exploitation (PyPI Brotli is confirmed affected; public PoCs
  target Node).

## Fixed versions

Brotli 1.0.10 / 1.1.1 / 1.2.1 · Node 22.23.4 / 24.22.1 / 26.12.1 · Bun 1.4.4 ·
PyPI Brotli 1.2.1 / brotlicffi 1.2.1.0. The affected surface is wider than
Node: Envoy, Istio, .NET 8–11, PHP-for-Windows, curl/libcurl builds, FFmpeg,
Apache Arrow, ClickHouse — anywhere a vulnerable Brotli is bundled or linked
([Tenable FAQ](https://www.tenable.com/blog/brotli2shell-frequently-asked-questions-for-google-brotli-decoder-cve-2026-111497),
[Akamai](https://www.akamai.com/blog/security-research/inside-node2shell-closer-look-cve-2026-111497)).
If you depend on anything older, upgrade.

## Ethics / scope

Defensive security research against **local, pinned lab images only**. The CVE
is public, fixes have shipped, and this repo contains research tooling for
differential detection and understanding of the bug — not attack
infrastructure.
