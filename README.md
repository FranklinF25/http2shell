# http2shell

Security research on **CVE-2026-111497** (**HTTP2Shell**, a.k.a. Broccoli2Shell):
an out-of-bounds write in Google's Brotli C decoder (`c/dec/decode.c`), affecting
Brotli 1.0.3–1.2.0 (CVSS 4.0 **9.2**).

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

## Usage

Requires Docker. Everything runs inside pinned official images; nothing
security-relevant executes on the host.

```bash
bash lab/run.sh        # or: make lab
```

Each run regenerates the corpus inside a container and writes a timestamped
matrix log under `lab/results/`.

## Research lines

- **Prefix-feed oracle** — tested and NEGATIVE on the Node pair (2026-10-26):
  feeding k-byte prefixes of the 13-byte trigger without ending the stream
  parks identically (k ≤ 8) and errors identically at CL_SPACE (k ≥ 9) on
  both builds — header-invalid small probes can never reach the vulnerable
  branch. Bounded-cost behavioral detection on Node zlib via small probes is
  closed; remaining candidates are other decoder consumers (brotli CLI
  1.2.0/1.2.1, PyPI Brotli 1.2.0/1.2.1, Bun 1.4.3/1.4.4) and larger
  header-valid constructs. Evidence:
  [`lab/results/2026-10-26-prefix-analysis.md`](lab/results/2026-10-26-prefix-analysis.md).
- Safe differential detection of patched vs unpatched Brotli consumers.
- Deterministic single-shot remote exploitation (heap-side stabilization of
  the OOB write).
- Python-side exploitation (currently zero public PoCs).

## Fixed versions

Brotli 1.0.10 / 1.1.1 / 1.2.1 · Node 22.23.4 / 24.22.1 / 26.12.1 · Bun 1.4.4 ·
PyPI Brotli 1.2.1 / brotlicffi 1.2.1.0. If you depend on anything older,
upgrade.

## Ethics / scope

Defensive security research against **local, pinned lab images only**. The CVE
is public, fixes have shipped, and this repo contains research tooling for
differential detection and understanding of the bug — not attack
infrastructure.
