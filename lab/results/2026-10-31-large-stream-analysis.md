# Large-stream differential analysis — 2026-10-31

First real differential signal of this lab, obtained with an original
block-switch-exhaustion trigger (public technique, no third-party code), plus
an HTTP-path black-box oracle through Express 5 / body-parser 2.

Feature: `odd/tasks/large-stream-differential.md` (T1–T4, branch
`feat/large-stream-differential`).

## Trigger construction (lab/gen-trigger.js)

23,068,690-byte header-valid Brotli stream, 143-bit header:

- WBITS encoding `1,0(3),2(3)`; metablock `ISLAST=0`, `MNIBBLES` code 2
  (24 bits), `MLEN-1 = 0xFFFFFF` (MLEN = 2^24), `ISUNCOMPRESSED=0`.
- `NBLTYPESL = 1` and `NBLTYPESD = 1` (single-type categories: implicit block
  count 2^24, no switch trees — the vulnerable shape).
- `NBLTYPESC = 2` with a one-symbol TYPE tree (always type 0) and a
  one-symbol COUNT tree (symbol 25, 24 extra bits), initial command BLEN
  extra bits `0xFFFFFF`.
- `NPOSTFIX=3, NDIRECT=0`, no context maps (`NTREESL=NTREESD=1`), and
  single-symbol data trees: literal sym 0, command sym 130 (one tree per
  command block type), distance sym 184.
- Flood: exactly 2^24 commands, each 0-bit command symbol + 0-bit distance
  symbol + 11 bits of distance extra (value 4). 8 commands x 11 bits = 88
  bits = 11 bytes, so the flood is one repeating byte-aligned group.
  2^24 x 11 / 8 = 23,068,672 bytes + 18-byte header = 23,068,690 bytes.

Mechanism: every command consumes one distance code, so the implicit distance
block count (2^24) is exhausted exactly at the end of the flood. With
`NBLTYPESD = 1` that exhaustion is an illegal block switch for a single-type
category — the `DecodeBlockTypeAndLength()` condition of CVE-2026-111497.

The size (~23 MB) is structural, not arbitrary: the single-type block count
is 2^24 and each minimal command is 11 bits. This matches the public
ecosystem's trigger sizes (23,068,764 scanner probe; 23,069,983 ITW body).

## Result 1 — direct decoder differential (lab/run-large.sh)

Same input (sha256 `b7a6508e…`) on both images, three feed modes, two full
matrix runs (deterministic):

| Image | sync | stream-whole | stream-chunked |
| --- | --- | --- | --- |
| node:24.22.0 | `Z_BUF_ERROR` errno -5 "unexpected end of file" | same | same |
| node:24.22.1 | `ERR__ERROR_FORMAT_BLOCK_SWITCH` errno -17 | same | same |

Reading: the vulnerable build misreports the illegal block switch as
incomplete input (the CVE's unchecked-return flaw); the fixed build names it
with the dedicated post-patch error. Clean, deterministic, crash-free
differential in every feed mode. Evidence:
`lab/results/large-matrix-20261031T194046Z.log`,
`lab/results/large-matrix-20261031T194126Z.log`.

### Negative control — payload-shaped, not size-shaped

An all-zeros flood payload (`--dist-extra 0`, same 23,068,690 bytes) is
rejected identically by BOTH builds with `ERR__ERROR_FORMAT_CL_SPACE`
(errno -6). The differential depends on the flood carrying the correctly
shaped distance-extra bits (value 4), not on size alone.

## Result 2 — HTTP-path black-box oracle (lab/run-http.sh)

Express 5.3.0 + body-parser 2.3.0 (`json({inflate:true, limit:'64mb'})`) on
both pinned images, isolated docker network, original scanner client
(methodology of the public node2shell-scanner: four one-byte controls, one
full probe with `Expect: 100-continue`, stability re-check).

- All four controls: identical classes and bodies on both images (C2's byte
  `0x06` turned out to be a valid empty stream — both answered 200 `{}`,
  i.e. not a malformed control; both agreed, which is what matters here).
- Full probe: both answer HTTP 400, both servers stay healthy — **but the
  error message differs**:
  - vuln: `{"error":"unknown","message":"unexpected end of file"}`
  - fixed: `{"error":"unknown","message":"Decompression failed"}`
- The public class logic alone reports *not distinguishable* (a
  non-crashing probe never reaches the valid route-response class). The
  distinguishing signal is message-level: the zlib error text propagates
  through body-parser into the error-handler response.

Caveats (honest limits):

1. Message visibility depends on the application's error handler surfacing
   `err.message`; this lab endpoint does it deliberately. Production stacks
   that swallow error details would hide this oracle.
2. This construction never crashes the decoder, so it yields no
   crash-based class signal (unlike public weaponized PoCs, which target
   the fast-path OOB write). Detection here is diagnostic, not impact.
3. Timing (996 ms vs 1038 ms server-side) is noise-level and was not
   treated as a signal.

Evidence: `lab/results/http-scan-20261031T194429Z.log` (deterministic on a
second independent run: identical bodies and sha256s,
`lab/results/http-scan-20261031T194742Z.log`).

## Conclusions

1. The lab's first real differential signal exists and is cheap to read
   once you accept the ~23 MB probe cost: errno/message pair
   (-5 "unexpected end of file" vs -17 BLOCK_SWITCH) on any feed mode.
2. The signal survives the full HTTP exposure path as a message-level
   black-box oracle, conditional on error-handler verbosity.
3. The 2026-10-25/26 negative results are now fully explained: small
   header-invalid probes cannot reach the block-switch branch, and the
   exhaustion construction is inherently ~2^24 commands.
4. Licensing: the reference public PoC repo is all-rights-reserved; this
   feature's generator and scanner are original implementations of the
   published technique.

## Reproduce

```bash
bash lab/run-large.sh   # decoder-level matrix (sync/stream/stream-chunked)
bash lab/run-http.sh    # HTTP-path scanner methodology against both images
```
