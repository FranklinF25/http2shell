# prefix-oracle — prefix-feed differential oracle for CVE-2026-111497 (HTTP2Shell)

Second feature of the http2shell repo (X2Shell series #3). Research goal: test
whether feeding a k-byte PREFIX of the 13-byte hang trigger to a streaming
Brotli decoder — WITHOUT ending the writable side — yields a bounded-cost,
safe differential signal between vulnerable (node:24.22.0) and fixed
(node:24.22.1) builds. Hypothesis source: research map Engram #2427 (rev 3,
items 8b/9) and lab/results/2026-10-25-analysis.md follow-up note.

## Specs

- S1: "dale" — approves the exact proposal "arrancar la feature del oráculo prefix-feed" (chat, after the evening delta re-check), plus the constraint "continua pero no lances mas de 2 subagentes a la vez" (delegation concurrency cap: at most 2 subagents running at once).
- S2 (hypothesis, from #2427 rev 3 + analysis doc): for k = 1..12 of the hang13 trigger bytes (verbatim corpus already at lab/triggers/hang13.br), feed k bytes to a streaming brotli decoder, do NOT end the writable side, wait a bounded time. Expected shapes: vulnerable parks in NEEDS_MORE_INPUT ("parked", no event) while fixed errors cleanly at some k* — ideally `ERR__ERROR_FORMAT_BLOCK_SWITCH` (errno -17). If such k* exists, that is the bounded-cost safe differential oracle no public tool currently has (all entrants are version fingerprints, static code-path scanners, or the full 23MB trigger). Benign control (lab/triggers/control.br) prefixes must park on BOTH builds at every k (negative control).
- S3 (recorded lesson #2431, backlog item): container writes into the bind mount must not leave root-owned artifacts — the new runner (and any container invocation it performs) uses `--user "$(id -u):$(id -g)"`.
- S4: outcomes recorded verbatim to lab/results/prefix-matrix-*.log. If a divergence k* exists: ship a minimal oracle prototype (`lab/oracle.sh`) that answers vulnerable/fixed/unknown with bounded cost (k* bytes + timeout) and a check pinning its verdicts on both pinned images. If NO divergence exists: record the negative result and analysis honestly; no oracle ships.
- S5: process discipline carried over (feature doc L4 lesson): trigger byte sequences are never hand-retyped; existing corpus files are reused as-is.

## Tasks

| ID | Spec | Task | Route | Commit |
|----|------|------|-------|--------|
| T1 | S1 | ODD bootstrap: feature doc + Engram mirror + todo + feature branch | inline | (this doc) |
| T2 | S2,S3,S5 | `lab/prefix-probe.js` (per-k stream park/error sweep, no end()) + `lab/run-prefix.sh` (matrix runner, --user uid:gid, external timeout) | inline | pending |
| T3 | S2,S4 | Run the prefix matrix on node:24.22.0 / node:24.22.1 (hang13 + control sweeps), capture outcomes verbatim | inline | pending |
| T4 | S4 | Analysis doc; if k* exists: `lab/oracle.sh` prototype + verdict-pinning check; update README research lines if the niche result lands | inline | pending |
| T5 | S1 | Verification per risk tier (≤2 concurrent subagents), RDD assess → review if due, work-unit commits, close | inline | pending |

## Log

- L1 (2026-10-26, session http2shell): user approved after evening delta re-check: "dale" + "continua pero no lances mas de 2 subagentes a la vez" → this feature. Prior art state at start: niche (b) safe bounded-cost behavioral detector still unclaimed (#2427 rev 3 item 9); ~85-90 public repos; first in-the-wild recon (node2shell-check) observed by ELLIO.
