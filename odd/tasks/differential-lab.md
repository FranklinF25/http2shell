# differential-lab — Docker differential lab for CVE-2026-111497 (HTTP2Shell)

X2Shell series repo #3 (php2shell → regex2shell → http2shell): security research on
CVE-2026-111497, OOB write in the Google Brotli C decoder 1.0.3–1.2.0 (CVSS 4.0 9.2).
This feature covers the ODD bootstrap plus the first deliverable: a Docker-only
differential lab on the vulnerable/fixed Node pair. Research map source: Engram #2427
(scoped to project regex2shell); handoff instructions: Engram #2428.

## Specs

- S1: "crea un repo publico con gh con el mismo nombre de este directorio sin descripcion ni readme" — public GitHub repo named after the working directory, no description, no README. DONE pre-feature: https://github.com/FranklinF25/http2shell (empty; local content not pushed).
- S2: "ahora revisa estos id de engram: 2427 y 2428" — load the research map and the handoff into this session. DONE pre-feature: both read and synthesized in chat.
- S3: "si dale" — authorizes the proposal quoted to the user verbatim: "Si me das el visto bueno, armo el feature doc inicial y el lab diferencial en Docker como primer paso" → ODD bootstrap + Docker differential lab as the first step of the project.
- S4 (series conventions from handoff #2428, technical parameters from #2427): Docker-only lab (nothing security-relevant runs on the host); differential pair "official node:24.22.0 vs 24.22.1 images"; first trigger corpus from #2427: a benign brotli control plus the 13-byte hang trigger `42008008010020820120000400`; fixed-side expected signal on write-path inputs: `BROTLI_DECODER_ERROR_FORMAT_BLOCK_SWITCH` (-17); the lab must record the observed behavior matrix verbatim — whether small probes distinguish patched from vulnerable is explicitly an open question in #2427, so the first run is an experiment, not a pass/fail oracle.

## Tasks

| ID | Spec | Task | Route | Commit |
|----|------|------|-------|--------|
| T1 | S3 | ODD bootstrap: feature doc + Engram mirror + todo + git init + feature branch + remote | inline | 6c8dbae (with T2) |
| T2 | S3,S4 | Docker lab harness: `lab/probe.js` (sync + stream modes), control generator, `lab/run.sh` matrix runner, Makefile; node:24.22.0 vs node:24.22.1, external `timeout` guard | inline | 6c8dbae |
| T3 | S4 | Run the differential matrix (control + hang13 on both images), capture outcomes with exit codes | inline | this commit (evidence: `lab/results/matrix-20261025T173535Z.log`) |
| T4 | S4 | Persist results (`lab/results/`), update Log with evidence, close tasks | inline | this commit (analysis: `lab/results/2026-10-25-analysis.md`) |

## Log

- L1 (2026-10-25 17:2x UTC, session http2shell): "crea un repo publico con gh con el mismo nombre de este directorio sin descripcion ni readme" → repo created with `gh repo create http2shell --public`, no description, no README; nothing pushed.
- L2 (2026-10-25): "ahora revisa estos id de engram: 2427 y 2428" → research map (#2427, discovery, 2 revisions) and handoff (#2428, session summary) loaded and synthesized; full technical chain available in-session.
- L3 (2026-10-25): "si dale" → authorizes ODD bootstrap + Docker differential lab as first step; this feature document created (4 specs, 4 tasks).
- L4 (2026-10-25, T2): near-miss — the hang13 hex literal was hand-typed into gen-control.js with a 1-byte transcription error (byte 10: 0x12 vs 0x20). Caught by machine comparison against #2427; correction now machine-enforced: verbatim value regex-extracted from the observation, files patched and verified by string equality. No hex in this repo is retyped by hand.
- L5 (2026-10-25, T3/T4): first matrix run (matrix-20261025T173535Z.log): control decodes identically both sides (harness sane); hang13 fed whole does NOT distinguish the pair — both error identically `ERR__ERROR_FORMAT_CL_SPACE` errno -6; no hang/spin/crash anywhere. Confirms #2427's "small probes cannot distinguish" for the Node pair. Open follow-up logged in analysis doc: prefix-feed oracle (feed k bytes, do not end, bounded wait) as candidate safe differential signal.
- L6 (2026-10-25, T4/T5): independent verifier (gentle-ai-verify) PASS on harness, determinism, analysis-doc accuracy, hex integrity, probe hygiene; FAIL on evidence hygiene: `.gitignore` `*.log` excluded the matrix logs from commit 94d88bd, so T3 evidence existed only on disk. Fix: negation `!lab/results/*.log`; original run + verifier rerun (observables identical) amended into the T3/T4 work-unit commit. Native assess tier: high (executable shell + docker process signals) → T5 review flow.
