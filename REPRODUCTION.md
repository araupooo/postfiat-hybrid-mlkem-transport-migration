# Reproduction

## Commands

From a fresh copy of this repository:

```sh
git clone <repo-url> hybrid-mlkem-repro
cd hybrid-mlkem-repro
bash run_all.sh
```

Expected output (exact figures for timing vary by machine; only the
orderings and the ratio bound are asserted):

```text
checks: 33 total, 33 passed, 0 failed
constants: <N>/<N> OK
verify_digests.sh: <N> files OK, 0 failed
run_all.sh: OK
```

and `git status` clean after the run.

To verify digests at any time without re-running the harness:

```sh
bash verify_digests.sh --check
```

Expected: every listed file `OK`, `0 failed`.

## What run_all.sh does, in order

1. `python3 scripts/run_checks.py` — runs all 33 checks from the
   vendored fixtures (local only; no network, no pinned tree needed),
   writes `results/run_log.txt`, `results/summary.json`,
   `results/summary.txt`, `results/checks/K*.txt`, `results/env.txt`.
   The log is captured to a temp file outside the pack first, then
   copied in.
2. `python3 scripts/verify_constants.py` — verifies
   `fixtures/constants.json` against the pure-Python FIPS 203
   implementation, liboqs metadata, pyca/cryptography sizes, and the
   pinned-tree audit record; writes
   `results/constants_verification.txt`.
3. `python3 scripts/build_derived.py` — rebuilds `docs/index.html`
   from `results/summary.json`, the run-log tail, and the findings
   matrix in `FINDINGS.md`.
4. Copies the run log, summaries, constants verification, and
   per-check outputs into `results/outputs/` (fresh clean-setup copies).
5. `bash verify_digests.sh` — regenerates `results/SHA256SUMS`
   (excluding `.git`, `.venv`, `__pycache__`, `results/SHA256SUMS`
   itself, `results/digest_check_output.txt`, and
   `results/reproduction_log.txt`); then `bash verify_digests.sh
   --check` verifies every listed file and writes
   `results/digest_check_output.txt`.

## Recorded results (this machine)

Recorded by the author on the build machine; re-running
`bash run_all.sh` on another machine reproduces the same check
outcomes (timing figures differ, as documented).

```text
checks: 33 total, 33 passed, 0 failed
constants: 70/70 OK
verify_digests.sh: 96 files OK, 0 failed
```

Exact timing figures for the recorded run are in
`results/timing_measurements.txt` (classical handshake ~0.19 ms;
hybrid handshakes ~0.26–0.29 ms; ratios ~1.4–1.6x; ML-KEM increments
~0.04–0.08 ms). That file is regenerated on every run and is
deliberately NOT covered by the digest manifest and NOT
version-controlled: wall-clock medians vary run to run on a shared
machine, and covering it would make a fresh-copy regeneration leave
`git status` dirty. The checks assert only the orderings (512 < 768 <
1024 by median) and the 20x ratio bound, which are stable; everything
else in the pack is byte-identical across runs.

Full per-check outputs: `results/checks/K01.txt` … `results/checks/K33.txt`
(and the fresh clean-setup copies in `results/outputs/`).

## Environment

- Python 3.12.3, Linux x86_64
- `cryptography==50.0.2` (pyca, OpenSSL backend)
- `liboqs-python==0.16.0.2` (liboqs 0.16.0)
- Pure-Python FIPS 203 implementation: `scripts/mlkem_py.py`
  (test-only, not constant-time)

`run_all.sh` creates `.venv` and installs `requirements.txt` the
first time if the system interpreter lacks the imports. `.venv/` is
excluded from the digest manifest and is never committed.

## Notes

- The harness never writes a file that the digest manifest covers
  while the manifest is being generated: run logs are captured outside
  the pack first, the derived page is built before digests run, and
  the digest-check output and reproduction log are excluded from the
  manifest. A fresh-copy regeneration therefore leaves `git status`
  clean.
- The pinned-tree audit (`fixtures/pinned_tree_audit.json`) records
  the exact commands and outputs of the audit run against commit
  `0085a1ff885d6a446369cf73a4430f75af22be55`. Where the tree is present
  on the machine, the gap checks re-run the primary greps live; where
  it is absent, the digest-checked audit record is verified instead.
