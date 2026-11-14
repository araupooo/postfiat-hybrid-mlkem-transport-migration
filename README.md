# Hybrid ML-KEM Transport Migration Assessment

Assessment of migrating the PFTL peer-to-peer overlay transport to
hybrid classical-plus-ML-KEM key exchange, for the pinned postfiatd
tree `0085a1ff885d6a446369cf73a4430f75af22be55`.

## Headline

The pinned tree has **no key-exchange primitive at all** on the
transport path: peer TLS uses an anonymous context with an ephemeral
self-signed RSA certificate and `verify_none`, authentication happens at
the application layer via a secp256k1 session signature bound to the TLS
Finished messages, and there is no TLS group/curve configuration
anywhere — so there is no hook point where a hybrid group could be
selected today. A migration must add the KEM, the negotiation, and the
key storage; it cannot reuse the node identity (always secp256k1) as a
KEM key. The measured cost is small: the hybrid handshake is about
roughly 1.2–1.7x the classical handshake across repeated runs on the build machine (exact figures for this run: `results/timing_measurements.txt`).

## What was assessed

1. **Pinned-tree gap analysis** (K01–K13): inventory of the transport
   key-exchange and signing paths — what exists (TLS context
   construction, anonymous peer context, secp256k1 node identity and
   session signature, validator keys from config) and what is absent
   (ML-KEM, X25519, ECDH, KEM call sites, KEM config, KEM key storage)
   — with exact file:line citations recorded in
   `fixtures/pinned_tree_audit.json`.
2. **Handshake benchmarks** (K14–K23): wire sizes and timing for hybrid
   X25519+ML-KEM-512/768/1024 against the classical X25519 baseline,
   measured locally with liboqs and pyca/cryptography (200 iterations
   per operation).
3. **Negotiation and downgrade analysis** (K28–K30): a deterministic
   model (`scripts/negotiation.py`) of three policies
   (`require-hybrid`, `prefer-hybrid`, `allow-classical`) tested
   exhaustively against `fixtures/negotiation_matrix.json`, including
   transcript-hash downgrade detection and fail-closed rejections.
4. **Key-compromise response and rollback** (K31–K33): fresh ephemeral
   keys per handshake (forward secrecy), a rotation procedure that maps
   to config + restart, and a rollback plan that is policy-only.
5. **Correctness grounding** (K24–K27): HKDF combiner checks, NIST
   ACVP known-answer vectors reproduced by the pure-Python FIPS 203
   implementation, and cross-implementation agreement between
   pyca/cryptography, liboqs, and the pure-Python implementation.

## Results

- Harness: 33 checks (see `results/summary.txt` for the totals).
- Wire sizes: hybrid public key 832 / 1,216 / 1,600 bytes and hybrid
  ciphertext 800 / 1,120 / 1,600 bytes for ML-KEM-512/768/1024
  (vs 32 / 32 bytes classical).
- Handshake cost: exact medians and ratios for this run are in
  `results/timing_measurements.txt`; the assertions are in
  `results/summary.json` (`benchmarks_ms`) and
  `results/checks/K23.txt`. All three hybrid ratios are under the 20x
  bound; the X25519 operations dominate the hybrid total on this
  machine, and the ML-KEM operations add only ~0.04–0.09 ms.
- Findings: F-01 (Medium) and F-02 (Medium) are the two design
  constraints a migration must work around; F-03–F-05 are Low;
  F-06–F-08 are Informational. See `FINDINGS.md`.

## How to reproduce

```sh
bash run_all.sh
```

Regenerates every derived output offline from the vendored fixtures,
rebuilds `docs/index.html`, and verifies digests. Expected: exit 0,
`checks: 33 total, 33 passed, 0 failed`,
`constants: <N>/<N> OK`, `verify_digests.sh: <N> files OK, 0 failed`,
clean git status. See `REPRODUCTION.md` for the exact commands and
recorded results.

Dependencies (installed once by `run_all.sh` into `.venv` if the system
interpreter lacks them): `cryptography==50.0.2`,
`liboqs-python==0.16.0.2` (see `requirements.txt`).

## Files

- `README.md` — this file
- `REPRODUCTION.md` — exact reproduction commands and recorded results
- `SCOPE_MAP.md` — pinned-tree audit and integration points
- `FINDINGS.md` — prioritized findings with mitigations and limitations
- `claim_evidence_index.md` — every material claim mapped to a runnable
  check or a primary-source citation
- `SOURCES.md` — primary sources and fixture provenance
- `scripts/mlkem_py.py` — pure-Python FIPS 203 implementation (test-only)
- `scripts/negotiation.py` — deterministic negotiation/downgrade model
- `scripts/run_checks.py` — the local-fixture harness (33 checks)
- `scripts/verify_constants.py` — FIPS 203 / RFC 7748 constants check
- `scripts/build_derived.py` — builds `docs/index.html`
- `fixtures/` — NIST ACVP vectors, FIPS 203 constants, pinned-tree
  audit record, negotiation matrix
- `results/` — run log, summaries, per-check outputs, digest manifest
- `results/outputs/` — fresh clean-setup run logs (all batteries re-run)
- `docs/index.html` — rendered results page

## Limitations (honest)

- No live network was used. All handshake costs are local component
  measurements; no live peers, no network latency, no real TLS
  handshake was measured.
- Timing figures are machine-dependent; only orderings and the ratio
  bound are asserted.
- The pure-Python FIPS 203 implementation is test-only (not
  constant-time); timing was measured with liboqs (C).
- The negotiation/downgrade analysis is a deterministic model, not a
  wire implementation.
- Only the pinned commit was audited.
