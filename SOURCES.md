# Sources

Primary sources only. Every measured or specification-derived claim in
this pack cites one of these, or a runnable check in `results/checks/`.

## Standards

- **NIST FIPS 203**, "Module-Lattice-Based Key-Encapsulation Mechanism
  Standard", published 13 August 2024, DOI 10.6028/NIST.FIPS.203.
  Parameter sets (Table 2: k, eta1, eta2, du, dv) and key/ciphertext
  sizes (Table 3: ML-KEM-512 800/1632/768/32, ML-KEM-768 1184/2400/
  1088/32, ML-KEM-1024 1568/3168/1568/32 bytes; shared secret 32 bytes).
  Section 8: "NIST recommends using ML-KEM-768 as the default parameter
  set." Verified against the standard text and reproduced by the
  pure-Python implementation against the NIST ACVP vectors (K25).
- **RFC 7748**, "Elliptic Curves for Security", section 5 (X25519):
  32-byte public keys and 32-byte shared secrets. Verified by the
  harness against pyca/cryptography (K17).
- **RFC 5869**, "HMAC-based Extract-and-Expand Key Derivation Function
  (HKDF)": the combiner construction. The harness's use (HKDF-SHA256,
  salt None, info `pftl-hybrid-handshake-v1`, input
  `x25519_ss || mlkem_ss`, 32-byte output) is the harness's own
  construction, not a standard-mandated one (K24).
- **FIPS 203 §7.2/§7.3** (KeyGen/Encaps/Decaps internal algorithms) and
  §4 (NTT, SampleNTT, ByteEncode/Decode): implemented by
  `scripts/mlkem_py.py` and validated against the ACVP vectors.

## Pinned tree (primary source for every in-tree claim)

- postfiatd, commit `0085a1ff885d6a446369cf73a4430f75af22be55`
  (tree: `/home/hatch/workspace/postfiatd-amendment/worktree-0085a1ff`).
  Exact commands and outputs recorded in
  `fixtures/pinned_tree_audit.json`; every file:line citation in this
  pack was verified against that commit.
- Key files: `src/libxrpl/basics/make_SSLContext.cpp`,
  `src/xrpld/overlay/detail/OverlayImpl.cpp`,
  `src/xrpld/overlay/detail/ConnectAttempt.cpp`,
  `src/xrpld/overlay/detail/Handshake.cpp`,
  `src/xrpld/app/main/NodeIdentity.cpp`,
  `src/libxrpl/protocol/SecretKey.cpp`,
  `src/libxrpl/protocol/PublicKey.cpp`,
  `src/xrpld/core/ConfigSections.h`,
  `src/xrpld/app/misc/ValidatorKeys.h`.

## Fixtures and provenance

- `fixtures/nist_keygen.json.gz`, `fixtures/nist_encapdecap.json.gz`:
  NIST ACVP (Automated Cryptographic Validation Protocol) ML-KEM
  test vectors (keyGen, encapsulation, decapsulation), public test
  data published by NIST. Used by K25 via the pure-Python FIPS 203
  implementation. Counts are reported per check in
  `results/checks/K25.txt`.
- `fixtures/constants.json`: FIPS 203 Table 2/3 values, RFC 7748
  sizes, hybrid wire sizes (arithmetic), and the pinned-tree TLS
  constants. Verified by `scripts/verify_constants.py` against the
  implementations and the audit record.
- `fixtures/pinned_tree_audit.json`: recorded audit run — 31 commands
  (greps, `git rev-parse`, `sed` line reads) with exact stdout, run
  against the pinned commit. The gap checks (K01–K13) verify this
  record and re-run the primary greps live when the tree is present.
- `fixtures/negotiation_matrix.json`: the expected-outcome table for
  the negotiation model (3 policies x 6 offer sets) and the policy
  rules R1–R6. The table is the specification; `scripts/negotiation.py`
  is the implementation; K28 checks one against the other.

## Implementations used for measurement

- **pyca/cryptography 50.0.2** (OpenSSL backend): ML-KEM-768/1024
  (ML-KEM-512 is not exposed by this library version) and X25519.
- **liboqs 0.16.0** via `liboqs-python 0.16.0.2`: ML-KEM-512/768/1024
  (FIPS 203 variants).
- **Pure-Python FIPS 203** (`scripts/mlkem_py.py`): written from the
  standard; test-only, not constant-time, never for real data.
  Validated against the NIST ACVP vectors (K25) and cross-checked
  against both libraries (K26).

## What was NOT used as a source

- No live network, no live peers, no production traffic.
- No secondary write-ups were used for any measured or
  specification-derived claim; web search was used only to confirm
  the FIPS 203 Table 2/3 values against the standard text, and the
  harness re-verifies those values against three implementations.
