# Claim-to-evidence index — Hybrid ML-KEM Transport Migration Assessment

Every material claim maps to a runnable check (`results/checks/Knn.txt`)
or a primary-source citation. "TESTED" claims were recomputed by the
harness from the vendored fixtures; "SOURCE-DERIVED" claims were verified
against the pinned tree and the audit record in
`fixtures/pinned_tree_audit.json`. Direct file links for the most-cited
artifacts: `claim_evidence_index.md` (this file),
`results/checks/K02.txt`, `results/checks/K06.txt`,
`results/checks/K11.txt`, `results/checks/K18.txt`,
`results/checks/K23.txt`, `results/checks/K28.txt`,
`results/checks/K31.txt`.

## Pinned tree

| Claim | Evidence |
| --- | --- |
| Pinned commit is 0085a1ff885d6a446369cf73a4430f75af22be55 | K01; `fixtures/pinned_tree_audit.json` |
| No ML-KEM/Kyber files anywhere in the tree (0 whole tree, 0 in src/) | K02; audit record |
| No X25519 files anywhere; no ECDH in application code (27 whole-tree ECDH hits confined to external/secp256k1/ + one research document) | K03; audit record |
| "encapsulat*" hits in src/ are non-KEM prose; no KeyEncapsulation symbol in src/ | K04; audit record |
| Signing only: ed25519 in 43 files, secp256k1 in 54 files under src/ | K05; audit record |
| TLS context: sslv23, floor TLS 1.2, cipher list "TLSv1.2:!CBC:!DSS:!PSK:!eNULL:!aNULL", RSA-2048 ephemeral self-signed cert, 2048-bit DH parameters, renegotiation disabled | K06; `src/libxrpl/basics/make_SSLContext.cpp:66,80,104,350,353-359,369,375` |
| Peer connections use the anonymous context; verify_none before the client handshake | K07; `src/xrpld/overlay/detail/OverlayImpl.cpp:1550`; `src/xrpld/overlay/detail/ConnectAttempt.cpp:175-176` |
| No TLS group/curve/KEM configuration exists in the TLS setup or the overlay | K08; audit record |
| Node identity is always secp256k1, from [node_seed] or the wallet DB, loaded once at startup | K09; `src/xrpld/app/main/NodeIdentity.cpp:54-55`; `src/xrpld/app/main/Application.cpp:1378`; `src/xrpld/core/ConfigSections.h:63` |
| Overlay handshake requires a secp256k1 node public key; signDigest requires secp256k1 | K10; `src/xrpld/overlay/detail/Handshake.cpp:294-295`; `src/libxrpl/protocol/SecretKey.cpp:230-233` |
| Session signature binds the TLS Finished messages to the node identity (shared value = sha512Half of XOR of the two Finished hashes) | K11; `src/xrpld/overlay/detail/Handshake.cpp:146-176,203-205,311-319` |
| Validator keys come from [validator_token]; no KEM config section exists | K12; `src/xrpld/core/ConfigSections.h:96`; `src/xrpld/app/misc/ValidatorKeys.h:37` |
| No KEM key storage or persistence paths in the tree | K13; audit record |

## Wire sizes and handshake cost

| Claim | Evidence |
| --- | --- |
| ML-KEM-512: ek 800, dk 1632, ct 768, ss 32 bytes (FIPS 203 Table 3) | K14; FIPS 203 Table 3; `fixtures/constants.json` |
| ML-KEM-768: ek 1184, dk 2400, ct 1088, ss 32 bytes (FIPS 203 Table 3; NIST recommended default) | K15; FIPS 203 Table 3, §8 |
| ML-KEM-1024: ek 1568, dk 3168, ct 1568, ss 32 bytes (FIPS 203 Table 3) | K16; FIPS 203 Table 3 |
| X25519: public key 32 bytes, shared secret 32 bytes (RFC 7748 §5) | K17; RFC 7748 §5 |
| Hybrid public key 832/1216/1600 bytes, hybrid ciphertext 800/1120/1600 bytes (512/768/1024) | K18; arithmetic from K14–K17 |
| Keygen/encaps/decaps medians grow monotonically with the parameter set (512 < 768 < 1024) | K19, K20, K21; `results/summary.json` (benchmarks_ms) |
| Classical X25519 handshake component sum (2x keygen + 2x exchange) | K22; `results/summary.json` |
| Hybrid handshake total is roughly 1.2-1.7x classical across repeated runs on the build machine, under the 20x bound | K23; `results/summary.json` |
| HKDF combiner is deterministic, 32-byte, domain-separated, and input-sensitive | K24; RFC 5869 |
| Impl C reproduces the NIST ACVP keyGen/encapsulation/decapsulation vectors for all three parameter sets | K25; `fixtures/nist_keygen.json.gz`, `fixtures/nist_encapdecap.json.gz` |
| liboqs and pyca/cryptography agree with Impl C on the wire format (cross-implementation encaps/decaps) | K26 |
| Encapsulate-then-decapsulate round trips pass (25/25 per parameter set per library) | K27 |

## Negotiation and downgrade

| Claim | Evidence |
| --- | --- |
| Negotiation model returns the expected outcome for all 18 (policy, offer) cells | K28; `fixtures/negotiation_matrix.json`; `scripts/negotiation.py` |
| Removing a hybrid algorithm from the offered list changes the transcript hash, so a downgrade is detectable | K29 |
| Mismatched hybrid / classical-only outcomes fail closed under require-hybrid; classical fallback under prefer-hybrid is recorded, not silent | K30 |
| The model has no exact-parameter policy knob; pinning ML-KEM-768 exactly needs an additional rule | K30 (NOTE in `results/checks/K30.txt`) |

## Compromise response and rollback

| Claim | Evidence |
| --- | --- |
| 100 hybrid handshakes produce 100 distinct encapsulation keys and 100 distinct shared secrets per parameter set | K31 |
| Every rotation step maps to a config change, an operator action, or a restart — no code change | K32; `scripts/negotiation.py` (ROTATION_STEPS) |
| Every rollback step is policy/config-only; rollback is reversible | K33; `scripts/negotiation.py` (ROLLBACK_STEPS) |

## Findings

| Finding | Evidence |
| --- | --- |
| F-01 (Medium): no key-exchange primitive on the transport path | K02, K03, K04, K06, K07, K08 |
| F-02 (Medium): node identity and session binding are secp256k1-only | K09, K10, K11 |
| F-03 (Low): no KEM key storage or configuration exists | K12, K13, K32, K33 |
| F-04 (Low): hybrid wire overhead 25x/37x/49x (pk) and 24x/34x/49x (ct) | K18 |
| F-05 (Low): no exact-parameter policy knob | K30 |
| F-06 (Informational): hybrid handshake cost is roughly 1.2-1.7x classical across repeated runs on the build machine | K19, K20, K21, K22, K23 |
| F-07 (Informational): timing is machine-dependent; only orderings and the ratio bound are asserted | K19, K20, K21, K22, K23 |
| F-08 (Informational): negotiation analysis is a model, not a wire implementation | K28, K29, K30 |
