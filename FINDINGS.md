# Findings — Hybrid ML-KEM Transport Migration Assessment

Pinned postfiatd tree: `0085a1ff885d6a446369cf73a4430f75af22be55`.
Scope: the peer-to-peer overlay transport's key-exchange path, a
reproducible local-fixture handshake benchmark, a negotiation and
downgrade analysis, and a key-compromise response and rollback plan.
Every finding below is backed by a runnable check (see
`claim_evidence_index.md`) or a primary-source citation.

Severity scale: Critical = exploitable now, blocks migration; High =
blocks migration until fixed; Medium = must be designed around before
migration lands; Low = real cost or constraint, manageable; Informational
= recorded for completeness.

<!-- MATRIX-START -->
| ID | Severity | Status | Finding | Checks |
| --- | --- | --- | --- | --- |
| F-01 | Medium | CONFIRMED | No key-exchange primitive exists on the transport path: peer TLS uses an anonymous context with an ephemeral self-signed RSA certificate and verify_none, and no TLS group/curve/KEM configuration exists anywhere | K02, K03, K04, K06, K07, K08 |
| F-02 | Medium | CONFIRMED | Node identity is secp256k1-only and cannot serve as a KEM key; the session-signature binding (TLS Finished messages signed with the node key) is secp256k1-only | K09, K10, K11 |
| F-03 | Low | CONFIRMED | No KEM key storage or configuration exists; a new config section and a key-storage format are fresh design decisions | K12, K13, K32, K33 |
| F-04 | Low | CONFIRMED | Hybrid wire overhead is 25x/37x/49x (public key) and 24x/34x/49x (ciphertext) vs classical; a hybrid handshake carries ~1.2–1.6 KB of key material per direction | K18 |
| F-05 | Low | CONFIRMED | The negotiation model has no exact-parameter policy knob: require-hybrid accepts ML-KEM-512 and ML-KEM-1024 as well as ML-KEM-768; pinning 768 exactly needs an additional rule | K30 |
| F-06 | Informational | CONFIRMED | Hybrid handshake cost is roughly 1.2-1.7x the classical handshake across repeated runs on the build machine; the ML-KEM operations add only ~0.04-0.09 ms on top of the X25519 baseline, and the HKDF combiner is negligible | K19, K20, K21, K22, K23 |
| F-07 | Informational | CONFIRMED | Timing figures are machine-dependent; only the parameter-set orderings and the 20x ratio bound are asserted, so the harness passes on any reasonable machine | K19, K20, K21, K22, K23 |
| F-08 | Informational | CONFIRMED | The negotiation/downgrade analysis is a deterministic model, not a wire implementation; transcript binding on the wire depends on extending the Finished-message binding (K11) to cover the negotiation transcript, which is not yet designed | K28, K29, K30 |
<!-- MATRIX-END -->

## F-01 (Medium, CONFIRMED) — No key exchange on the transport path

**Evidence.** The pinned tree contains zero ML-KEM/Kyber files (K02),
zero X25519 files (K03), zero ECDH call sites in application code (K03:
the 27 ECDH hits are the vendored `external/secp256k1/` library plus one
research document), and zero `KeyEncapsulation` symbols in `src/` (K04).
Peer TLS is built in `src/libxrpl/basics/make_SSLContext.cpp` with a
fixed method (`sslv23`, :350), a fixed cipher list
(`"TLSv1.2:!CBC:!DSS:!PSK:!eNULL:!aNULL"`, :104), TLS 1.1 as the floor
(:353–359), a 2048-bit RSA ephemeral self-signed certificate
(`initAnonymous`, :107; `defaultRSAKeyBits = 2048`, :66), and fixed
2048-bit DH parameters (:80, :369). Peer connections use that anonymous
context (`OverlayImpl.cpp:1550`, `setup.context = make_SSLContext("")`)
with `verify_none` (`ConnectAttempt.cpp:175`), and no TLS group, curve,
or KEM configuration exists anywhere in the TLS setup or the overlay
(K08: 0 matches for `set1_groups|set1_curves|SSL_CTX_set1|TLS1_3|
X25519MLKEM|mlkem`).

**Impact.** There is no hook point where a hybrid group such as
X25519MLKEM768 could be selected today. A migration cannot be a
configuration change: it must add the KEM implementation, the group
negotiation, and the key storage. Conversely there is no ML-KEM attack
surface in-tree and no legacy KEM behaviour to preserve.

**Mitigation.** Add the KEM as a new, explicitly negotiated algorithm:
configure TLS groups explicitly (rather than relying on OpenSSL
defaults), and negotiate the hybrid group in the overlay handshake
before the TLS handshake completes, with the transcript bound the way
the session signature is bound today (see F-02).

## F-02 (Medium, CONFIRMED) — Node identity and session binding are secp256k1-only

**Evidence.** The node identity keypair is derived from the
`[node_seed]` seed (or the wallet DB) as secp256k1, unconditionally
(`NodeIdentity.cpp:54–55`; loaded once at startup,
`Application.cpp:1378`). `verifyHandshake` rejects any node public key
that is not secp256k1 (`Handshake.cpp:294–295`), and `signDigest`
refuses to sign a digest with anything but secp256k1
(`SecretKey.cpp:230–233`, `secp256k1_ecdsa_sign`, RFC 6979 nonce). The
session signature binds the TLS Finished messages to the node identity:
`makeSharedValue` (`Handshake.cpp:146–176`) XORs the SHA-512 hashes of
the local and peer Finished messages and halves the result; the node
key signs that value into the `Session-Signature` header
(`Handshake.cpp:203–205`); verification failure throws "Failed to verify
session" (`Handshake.cpp:318–319`).

**Impact.** The node identity cannot double as a KEM key, and the
session-signature binding cannot authenticate a hybrid handshake
without either keeping the secp256k1 binding alongside the KEM (the
recommended approach: the KEM establishes the session secret, the
existing signature still authenticates the peer) or changing both
`signDigest` and `verifyHandshake`. Any design that drops the
secp256k1 binding loses the proof that the TLS session is end-to-end
with the claimed node.

**Mitigation.** Keep the existing secp256k1 session signature as the
peer-authentication mechanism; use the hybrid KEM only for session-secret
establishment. Bind the negotiation transcript to the session the same
way the Finished messages are bound (hash the transcript into the
shared value, or sign it with the node key).

## F-03 (Low, CONFIRMED) — No KEM key storage or configuration exists

**Evidence.** No `[kem]` (or any KEM) config section exists
(`ConfigSections.h`: 0 `kem|KEM` matches, K12); no file in the tree is
named for a KEM (K13: 0 `*kem*` filenames); no KEM key is generated,
stored, loaded, or rotated anywhere (K02, K04). Validator keys follow
the config pattern (`[validator_token]`, `ConfigSections.h:96`;
`ValidatorKeys`, `ValidatorKeys.h:37`).

**Impact.** A migration must invent the key-storage format and the
config section. That is a fresh design decision with long-term
consequences (key file permissions, backup, rotation), not a reuse of
existing machinery.

**Mitigation.** Follow the existing `[validator_token]` pattern: a new
config section (e.g. `[kem_key]`) holding the KEM keypair, loaded once
at startup like the node identity. Rotation is then config + restart
(K32); rollback is policy-only (K33).

## F-04 (Low, CONFIRMED) — Hybrid wire overhead

**Evidence.** Hybrid public key = 32-byte X25519 key + ML-KEM
encapsulation key; hybrid ciphertext = 32-byte X25519 key + ML-KEM
ciphertext (K18). ML-KEM-512: 832 / 800 bytes; ML-KEM-768: 1,216 /
1,120 bytes; ML-KEM-1024: 1,600 / 1,600 bytes — 25x/37x/49x and
24x/34x/49x the classical 32-byte values.

**Impact.** A peer handshake grows by roughly 1.2–1.6 KB per direction
before any other handshake fields. On the overlay this is a one-time
per-connection cost, not a per-message cost, so it is tolerable; but
any handshake size limit or fragmentation assumption in the overlay
must be re-checked before migration.

**Mitigation.** Prefer ML-KEM-768 (the NIST recommended default, FIPS
203 §8) unless policy requires category 5: it is the smallest parameter
set with a large security margin. Measure the overlay's actual
handshake-size limits before landing the migration.

## F-05 (Low, CONFIRMED) — No exact-parameter policy knob

**Evidence.** The negotiation model (`scripts/negotiation.py`) accepts
any hybrid algorithm under `require-hybrid`; a peer offering only
ML-KEM-512 is accepted (K30). There is no policy variant that pins
ML-KEM-768 exactly.

**Impact.** An operator who must deploy exactly ML-KEM-768 (for
example, to match a fleet-wide policy or a compliance requirement)
cannot express that with the three policies as specified; a peer
offering only 512 would negotiate a weaker parameter set than intended.

**Mitigation.** Add an exact-match policy rule (reject any offer that
is not `X25519+ML-KEM-768`) as a fourth policy before deployment, and
test it the same way K28 tests the other three.

## F-06 (Informational, CONFIRMED) — Hybrid handshake cost is small

**Evidence.** Keygen, encapsulation, and decapsulation medians grow
monotonically with the parameter set (K19–K21), and the hybrid
handshake component sum was roughly 1.2-1.7x the classical X25519
across repeated runs on the build machine
handshake for every parameter set, under the 20x bound (K23; exact
figures in `results/summary.json` and `results/checks/K23.txt`). The
X25519 operations dominate the hybrid total on this machine; the
ML-KEM operations add only ~0.04-0.09 ms, and the HKDF combiner is
negligible next to both.

**Impact.** CPU cost is not a blocker for migration. On this machine
the X25519 operations dominate the hybrid total, so the parameter-set
choice (512 vs 768 vs 1024) moves the total by only ~0.02 ms; the
wire size (F-04), not CPU, is the main cost lever between parameter
sets.

## F-07 (Informational, CONFIRMED) — Timing is machine-dependent

**Evidence.** All timing figures are measured on the harness machine
(200 iterations per operation, 10 warmup) and recorded in
`results/timing_measurements.txt`, which is regenerated on every run.
The harness asserts only orderings (512 < 768 < 1024 by median) and
the 20x ratio bound, not absolute values (K19–K23).

**Impact.** Absolute millisecond figures will differ on other machines;
only the orderings and the ratio bound are portable claims. Re-run
`bash run_all.sh` on the target machine before citing absolute numbers.

## F-08 (Informational, CONFIRMED) — Negotiation analysis is a model

**Evidence.** The negotiation, downgrade, and compromise-response
analyses are a deterministic model (`scripts/negotiation.py`), tested
exhaustively against `fixtures/negotiation_matrix.json` (K28–K30). The
model is not a wire implementation, and the pinned tree contains no
negotiation code to test against.

**Impact.** The model proves the policy logic is sound (18/18 cells,
transcript-hash downgrade detection, fail-closed rejections), but it
does not prove a future wire implementation is correct. The transcript
binding on the wire depends on extending the Finished-message binding
(K11) to cover the negotiation transcript — a design step that is not
yet done.

**Mitigation.** When a wire implementation is written, bind the
negotiation transcript into the session signature (same mechanism as
K11) and re-run the K28–K30 model checks against the implementation's
actual negotiation outcomes.

## Recommended migration shape (derived from the findings)

1. **Parameter set:** ML-KEM-768 (NIST recommended default, FIPS 203
   §8; category 3, ~AES-192). 512 only for constrained peers; 1024
   only where policy requires category 5.
2. **Construction:** hybrid `X25519+ML-KEM`, combined with HKDF-SHA256
   over `x25519_ss || mlkem_ss` (info `pftl-hybrid-handshake-v1`),
   32-byte output (K24).
3. **Authentication:** keep the existing secp256k1 session signature;
   the KEM establishes the session secret only (F-02).
4. **Negotiation:** `require-hybrid` for new deployments,
   `prefer-hybrid` during transition (with the downgrade event
   recorded, K30), `allow-classical` for rollback (K33). Add an
   exact-768 policy variant before deployment (F-05).
5. **Keys:** new config section following the `[validator_token]`
   pattern; rotation is config + restart (K32); no KEM key material in
   the tree today (F-03).
6. **Transcript binding:** bind the negotiation transcript the way the
   TLS Finished messages are bound today (K11, F-08).

## Honest limitations

- There is no live network in this assessment. All handshake costs are
  local component measurements; no live peers were contacted and no
  network latency, packet loss, or real TLS handshake was measured.
- Timing figures are machine-dependent (F-07); only orderings and the
  ratio bound are asserted.
- The pure-Python FIPS 203 implementation (Impl C) is test-only: it is
  not constant-time and must never protect real data. Timing was
  measured with liboqs (C), not with Impl C.
- The negotiation/downgrade analysis is a model (F-08), not a wire
  implementation; a future implementation needs its own tests.
- The unknowns in this pack are: the overlay's actual handshake-size
  limits (F-04), and whether OpenSSL's TLS 1.3 defaults on the
  deployment hosts negotiate the expected groups (the tree does not pin
  them, K08).
- Only the pinned commit was audited. Any later commit may change the
  cited lines; the audit record is pinned to
  `0085a1ff885d6a446369cf73a4430f75af22be55`.
