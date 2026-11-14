# Scope map — Hybrid ML-KEM Transport Migration Assessment

Pinned postfiatd tree: `0085a1ff885d6a446369cf73a4430f75af22be55`
(tree: `/home/hatch/workspace/postfiatd-amendment/worktree-0085a1ff`).
All file:line citations below were verified against that commit and
are recorded verbatim in `fixtures/pinned_tree_audit.json`.

## What exists on the transport key-exchange path

| Component | Location | What it does |
| --- | --- | --- |
| TLS context construction | `src/libxrpl/basics/make_SSLContext.cpp:346–380` (`get_context`) | Builds the `ssl::context`: method `sslv23` (:350), floor TLS 1.2 via `no_tlsv1`/`no_tlsv1_1` (:353–359), fixed cipher list `TLSv1.2:!CBC:!DSS:!PSK:!eNULL:!aNULL` (:104), `use_tmp_dh` with fixed 2048-bit DH parameters (:369), renegotiation disabled (:375) |
| Anonymous context | `src/libxrpl/basics/make_SSLContext.cpp:107–247` (`initAnonymous`) | Ephemeral self-signed RSA-2048 certificate and key, generated in-process at startup (`defaultRSAKeyBits = 2048`, :66) |
| Authenticated context | `src/libxrpl/basics/make_SSLContext.cpp:249–344` (`initAuthenticated`) | Loads certificate/key/chain from PEM files; used for RPC/WebSocket, **not** for peer connections |
| Peer context wiring | `src/xrpld/overlay/detail/OverlayImpl.cpp:1550` | `setup.context = make_SSLContext("")` — peer connections use the **anonymous** context |
| Peer client handshake | `src/xrpld/overlay/detail/ConnectAttempt.cpp:175–183` | `verify_none`, then client `async_handshake` |
| Session-value binding | `src/xrpld/overlay/detail/Handshake.cpp:146–176` (`makeSharedValue`) | SHA-512 of local + peer TLS Finished messages, XORed, halved (`sha512Half`) |
| Handshake build | `src/xrpld/overlay/detail/Handshake.cpp:178–226` (`buildHandshake`) | `Public-Key` header (node public key), `Session-Signature` header (node key signs the shared value, :203–205) |
| Handshake verify | `src/xrpld/overlay/detail/Handshake.cpp:227–340` (`verifyHandshake`) | Requires a secp256k1 node public key (:294–295); verifies the session signature (:311–319) |
| Node identity | `src/xrpld/app/main/NodeIdentity.cpp:42–60` | Seed from `--nodeid` or `[node_seed]` (`ConfigSections.h:63`), or the wallet DB; keypair always secp256k1 (:54–55); loaded once at startup (`Application.cpp:1378`) |
| Digest signing | `src/libxrpl/protocol/SecretKey.cpp:230–256` (`signDigest`) | Requires secp256k1; ECDSA with RFC 6979 nonce |
| Digest verification | `src/libxrpl/protocol/PublicKey.cpp:239–310` (`verifyDigest`) | secp256k1 and ed25519 verification paths |
| Validator keys | `src/xrpld/app/misc/ValidatorKeys.h:37–69` | Keys loaded from the `[validator_token]` config section (`ConfigSections.h:96`) at startup, all-or-nothing |

## What is absent (gap analysis)

| Item | Evidence |
| --- | --- |
| ML-KEM / Kyber code | 0 files in the whole tree, 0 in `src/` (K02) |
| X25519 code | 0 files anywhere (K03) |
| ECDH in application code | 0 files in `src/xrpld` + `src/test`; the 27 whole-tree hits are the vendored `external/secp256k1/` library (26) and one research document (K03) |
| `KeyEncapsulation` symbol | 0 matches in `src/` (K04) |
| `postquantum` / `post-quantum` | 0 files anywhere (K04) |
| TLS group / curve configuration | 0 matches for `set1_groups\|set1_curves\|SSL_CTX_set1\|TLS1_3\|X25519MLKEM\|mlkem` in the TLS setup and the overlay (K08) |
| KEM config section | 0 `kem\|KEM` matches in `ConfigSections.h` (K12) |
| KEM key files / storage | 0 `*kem*` filenames in the tree (K13) |

## Integration points for a future migration

1. **`make_SSLContext.cpp` (`get_context`)** — where TLS groups would
   be configured (`SSL_CTX_set1_groups`) and where a hybrid group
   would be selected. Today it configures no groups at all.
2. **`OverlayImpl.cpp:1550`** — where the peer context is chosen; a
   migration that needs an authenticated (rather than anonymous)
   context for peers would change this line.
3. **`Handshake.cpp` (`buildHandshake` / `verifyHandshake`)** — where
   the negotiation transcript must be bound, the same way the
   Finished-message shared value is bound today.
4. **`NodeIdentity.cpp:54–55` + `SecretKey.cpp:230`** — the secp256k1-only
   constraint on the node identity and the session signature; a KEM key
   needs its own keypair and config section, not a reuse of the node
   identity.
5. **`ConfigSections.h`** — where a new KEM key section (e.g.
   `[kem_key]`) would be declared, following the `[validator_token]`
   pattern.

## Out of scope

- No live-network testing, no live peers, no TLS handshake was run
  against a real node. Handshake costs are local component
  measurements.
- No changes were made to the pinned tree (read-only audit).
- No wire implementation of the negotiation was written or tested; the
  negotiation analysis is a deterministic model
  (`scripts/negotiation.py`).
- The RPC/WebSocket TLS path (`make_SSLContextAuthed`, `WorkSSL.cpp`)
  was inventoried only to distinguish it from the peer path; the
  migration assessment covers the peer-to-peer overlay transport.
