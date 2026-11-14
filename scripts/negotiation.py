#!/usr/bin/env python3
"""Deterministic negotiation / downgrade / compromise-response model.

This module is the specification of the proposed hybrid handshake
negotiation, written as pure functions so the harness can test it
exhaustively. It is a MODEL, not a wire implementation: the pinned tree
contains no such negotiation code (see the gap analysis), and nothing here
claims to be a deployed protocol. Every rule is stated in
fixtures/negotiation_matrix.json and every outcome is checked against it.

Algorithm identifiers:
  "X25519"                classical-only
  "X25519+ML-KEM-512"     hybrid, ML-KEM-512
  "X25519+ML-KEM-768"     hybrid, ML-KEM-768 (preferred)
  "X25519+ML-KEM-1024"    hybrid, ML-KEM-1024

Policies:
  "require-hybrid"   accept only a hybrid algorithm; reject otherwise.
  "prefer-hybrid"    accept the strongest common hybrid; fall back to
                     classical only when the peer offers no hybrid, and
                     record a downgrade event.
  "allow-classical"  accept the strongest common algorithm, classical
                     included.

Transcript: SHA-256 of the canonical encoding of the offered algorithm
list (algorithms sorted by the preference order, joined with ",").
A downgrade attack that removes an algorithm from the offered list in
transit changes the transcript; the peer's signature over its own
transcript then fails to verify against the transcript the initiator
observed.
"""

from __future__ import annotations

import hashlib

ALGORITHMS = (
    "X25519",
    "X25519+ML-KEM-512",
    "X25519+ML-KEM-768",
    "X25519+ML-KEM-1024",
)

# Strongest first. ML-KEM-768 first: it is the NIST recommended default
# (FIPS 203 section 8); 1024 next (higher category); 512 next; classical last.
PREFERENCE_ORDER = (
    "X25519+ML-KEM-768",
    "X25519+ML-KEM-1024",
    "X25519+ML-KEM-512",
    "X25519",
)

POLICIES = ("require-hybrid", "prefer-hybrid", "allow-classical")

HYBRID = frozenset(
    {"X25519+ML-KEM-512", "X25519+ML-KEM-768", "X25519+ML-KEM-1024"})


def is_hybrid(algorithm: str) -> bool:
    return algorithm in HYBRID


def canonical_transcript(offered) -> bytes:
    """Canonical encoding of an offered-algorithm list.

    The list is sorted by the preference order and joined with commas.
    Two offer lists that differ in any element produce different bytes.
    """
    ordered = [a for a in PREFERENCE_ORDER if a in set(offered)]
    unknown = sorted(set(offered) - set(ALGORITHMS))
    if unknown:
        raise ValueError(f"unknown algorithm(s): {unknown}")
    return ",".join(ordered).encode("ascii")


def transcript_hash(offered) -> str:
    """SHA-256 hex digest of the canonical transcript."""
    return hashlib.sha256(canonical_transcript(offered)).hexdigest()


def negotiate(policy: str, peer_offers) -> dict:
    """Negotiate one handshake.

    Returns a dict with:
      outcome: "ACCEPT-HYBRID-<param>", "ACCEPT-CLASSICAL", or "REJECT"
      algorithm: the chosen algorithm, or None on rejection
      downgrade_event: True when a classical fallback was taken under
        prefer-hybrid (the fallback is recorded, not silent)
      reason: short human-readable reason
    """
    if policy not in POLICIES:
        raise ValueError(f"unknown policy: {policy}")
    offers = set(peer_offers)
    unknown = offers - set(ALGORITHMS)
    if unknown:
        raise ValueError(f"unknown algorithm(s): {sorted(unknown)}")

    common = [a for a in PREFERENCE_ORDER if a in offers]
    if policy == "require-hybrid":
        hybrid_common = [a for a in common if is_hybrid(a)]
        if not hybrid_common:
            return {"outcome": "REJECT", "algorithm": None,
                    "downgrade_event": False,
                    "reason": "require-hybrid: peer offers no hybrid algorithm"}
        return {"outcome": "ACCEPT-HYBRID-" + hybrid_common[0].split("+")[1],
                "algorithm": hybrid_common[0], "downgrade_event": False,
                "reason": "strongest common hybrid algorithm selected"}

    if policy == "prefer-hybrid":
        hybrid_common = [a for a in common if is_hybrid(a)]
        if hybrid_common:
            return {"outcome": "ACCEPT-HYBRID-" + hybrid_common[0].split("+")[1],
                    "algorithm": hybrid_common[0], "downgrade_event": False,
                    "reason": "strongest common hybrid algorithm selected"}
        if "X25519" in offers:
            return {"outcome": "ACCEPT-CLASSICAL", "algorithm": "X25519",
                    "downgrade_event": True,
                    "reason": "no hybrid offered; classical fallback with "
                              "downgrade event recorded"}
        return {"outcome": "REJECT", "algorithm": None,
                "downgrade_event": False,
                "reason": "peer offers no usable algorithm"}

    # allow-classical
    if not common:
        return {"outcome": "REJECT", "algorithm": None,
                "downgrade_event": False,
                "reason": "peer offers no usable algorithm"}
    chosen = common[0]
    if is_hybrid(chosen):
        return {"outcome": "ACCEPT-HYBRID-" + chosen.split("+")[1],
                "algorithm": chosen, "downgrade_event": False,
                "reason": "strongest common algorithm selected"}
    return {"outcome": "ACCEPT-CLASSICAL", "algorithm": "X25519",
            "downgrade_event": False,
            "reason": "classical is the only common algorithm"}


def detect_downgrade(offered_by_peer, transcript_seen_by_initiator) -> bool:
    """Return True when the observed transcript differs from the peer's.

    The peer signs (or otherwise binds) the transcript of the algorithm
    list it actually offered. If an attacker removed a hybrid algorithm
    from the list in transit, the initiator's transcript hash will not
    match the peer's, and the downgrade is detected.
    """
    return transcript_hash(offered_by_peer) != transcript_seen_by_initiator


# ---------------------------------------------------------------------------
# Compromise response and rollback: step tables.
#
# Each step maps to a concrete mechanism in the pinned tree (config section
# or startup code path) or to a documented operator action. A step that
# required a code change would be flagged by the harness; the migration
# design keeps every step config- or policy-only.
# ---------------------------------------------------------------------------

# Rotation steps for a compromised KEM decapsulation key. Each entry:
# (step, mechanism, pinned-tree anchor)
ROTATION_STEPS = [
    ("1. Revoke the compromised KEM key in the operator's key inventory "
     "(the key itself is never stored in the tree).",
     "operator action",
     "no KEM key material exists in the tree (gap analysis K02/K13)"),
    ("2. Generate a fresh ML-KEM keypair for the affected parameter set.",
     "operator action (offline)",
     "ML-KEM key generation is a library operation; no tree code involved"),
    ("3. Publish the new encapsulation key in the operator's peer "
     "configuration (the new [kem] config section the migration adds).",
     "config change",
     "config sections are declared in src/xrpld/core/ConfigSections.h; "
     "validator keys already follow this pattern via [validator_token] "
     "(ConfigSections.h:96)"),
    ("4. Restart the node so the new key is loaded at startup.",
     "restart",
     "node identity and keys are loaded once at startup: "
     "src/xrpld/app/main/Application.cpp:1378 "
     "(nodeIdentity_ = getNodeIdentity(...))"),
    ("5. Old sessions are unaffected: each handshake used fresh ephemeral "
     "keys, so a compromised long-term KEM key does not retroactively "
     "expose past sessions.",
     "forward secrecy (ephemeral keys)",
     "harness check K31: every handshake iteration generates fresh "
     "ephemeral keys and distinct shared secrets"),
]

# Rollback steps from hybrid to classical-only operation. Every step is
# config/policy only; no code change and no tree modification is required.
ROLLBACK_STEPS = [
    ("1. Change the local negotiation policy from require-hybrid (or "
     "prefer-hybrid) to allow-classical.",
     "policy change",
     "policy is a local operator setting, not tree code"),
    ("2. Peers that still offer hybrid algorithms keep negotiating hybrid; "
     "peers that do not fall back to classical X25519.",
     "negotiation model",
     "scripts/negotiation.py negotiate('allow-classical', ...)"),
    ("3. No tree code is removed or changed: the tree contains no KEM code "
     "to remove, and the hybrid code path lives outside the pinned tree "
     "until a migration lands.",
     "no code change",
     "gap analysis K02: 0 ML-KEM files in the pinned tree"),
    ("4. Re-enable hybrid later by reversing step 1; no key material is "
     "invalidated by the rollback.",
     "policy change",
     "negotiation model; no persistent KEM state in the tree"),
]
