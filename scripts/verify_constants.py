#!/usr/bin/env python3
"""Verify the constants vendored in fixtures/constants.json against the
implementations (scripts/mlkem_py.py, liboqs, pyca/cryptography) and the
pinned-tree audit record.

Usage: python3 scripts/verify_constants.py   (run from the pack root)
Exit code: 0 iff every constant matches.
"""

from __future__ import annotations

import contextlib
import gzip
import io
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import mlkem_py as C  # noqa: E402

with contextlib.redirect_stderr(io.StringIO()):
    import oqs as _oqs  # noqa: E402

from cryptography.hazmat.primitives.asymmetric import mlkem as _mlkem_mod  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.x25519 import (  # noqa: E402
    X25519PrivateKey)
from cryptography.hazmat.primitives.serialization import (  # noqa: E402
    Encoding, PublicFormat)

PACK_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FIX = os.path.join(PACK_DIR, "fixtures")


def main() -> int:
    with open(os.path.join(FIX, "constants.json")) as fh:
        consts = json.load(fh)
    n_ok = 0
    n_total = 0

    def check(label, got, want):
        nonlocal n_ok, n_total
        n_total += 1
        if got != want:
            print(f"FAIL {label}: got {got!r}, want {want!r}")
            return
        n_ok += 1
        print(f"OK {label}: {got!r}")

    # FIPS 203 Table 2 parameters, against the pure-Python implementation.
    for param, want in consts["parameter_sets"].items():
        p = C.PARAMS[param]
        for key in ("k", "eta1", "eta2", "du", "dv",
                    "ek_len", "dk_len", "ct_len"):
            check(f"{param}.{key}", p[key], want[key])
        check(f"{param}.ss_len", C.SS_LEN, consts["shared_secret_len"])
    check("q", C.Q, consts["q"])
    check("n", C.N, consts["n"])
    check("zeta", C.ZETA, consts["zeta"])

    # Same sizes, against liboqs's own metadata (independent implementation).
    for param, want in consts["parameter_sets"].items():
        with _oqs.KeyEncapsulation(param) as kem:
            d = kem.details
        check(f"liboqs {param}.ek_len", d["length_public_key"], want["ek_len"])
        check(f"liboqs {param}.dk_len", d["length_secret_key"], want["dk_len"])
        check(f"liboqs {param}.ct_len", d["length_ciphertext"], want["ct_len"])
        check(f"liboqs {param}.ss_len", d["length_shared_secret"],
              consts["shared_secret_len"])
        check(f"liboqs {param}.nist_category", d["claimed_nist_level"],
              want["nist_category"])

    # Same sizes, against pyca/cryptography (768/1024 only).
    for param, cls in (("ML-KEM-768", _mlkem_mod.MLKEM768PrivateKey),
                       ("ML-KEM-1024", _mlkem_mod.MLKEM1024PrivateKey)):
        want = consts["parameter_sets"][param]
        sk = cls.generate()
        pk = sk.public_key()
        check(f"pyca {param}.ek_len",
              len(pk.public_bytes(Encoding.Raw, PublicFormat.Raw)),
              want["ek_len"])
        ss, ct = pk.encapsulate()
        check(f"pyca {param}.ct_len", len(ct), want["ct_len"])
        check(f"pyca {param}.ss_len", len(ss), consts["shared_secret_len"])
        check(f"pyca {param}.round_trip", sk.decapsulate(ct) == ss, True)

    # X25519 sizes, against pyca/cryptography.
    x = consts["x25519"]
    a = X25519PrivateKey.generate()
    b = X25519PrivateKey.generate()
    check("x25519.public_key_len",
          len(a.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)),
          x["public_key_len"])
    check("x25519.shared_secret_len", len(a.exchange(b.public_key())),
          x["shared_secret_len"])

    # Hybrid wire sizes are arithmetic: 32 + the ML-KEM value.
    for param in consts["parameter_sets"]:
        want = consts["hybrid_wire"][param]
        p = consts["parameter_sets"][param]
        check(f"hybrid {param}.pk_len", want["hybrid_pk_len"],
              32 + p["ek_len"])
        check(f"hybrid {param}.ct_len", want["hybrid_ct_len"],
              32 + p["ct_len"])

    # Vector byte-lengths agree with Table 2.
    with gzip.open(os.path.join(FIX, "nist_keygen.json.gz"), "rt") as fh:
        kg = json.load(fh)
    for grp in kg["testGroups"]:
        param = grp["parameterSet"]
        want = consts["parameter_sets"][param]
        t = grp["tests"][0]
        check(f"KAT keygen {param}.ek_bytes", len(bytes.fromhex(t["ek"])),
              want["ek_len"])
        check(f"KAT keygen {param}.dk_bytes", len(bytes.fromhex(t["dk"])),
              want["dk_len"])

    # Pinned-tree TLS constants agree with the audit record.
    with open(os.path.join(FIX, "pinned_tree_audit.json")) as fh:
        audit = json.load(fh)
    rec = {c["cmd"]: c for c in audit["checks"]}
    tls = consts["pinned_tree_tls"]
    check("tls.default_cipher_list",
          rec["sed -n '104p' src/libxrpl/basics/make_SSLContext.cpp"]
          ["stdout"].strip(),
          f'std::string const defaultCipherList = "{tls["default_cipher_list"]}";')
    check("tls.context_method_sslv23",
          "sslv23" in rec["sed -n '349,360p' "
                          "src/libxrpl/basics/make_SSLContext.cpp"]["stdout"],
          True)
    check("audit.pinned_commit", audit["pinned_commit"],
          "0085a1ff885d6a446369cf73a4430f75af22be55")

    print(f"constants: {n_ok}/{n_total} OK")
    return 0 if n_ok == n_total else 1


if __name__ == "__main__":
    sys.exit(main())
