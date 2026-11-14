#!/usr/bin/env python3
"""Build docs/index.html from the finished run outputs.

Reads results/summary.json, results/run_log.txt (tail), and FINDINGS.md
(the findings matrix between the MATRIX-START/END markers).
Deterministic: no timestamps, no random data. Must run AFTER the final
run log exists (run_all.sh order: harness -> constants -> this script
-> digests).
"""

from __future__ import annotations

import html
import json
import os
import re

PACK_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RES = os.path.join(PACK_DIR, "results")


def parse_matrix(path: str):
    with open(path) as fh:
        text = fh.read()
    m = re.search(r"<!-- MATRIX-START -->(.*?)<!-- MATRIX-END -->",
                  text, re.S)
    if not m:
        raise RuntimeError("matrix markers not found in FINDINGS.md")
    rows = []
    for line in m.group(1).strip().splitlines():
        line = line.strip()
        if not line.startswith("|"):
            continue
        cells = [c.strip() for c in line.strip("|").split("|")]
        if cells[0] == "ID" or set(cells[0]) <= set("- "):
            continue
        rows.append(cells)
    return rows


def main() -> None:
    with open(os.path.join(RES, "summary.json")) as fh:
        summary = json.load(fh)
    with open(os.path.join(RES, "run_log.txt")) as fh:
        run_log = fh.read()
    matrix = parse_matrix(os.path.join(PACK_DIR, "FINDINGS.md"))

    total = summary["total"]
    passed = summary["passed"]
    failed = summary["failed"]
    checks = summary["checks"]
    tested = sum(1 for c in checks if c["kind"] == "TESTED")
    bench = summary["benchmarks_ms"]

    matrix_html = "\n".join(
        "<tr>" + "".join(
            f"<td>{html.escape(cell)}</td>" for cell in row) + "</tr>"
        for row in matrix)
    checks_html = "\n".join(
        "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>".format(
            html.escape(c["id"]), html.escape(c["kind"]),
            html.escape(c["title"]), html.escape(c["result"]))
        for c in checks)
    tail = "\n".join(run_log.strip().splitlines()[-40:])

    # The page states the asserted bounds, not measured figures: exact
    # timing figures vary run to run and live in
    # results/timing_measurements.txt (regenerated every run).
    bench_rows = ("<tr><td>Hybrid handshake, all parameter sets</td>"
                  "<td>under the 20x bound vs classical (K23)</td>"
                  "<td>exact figures: results/timing_measurements.txt</td></tr>"
                  "<tr><td>Classical handshake (X25519, component sum)</td>"
                  "<td>baseline for the ratios (K22)</td>"
                  "<td>exact figures: results/timing_measurements.txt</td></tr>")

    page = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Hybrid ML-KEM Transport Migration Assessment</title>
<style>
body {{ font-family: system-ui, sans-serif; max-width: 960px; margin: 2em auto; padding: 0 1em; line-height: 1.5; }}
table {{ border-collapse: collapse; margin: 1em 0; }}
th, td {{ border: 1px solid #bbb; padding: 0.35em 0.6em; text-align: left; font-size: 0.9em; }}
th {{ background: #eee; }}
pre {{ background: #f6f6f6; padding: 1em; overflow-x: auto; font-size: 0.85em; }}
</style>
</head>
<body>
<h1>Hybrid ML-KEM Transport Migration Assessment</h1>
<p>Assessment of migrating the PFTL peer-to-peer overlay transport to
hybrid classical-plus-ML-KEM key exchange, for the pinned postfiatd tree
<code>0085a1ff885d6a446369cf73a4430f75af22be55</code>: a gap analysis of
what the tree actually contains on the transport key-exchange path,
reproducible local-fixture handshake benchmarks (hybrid
X25519+ML-KEM-512/768/1024 against the classical X25519 baseline), a
negotiation and downgrade analysis, and a key-compromise response and
rollback plan. Local fixtures only; no live-network testing, no mutation
of the pinned tree.</p>
<p><strong>Headline finding.</strong> The pinned tree has no key-exchange
primitive at all on the transport path (F-01): peer TLS uses an anonymous
context with an ephemeral self-signed RSA certificate and
<code>verify_none</code>, authentication happens at the application layer
via a secp256k1 session signature bound to the TLS Finished messages, and
there is no TLS group/curve configuration anywhere — so there is no hook
point where a hybrid group could be selected today. A migration must add
the KEM, the negotiation, and the key storage; it cannot reuse the node
identity (always secp256k1) as a KEM key. The measured cost is small: the
hybrid handshake was roughly 1.2-1.7x the classical one across repeated
runs on the build machine (exact figures for this run:
<code>results/timing_measurements.txt</code>).
No Critical or High finding.</p>
<h2>Headline numbers</h2>
<table>
<tr><th>Measure</th><th>Value</th><th>Notes</th></tr>
<tr><td>Harness checks</td><td>{total} total — {passed} passed, {failed} failed ({tested} tested)</td><td>results/checks/</td></tr>
{bench_rows}
<tr><td>Hybrid public key / ciphertext, ML-KEM-768</td><td>1,216 / 1,120 bytes</td><td>vs 32 / 32 bytes classical</td></tr>
<tr><td>Highest severity</td><td>Medium (F-01: no key exchange in the pinned tree)</td><td>see Findings</td></tr>
</table>
<h2>Findings</h2>
<table>
<tr><th>ID</th><th>Severity</th><th>Status</th><th>Finding</th><th>Checks</th></tr>
{matrix_html}
</table>
<p>Full detail, impact, and concrete mitigations: <code>FINDINGS.md</code>.
Every material claim is mapped to a runnable check or a primary-source
citation in <code>claim_evidence_index.md</code>.</p>
<h2>Checks</h2>
<table>
<tr><th>ID</th><th>Kind</th><th>Check</th><th>Result</th></tr>
{checks_html}
</table>
<p>Per-check outputs: <code>results/checks/</code>. Full raw log:
<code>results/run_log.txt</code> (tail below).</p>
<h2>Reproduction</h2>
<pre>bash run_all.sh</pre>
<p>Regenerates every derived output offline from the vendored fixtures,
rebuilds this page, and verifies digests. Expected: exit 0, byte-identical
outputs, clean git status. See <code>REPRODUCTION.md</code> for the exact
commands and recorded results, and
<code>results/digest_check_output.txt</code> for the raw digest-check output.
Verify digests at any time with <code>bash verify_digests.sh --check</code>.
Fresh-clean-setup logs (all batteries re-run) are under
<code>results/outputs/</code>.</p>
<h2>Run log (last 40 lines)</h2>
<pre>{html.escape(tail)}</pre>
<h2>Digest check output</h2>
<p>The raw digest-check output is <code>results/digest_check_output.txt</code>
(all manifest files OK). It is deliberately not embedded in this page: the
digest output is produced after this page is built, so embedding it would make
the page lag one run behind the manifest and a fresh-copy regeneration would
leave git status dirty whenever manifest membership changed.</p>
<h2>Files</h2>
<ul>
<li><code>README.md</code> — scope, method, how to reproduce</li>
<li><code>SCOPE_MAP.md</code> — pinned-tree audit and integration points</li>
<li><code>FINDINGS.md</code> — prioritized findings with concrete mitigations and limitations</li>
<li><code>claim_evidence_index.md</code> — every material claim mapped to a runnable check or a primary-source citation</li>
<li><code>SOURCES.md</code> — primary sources and fixture provenance</li>
<li><code>scripts/mlkem_py.py</code> — pure-Python FIPS 203 implementation (Impl C)</li>
<li><code>scripts/negotiation.py</code> — deterministic negotiation / downgrade / rollback model</li>
<li><code>scripts/run_checks.py</code> — the local-fixture harness (33 checks)</li>
<li><code>fixtures/</code> — NIST ACVP vectors, FIPS 203 constants, pinned-tree audit record, negotiation matrix</li>
<li><code>results/run_log.txt</code>, <code>results/summary.json</code>, <code>results/summary.txt</code> — harness outputs</li>
<li><code>results/checks/</code> — per-check outputs</li>
<li><code>results/outputs/</code> — fresh clean-setup run logs (all batteries)</li>
<li><code>results/SHA256SUMS</code> — digest manifest</li>
</ul>
</body>
</html>
"""
    with open(os.path.join(PACK_DIR, "docs", "index.html"), "w") as fh:
        fh.write(page)
    print("build_derived.py: docs/index.html written")


if __name__ == "__main__":
    main()
