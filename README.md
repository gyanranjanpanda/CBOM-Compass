# CBOM Compass

**Cryptographic inventory and post-quantum readiness platform** — SIH25164 · Cybersecurity

Finds every cryptographic asset an organisation runs, works out which ones a quantum computer breaks
and which ones a regulator disallows first, and hands back a prioritised migration list in a
standard format.

Full specification: [`docs/cbom-compass-prd.md`](docs/cbom-compass-prd.md) (PRD v1.1).

---

## Quick start

```bash
python3 -m venv .venv && .venv/bin/pip install -e ".[dev]"
.venv/bin/python -m cbom_compass.cli serve --policy crypto-policy.yaml
```

Open http://127.0.0.1:8000 and you land on **New scan**. Drop a `.zip` of your
codebase onto the page, or type a public repository URL — `github.com/psf/requests` —
and the inventory, risk heat map, recommendations and CycloneDX 1.7 export are
built from it. No terminal needed after the server is up.

```bash
./demo.sh          # or: seed two scans from real upstream repos and open the dashboard
```

That seeds two scans so the drift view has real content, starts a local TLS
endpoint for the live-endpoint scanner, writes `demo-cbom.json` and
`demo-risk-summary.pdf`, and serves the dashboard on http://127.0.0.1:8000.
`./demo.sh --no-serve` does everything except the dashboard.

Manually:

```bash
python3 -m venv .venv && .venv/bin/pip install -e ".[dev]"

# scan the bundled sample environment
.venv/bin/python -m cbom_compass.cli scan samples/vulnerable-app \
    --policy samples/vulnerable-app/crypto-policy.yaml \
    -o cbom.json --format cbom

# open the dashboard
.venv/bin/python -m cbom_compass.cli serve --policy samples/vulnerable-app/crypto-policy.yaml
```

There are no hard external tool dependencies. `syft` is used for container SBOMs when it is on
`PATH` and substituted for with a built-in layer walk when it is not, so a demo machine without it
still produces a complete result.

`semgrep` and `sslyze` are **not** integrated. Both appear in the PRD's stack and both are Phase 2:
semgrep needs purpose-written crypto rules rather than an off-the-shelf ruleset, and sslyze needs
driving as a library to enumerate every accepted cipher suite rather than just the negotiated one.
They are named here rather than stubbed, because a stub that shells out and discards the output is
worse than an honest gap.

Note that the SSH scanner does not have the equivalent gap. SSH announces every algorithm it will
accept in its opening `SSH_MSG_KEXINIT`, before anything is negotiated, so reading one message gives
the complete accepted set — the enumeration sslyze has to work for on the TLS side.

The live cloud and hardware connectors need their SDKs, which are optional extras so that a plain
install stays small:

```bash
pip install -e ".[connectors]"    # boto3, azure-keyvault-keys, google-cloud-kms, python-pkcs11
```

### Demoing the live-endpoint scanner

```bash
.venv/bin/python samples/tls_demo_server.py &          # self-signed RSA-2048 on 127.0.0.1:8443
.venv/bin/python -m cbom_compass.cli scan --tls 127.0.0.1:8443 \
    --policy samples/vulnerable-app/crypto-policy.yaml
```

Probing anything outside `scanning.allowlist` in the policy is **refused**, not warned about.
Without that gate this is just a network scanner pointed at arbitrary hosts.

### Other commands

```bash
cbom-compass scan --repo github.com/psf/requests    # clone and scan a public repository
cbom-compass scan ./repo --container myimage:latest --tls host:443 --cloud aws://us-east-1
cbom-compass scan --ssh jump.internal:22                  # offered kex/host-key/cipher/MAC set
cbom-compass scan --cloud azure://kv-payments-prod        # Azure Key Vault
cbom-compass scan --cloud gcp://my-project/global         # GCP Cloud KMS
cbom-compass scan --cloud pkcs11:///usr/lib/softhsm/libsofthsm2.so   # any PKCS#11 HSM/TPM
cbom-compass scan --cloud file://samples/hsm-export.json  # HSM demo without a token
cbom-compass scan ./repo --z 2040          # override the quantum-arrival estimate
cbom-compass diff <old-scan-id> <new-scan-id>
cbom-compass validate cbom.json
```

---

## What it does

**Discovery.** Eight source types, each normalised into one de-duplicated inventory.

| Source | Technique | Confidence |
|---|---|---|
| Source code | Python via stdlib `ast` (resolves literal key sizes, curves, modes); Java, JS/TS, Go, **C/C++**, **C#/.NET** and **Rust** via pattern rules | high / medium |
| Configuration | `sshd_config`, strongSwan `ipsec.conf`/`swanctl.conf`, OpenVPN, nginx/Apache TLS, S/MIME. Protocol cryptography that no AST walk and no manifest can reach | medium |
| Dependencies | Manifest parsing against a crypto-library knowledge base | high on version |
| Binaries | LIEF parses the import table (ELF `DT_NEEDED`, Mach-O `LOAD_DYLIB`, PE descriptors) for linked libraries and imported crypto functions; symbol names often carry the key size and mode too (`EVP_aes_128_gcm`). Byte scanning is the fallback for statically-linked or stripped binaries, at lower confidence | high / medium |
| Containers | Layer walk plus **embedded key and certificate discovery** — the find nothing else makes | high |
| Live TLS | TLS handshake probing, allowlist-gated | high (ground truth) |
| Live SSH | `SSH_MSG_KEXINIT` read over a raw socket: the **complete offered set** of kex, host-key, cipher and MAC algorithms, not one negotiated suite. The handshake is abandoned before key exchange — never authenticated, no credential sent | high (ground truth) |
| Cloud / hardware | AWS KMS, Azure Key Vault and GCP Cloud KMS over read-only metadata APIs; **PKCS#11** for any HSM or TPM (SoftHSM, Luna, nCipher, Utimaco, YubiHSM, CloudHSM, tpm2-pkcs11); or a key-store export as JSON for demoing without credentials or a token | high |

Two things in that table are load-bearing rather than box-ticking.

*Hardware modules* get their own `location_class`, not a shared one with cloud KMS. A key confined
to a token cannot be re-issued by an application team — the vendor must ship firmware that implements
ML-KEM or ML-DSA first, then it must be re-certified, then installed in a change window. So an HSM
key inherits the **embedded** migration estimate (5 years), making it a *harder* migration than the
same algorithm in application code, not an easier one. Managed cloud keys stay on the short estimate,
because AWS already exposes ML-DSA parameter sets and a managed key rotates on request.

*Hybrid key exchange* is declared, not inferred, wherever the identifier says so. `mlkem768x25519-sha256`
names its own pairing, so both halves are emitted and linked explicitly. That matters because an
`sshd_config` lists hybrid and non-hybrid key exchanges on the same line: inferring from co-location
would discount a bare `curve25519-sha256` sitting next to a migrated one, marking a genuinely exposed
key exchange as already done.

**Assessment.** Two independent clocks, because only one of them is a guess:

- *Quantum* — Shor-broken (RSA/DSA/DH/ECDSA/ECDH), classically broken, deprecated, or adequate.
- *Regulatory* — NIST IR 8547 (RSA/ECC deprecated after 2030, disallowed after 2035) and CNSA 2.0.

**Classification.** Mosca's inequality, made computable — see below.

**Recommendation.** FIPS 203/204/205/206 and SP 800-208, hybrid by default, ranked by risk score,
bandwidth budget, support maturity, compliance regime, and rotation cost computed from the asset
graph.

---

## Three design decisions worth knowing about

### 1. AES-128 and SHA-256 are classified *adequate*

The popular claim that Grover halves symmetric security is an oversimplification we deliberately do
not implement. Grover needs ~2⁶⁴ **sequential** quantum operations and parallelises poorly (m
machines buy only √m); the relevant attack on hash collision resistance is Brassard–Høyer–Tapp, a
cube-root speedup that is not practically better than the classical birthday bound. NIST defines its
own PQC security-strength categories *using* AES-128 and SHA-256 as reference points.

Classifying them as "weakened" would put every hash call in the codebase into the act-now bucket and
bury the RSA findings that matter. Where AES-256/SHA-384 is genuinely required it surfaces as a
**CNSA 2.0 policy flag**, not as a quantum break.

### 2. The priority score is a formula, not a boolean

Mosca's inequality returns true or false, and a boolean times a weight gives two buckets rather than
a ranking. The signed **exposure gap** preserves *how badly* an asset fails:

```
exposure_gap  = (X + Y) − Z_years          # positive ⇒ already overdue
urgency       = clamp(exposure_gap / URGENCY_SCALE, 0, 1)
compliance    = how close the nearest NIST IR 8547 deadline is (0 → 1 as it approaches)
vulnerability = 1.0 broken · 0.8 deprecated · 0.3 policy-only · 0.0 adequate
timing        = max(urgency, compliance, TIMING_FLOOR)
risk          = vulnerability × timing × (0.6 + 0.4 × hndl)
score         = risk × criticality_weight
```

**Timing modulates a real need to migrate; it never creates one.** An earlier version took a flat
`max()` across three peer axes, and a real scan of paramiko put its already-migrated **ML-KEM key
exchange at 0.60** purely because SSH session keys protect long-lived access — exactly the false
urgency this tool exists to avoid. If there is nothing to migrate, no timeline makes it urgent.

The floor works in the other direction: 3DES protecting session data is still worth replacing, so
timing never drops to zero.

Compliance pressure **rises as the deadline approaches** rather than sitting at 1.0 from the day the
rule was published. A flat 1.0 pinned every broken asset to the same score, which left Mosca unable
to distinguish between them — and distinguishing between them is the entire point of Mosca. The
result is that the same RSA-2048 scores **1.00 protecting 25-year data and 0.36 protecting session
data**.

One consequence is worth saying out loud, because it looks like a bug otherwise: **moving the Z
slider does not change the score of an RSA key**, because NIST's dates do not depend on anyone's
Q-Day estimate. Every classification records which axis drove it, and the dashboard says so
explicitly rather than leaving the slider looking dead.

### 3. X, Y and criticality are human inputs, and are labelled as such

No static analyser can know that a given AES call protects 25-year defence secrets, and dependency
depth is a poor proxy for migration effort — a deeply-nested dependency is often *easier* to fix
(bump a version) than a shallow one (rewrite in-house protocol code).

So `X` and criticality come from service tags in a checked-in `crypto-policy.yaml`, `Y` comes from a
rule table on asset type × deployment surface, and anything falling back to a default is stored with
`x_source: assumed` and **badged in the UI**. An honest "we assumed 7 years, click to change" is
more defensible to an auditor than a confident number with no provenance.

---

## Architecture

```
inputs → scanners → CBOM store → risk & recommendation engines → dashboard
                    (identity merge, drift)   (Mosca, NIST clocks, PQC rules)
```

| Module | Role |
|---|---|
| `knowledge/algorithms.py` | Algorithm risk knowledge base — the classification corrections live here |
| `knowledge/mosca.py` | X defaults by data class, Y rule table, HNDL rule |
| `knowledge/libraries.py` | Library → algorithms; binary signatures and symbol maps |
| `scanners/` | One module per source type; a failure degrades to a per-source error |
| `inventory.py` | Asset identity and cross-source de-duplication |
| `risk.py` | Mosca scoring, the two clocks, driver attribution |
| `recommend.py` | PQC/hybrid rule base with the five ranking criteria |
| `cbom.py` | CycloneDX 1.7 export and conformance validation |
| `report_pdf.py` | Board/compliance PDF summary, leading with assumptions and limits |
| `evaluate.py` | Precision and recall against the labelled corpus |
| `engine.py` | Orchestration, KPIs, drift diffing |
| `api.py` / `web/` | FastAPI + dashboard (no build step) |
| `store.py` | Scan snapshots and the audit log |

**Standard output.** CycloneDX **1.7**, ratified as **ECMA-424 2nd Edition** (Dec 2025) — not the
1.6 / 1st Edition assumed in PRD v1.0. Algorithm naming uses the Cryptography Registry introduced in
1.7, and `nistQuantumSecurityLevel` is populated as a native schema field rather than duplicated
into our extension namespace. Risk and recommendation data ride alongside under `cbom-compass:`.

**Store.** The PRD names Postgres + JSONB; this MVP uses SQLite with the same JSON-document shape, so
the move is a connection-string change. Nothing depends on SQLite-specific behaviour.

---

## Code intake

The dashboard accepts work two ways, both of which land in `cbom_compass/ingest.py`.

| Route | Endpoint | Accepts |
|---|---|---|
| Upload | `POST /api/scan/upload` | `.zip`, `.tar.gz`, `.tgz`, or one source file |
| Repository | `POST /api/scan/repo` | Public repo on github / gitlab / bitbucket / codeberg |

Uploads are the untrusted edge of the system, so extraction is written out
rather than delegated to `ZipFile.extractall`, which performs none of these
checks:

- **Path traversal** — every member is resolved against the extraction root and
  refused if it escapes. Absolute paths, `..` segments, backslash separators and
  Windows drive letters are all covered.
- **Decompression bombs** — the ceiling is enforced against bytes actually
  *read*, not the size declared in the archive header, which the attacker
  controls. 200 MB compressed in, 800 MB extracted, 64 MB per file, 40 000 entries.
- **Symlinks** — never materialised from an archive, and stripped from a clone
  afterwards. Otherwise `config -> /etc/shadow` gets read and quoted back as
  evidence.
- **SSRF** — an arbitrary git URL reaches cloud metadata endpoints and the
  `ext::` transport runs shell commands. Only https on an allowlisted host, no
  credentials, no submodules, and the ambient git config is not read.

Extracted trees are **kept** under `.cbom-workspace/`, not deleted. `verify`
re-reads each finding from the artefact on disk to prove it was not fabricated,
and that guarantee disappears if the tree is thrown away when the scan ends.
Retention is capped at the 20 most recent trees.

---

## Security model

The output of this tool is a ranked, filterable list of an organisation's weakest cryptography — an
attacker's shopping list, pre-sorted. It also ingests KMS and HSM credentials. So:

- Cloud/HSM connectors require **read-only, least-privilege** roles; never `Decrypt`, never `Sign`.
- Live probing is gated on an explicit **target allowlist** plus a recorded authorization attestation.
- `Z`, criticality weights and the allowlist are **`risk_officer`-only** — they change every score in
  the system. `auditor` is read/export only.
- Every settings change and every export is written to an **audit log**; exports are the primary
  exfiltration path.
- Discovered private keys are recorded as **fingerprint and location only**, never the key bytes.

---

## Proving the findings are real

```bash
.venv/bin/python -m cbom_compass.cli --db demo.db verify --sample 0
```

A scan report is a claim. `verify` re-opens each artefact on disk and checks the claim against it,
using nothing from the scan except the location it pointed at — and quoting the line, so a sceptic
can repeat any check by hand:

```
PASS  ML-KEM        targets/paramiko/paramiko/kex_mlkem.py:90
      > self.mlkem_key.public_key().public_bytes_raw()
PASS  AES-256-CBC   /usr/bin/ssh contains 'EVP_aes_256_cbc': True
PASS  RSA-1024      targets/golang-crypto/acme/autocert/autocert_test.go:649
      > rsaKey, err := rsa.GenerateKey(rand.Reader, 1024)
```

It uses a deliberately different method from the scanner — coarse corroboration patterns and raw
byte reads rather than AST parsing — so agreement means two independent techniques reached the same
answer.

**A verifier that confirms everything proves nothing**, so
`tests/test_verify.py::test_fabricated_findings_are_rejected` plants algorithms that are *not* at
the claimed location and asserts every one is reported UNCONFIRMED. Anchoring a real algorithm to
the wrong line must fail too.

Running it against real code is how the comment-matching bug was found: a finding anchored to
`//private static final String RSA_ENC_OID = ...` in jjwt — a commented-out declaration. Dead code
is not cryptography in use, and filtering comments removed 14 false positives.

## Measured accuracy

```bash
.venv/bin/python -m cbom_compass.cli eval
```

Against `corpus/` — 92 usages hand-labelled from source across seven languages, plus seven negative
controls that mention cryptography in prose and identifiers while performing none:

| Metric set | Precision | Recall | F1 |
|---|---|---|---|
| **algorithm** (did we notice the usage) | 100.0% | 97.5% | 0.99 |
| **strict** (key size, mode and curve too) | 98.9% | 96.7% | 0.98 |

Per language, algorithm-level: C 100% / 100%, C# 100% / 100%, Go 100% / 100%, Java 100% / 100%,
JS 100% / 100%, Python 100% / 92.0%, Rust 100% / 100%. Zero findings on the negative controls.

`tests/test_evaluate.py` derives the required language list from the scanner's own rule table, so
adding a language without labelling a corpus for it fails the suite rather than shipping an
unmeasured claim.

Every remaining miss is in `corpus/python/hard_dynamic.py` — algorithm names read from the
environment, key sizes from variables, `getattr(hashlib, ...)` indirection. Those are labelled as
expected findings and counted as misses rather than excluded, because hiding a limitation is not the
same as not having one. `tests/test_evaluate.py` asserts that no miss appears anywhere else.

Building the corpus found seven real bugs, including Triple-DES being reported as single DES
(`des-ede3-cbc` resolving via its `des` prefix) and every pycryptodome cipher mode being dropped.
Details in [`corpus/README.md`](corpus/README.md).

## Tests

```bash
.venv/bin/python -m pytest tests/ -q
```

140 tests, including **browser smoke tests** that render every view in headless
Chromium. Those exist because the asset graph once shipped completely blank —
every API returned 200 and the JS parsed cleanly, and only looking at the page
catches that. `test_ui.py` skips itself if Playwright is not installed
(`.venv/bin/playwright install chromium`). The ones worth reading first are the invariants that are easy to get wrong:

- `test_classification.py` — AES-128 and SHA-256 stay adequate; RSA-1024 is *insufficient*, not
  "already broken"; 3DES fails on block size, not on a break.
- `test_inventory.py` — one OpenSSL from three scanners collapses to one asset, while two RSA-2048
  call sites in different services stay separate.
- `test_engine.py::test_kpis_reconcile_with_the_inventory` — the Overview totals must equal the
  Inventory Explorer row count, which is the failure most likely to be spotted live.
- `test_scanners.py::test_tls_refuses_targets_outside_the_allowlist` — refused, not warned.
- `test_api.py::test_pinned_assets_hold_when_z_moves` — regulation-pinned scores must not drift.
- `test_api.py::test_graph_clusters_rather_than_truncating` — every asset stays represented in the
  graph; the long tail is clustered, never dropped.
- `test_cloud.py::test_scanner_stays_within_read_only_apis` — the KMS connectors are asserted,
  against recording fake clients for AWS, Azure and GCP, never to call anything beyond
  describe-level APIs.
- `test_cloud.py::test_pkcs11_never_reads_key_material` — the fake token raises if `CKA_VALUE` or
  `CKA_PRIVATE_EXPONENT` is ever touched, so the read-only claim is enforced rather than documented.
- `test_cloud.py::test_hardware_keys_carry_the_long_migration_estimate` — an HSM-resident RSA key
  must score a longer migration time than the same algorithm under managed KMS.
- `test_protocols.py::test_ssh_hybrid_kex_discounts_only_its_own_classical_half` — a bare
  `curve25519-sha256` offered beside a migrated hybrid must stay flagged. This is the most expensive
  mistake the tool could make, so it has its own test.
- `test_protocols.py::test_a_removal_list_is_not_an_inventory` — `PubkeyAcceptedAlgorithms -ssh-dss`
  *disables* DSA; reporting it would invert the finding.
- `test_scanners.py::test_a_multiline_block_comment_is_not_code` — the middle line of a `/* */`
  block neither opens nor closes it, and commented-out crypto is not crypto in use.
- `test_ui.py::test_asset_graph_actually_draws_pixels` — reads the rendered canvas bitmap, because
  a blank graph passes every other check.
- `test_ui.py::test_z_slider_recomputes_scores_live` — dragging Z must actually move total risk.
- `test_evaluate.py` — accuracy floors, and an assertion that every remaining miss is a
  documented dynamic-resolution case rather than a regression.

---

## Deliverables (problem statement §Expected Solution)

| Requirement | Status |
|---|---|
| Scans source code repositories | ✅ Python (AST); Java, JS/TS, Go, C/C++, C#/.NET, Rust (patterns) |
| Scans compiled binaries | ✅ ELF/PE/Mach-O library + symbol resolution |
| Scans libraries / dependencies | ✅ requirements.txt, package.json, pom.xml, go.mod |
| Scans container images | ✅ layer walk, SBOM, embedded key material |
| Scans cloud / HSM key stores | ✅ AWS KMS, Azure Key Vault, GCP Cloud KMS, PKCS#11 hardware modules, key-store export |
| Catalogues protocols | ✅ TLS and SSH probed live; SSH/IPsec/OpenVPN/web-TLS/S-MIME from configuration |
| Standardised CBOM report | ✅ CycloneDX 1.7 / ECMA-424 2nd Ed, validated |
| Quantum risk assessment | ✅ Shor + classical + HNDL, **plus NIST 8547 / CNSA 2.0** |
| Mosca classification | ✅ continuous score with input provenance |
| PQC/hybrid recommendations | ✅ FIPS 203/204/205/206, SP 800-208, five ranking criteria |
| Interactive GUI | ✅ overview, inventory, heat map, clustered graph, recommendations, exports |

Beyond the stated ask: per-finding **confidence levels**, cross-source **de-duplication**, the
**regulatory deadline** axis, **drift** tracking, **measured accuracy** against a labelled corpus,
and a **security model for the tool itself**.

**Not built.** CI scan-on-commit plugin (Phase 4). Certificate
*chain* walking: leaf certificates carry full metadata and expiry, issuer chains do not, so the
"if this CA breaks, which certificates cascade" view is not yet complete. RBAC is header-based and
demonstrates where gating belongs rather than being real authentication. And CBOM conformance is
checked against the fields and enumerations we emit, not the published JSON Schema.
