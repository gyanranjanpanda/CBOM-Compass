# Product Requirements Document — CBOM Compass

**Cryptographic Inventory & Post-Quantum Readiness Platform**
Problem Statement: SIH25164 · Theme: Cybersecurity
Doc status: **v1.2 — revised draft** · Prepared 03 Sep 2026 · Supersedes v1.0

> **Changelog v1.1 → v1.2.** Rebuilt §6.3's scoring as `vulnerability × timing` after a scan of real third-party code (paramiko) scored an already-migrated ML-KEM key exchange at 0.60; recalibrated `URGENCY_SCALE` to 10y so the timing floor no longer dominates every realistic exposure gap; made compliance pressure a ramp toward the NIST deadline rather than a step at publication. Also: the demo now scans unmodified upstream repositories rather than fixtures, PQC APIs are detected so already-migrated assets are recognised, and `usedforsecurity=False` hashes are inventoried but not scored.
>
> **Changelog v1.0 → v1.1.** Corrected the symmetric/hash risk classification (Grover's impact was overstated); added the NIST IR 8547 compliance deadline as a second, certain scoring axis alongside the uncertain Mosca axis; retargeted output to CycloneDX 1.7 / ECMA-424 2nd Edition and its Cryptography Registry; completed the PQC recommendation table (FIPS 206, HQC, LMS/XMSS); specified the priority score as an actual formula; made X/Y/criticality honestly human-sourced; defined asset identity and de-duplication; added §10, a security model for the tool itself; and re-sequenced the roadmap so the first milestone lights up every scored deliverable rather than one pillar.

---

## 1. Overview

CBOM Compass is a scanning and risk-assessment platform that discovers every cryptographic asset an organisation runs — in source code, compiled binaries, container images, live network endpoints, dependencies, and cloud/HSM key stores — and tells the organisation which of those assets a quantum computer will break, which ones a regulator will disallow first, how urgently each needs migrating, and what to replace it with.

The product exists because quantum computers capable of breaking RSA/ECC-class cryptography do not need to exist yet for the risk to be live. In a *harvest now, decrypt later* attack, adversaries record encrypted traffic today and decrypt it once a cryptographically-relevant quantum computer (CRQC) exists. Anything with a confidentiality requirement longer than the time remaining until that day is already exposed.

There is also a nearer, more certain deadline than Q-Day: **NIST IR 8547 deprecates RSA-2048 and ECC P-256 after 2030 and disallows all RSA/ECC after 2035.** Many organisations will be forced to migrate by regulation years before they are forced by physics. CBOM Compass scores both.

**One line:** find every lock in the building, work out which ones a quantum computer can pick and which ones the regulator bans first, and hand over a prioritised locksmith's list.

---

## 2. Problem Statement

Organisations run cryptography they can no longer fully see: the exact RSA key length a payment gateway negotiates, the TLS version a legacy service still accepts, a certificate expiring inside a vendor SDK three dependencies deep. There is no standard, automated way to answer *"what cryptography do we actually run, and which of it is quantum-vulnerable?"*

The problem statement requires four functions:

- **Discover** — scan code, binaries, containers, dependencies, endpoints and key stores; produce one de-duplicated inventory.
- **Assess** — flag which assets a quantum computer breaks, which a regulator disallows, and what data that exposes.
- **Classify** — rank by urgency using Mosca's inequality and the NIST deadline, weighted by business criticality.
- **Recommend** — suggest the correct PQC or hybrid replacement per asset, weighing cost, latency, and support maturity.

---

## 3. Goals and Non-Goals

### 3.1 Goals

1. Produce a complete, de-duplicated, standards-conformant cryptographic inventory (CBOM) across six source types.
2. Classify every asset on two independent axes: **quantum vulnerability** (Shor-broken / Grover-relevant / adequate / deprecated) and **regulatory deadline** (NIST IR 8547, CNSA 2.0).
3. Compute a defensible, configurable, *continuous* migration priority score — not a boolean and not a gut feel.
4. Recommend NIST-standardised PQC or hybrid replacements per asset, with cost/latency/maturity tradeoffs shown.
5. Attach a **confidence level** to every finding, because static and binary detection are inherently uncertain.
6. Present all of the above through a dashboard usable by both security engineers and non-technical risk officers.
7. Emit **CycloneDX 1.7 / ECMA-424 2nd Edition** CBOM that validates against the published schema.
8. Be safe to run: least-privilege connectors, scoped scan targets, no plaintext credential persistence.

### 3.2 Non-Goals (v1)

- No automated remediation. CBOM Compass recommends; it does not rewrite code, rotate keys, or reissue certificates.
- Not a general SAST/SCA platform. Scope is cryptographic assets specifically.
- No prediction of Q-Day. `Z` is always a configurable, risk-officer-owned input, never a hardcoded date.
- No agent-based runtime/dynamic crypto tracing (e.g. hooking live `libcrypto` calls). Static, manifest, image and handshake evidence only.

---

## 4. Threat Model

Two quantum algorithms are relevant, and they matter **very** differently. Overstating the second is a common error; this section is deliberately precise.

### 4.1 Shor's algorithm — the real problem

Shor solves integer factorisation and discrete logarithms efficiently — the exact hard problems underlying **RSA, DSA, Diffie-Hellman, ECDSA and ECDH**. A sufficiently large quantum computer does not weaken these; it **breaks them outright**. Every certificate chain, TLS key exchange, and code-signing key built on today's public-key cryptography is affected. There is no key-size fix; the mathematics is gone.

### 4.2 Grover's algorithm — much less than the headlines suggest

Grover gives a quadratic speedup on unstructured search. The popular claim that "AES-128 becomes a 64-bit key" is **an oversimplification we deliberately do not implement**, for three reasons:

- Grover requires ~2⁶⁴ **sequential** quantum operations; it parallelises poorly (m machines buy only √m), so wall-clock attack time does not fall the way the raw exponent suggests.
- The required coherent quantum runtime is far beyond any credible near-term machine.
- NIST's own PQC security-strength categories are *defined* using AES-128 and SHA-256 as reference points — they are treated as adequate baselines, not as casualties.

For hash functions the relevant quantum attack on collision resistance is **Brassard–Høyer–Tapp** (a cube-root speedup), which is not considered practically superior to the classical birthday attack once quantum memory costs are counted.

**Design consequence:** symmetric ciphers ≥128-bit and hashes ≥256-bit are classified **adequate**, not "weakened". Where AES-256/SHA-384 is required, it is surfaced as a **CNSA 2.0 policy flag**, not as a quantum break. This keeps the "act now" bucket small and credible instead of flooding it with every SHA-256 call in the codebase.

### 4.3 Harvest now, decrypt later

An adversary records encrypted traffic today and holds it until a CRQC exists. Any asset whose data must stay confidential for longer than the time remaining until Q-Day is **already** exposed. This is why discovery cannot wait, and it is the flag that drives the Mosca calculation in §6.3.

### 4.4 The regulatory clock (the certain deadline)

| Regime | Requirement | Date |
|---|---|---|
| NIST IR 8547 | RSA-2048 / ECC P-256 (112-bit class) **deprecated** | after 2030 |
| NIST IR 8547 | All RSA / ECC, any strength, **disallowed** | after 2035 |
| CNSA 2.0 (NSA) | AES-256, SHA-384/512, ML-KEM-1024, ML-DSA-87; LMS/XMSS for firmware signing | phased to 2030–2033 |

Unlike `Z`, these dates are fixed and citable. Every asset is scored against both clocks.

---

## 5. Target Users / Personas & Roles

| Persona | Needs | Role in product |
|---|---|---|
| Security / cryptography engineer | Asset-level detail: algorithm, key size, library version, source location, confidence, dependency path | `engineer` — read all, tag assets, run scans |
| CISO / risk officer | Aggregate heat map, priority order, exportable board/compliance reports; owns `Z` and criticality weights | `risk_officer` — all of the above **plus** edit global `Z`, criticality policy |
| DevOps / platform engineer | Scan-on-commit so new cryptographic debt is not merged silently | `engineer` + CI service token (scan + write, no settings) |
| Compliance / audit lead | Standardised exportable CBOM as regulatory evidence | `auditor` — read + export only, no settings, no scan trigger |

Roles matter functionally, not just administratively: `Z` is a single global input that changes **every** risk score in the system, so it is a privileged, audit-logged setting (§10).

---

## 6. Functional Requirements — The Four Pillars

### 6.1 Pillar I — Discovery & Inventory

Six source types, each with its own technique, all normalised into one inventory.

| Source | Technique | What it actually yields | Typical confidence |
|---|---|---|---|
| **Source code** | Semgrep rules over AST for crypto API call sites | `javax.crypto.*`, OpenSSL `EVP_*`, Python `hashlib`/`cryptography`, Go `crypto/*`, Node `crypto` — algorithm, key size where literal, file:line | High (literal args) / Medium (variable args) |
| **Dependencies** | Manifest parsing cross-referenced against a crypto-library knowledge base | `package.json`, `requirements.txt`, `pom.xml`, `go.mod` → library + resolved version → algorithms *supported* | High for version, Medium for usage |
| **Binaries** | **Library identification first**: imports/exports, symbol tables, version strings, build-ids → resolved library + version. YARA constant tables (AES S-box, SHA IVs) only as a supplementary low-confidence signal | Statically-linked crypto libs, including stripped ones | High (imports) / Low (constants only) |
| **Container images** | Syft/Trivy-style layer extraction → SBOM, then source + binary scanners over the filesystem. **Differentiator: embedded key material and certificate discovery in layers** | Base-image OpenSSL version, bundled CA bundles, *accidentally baked-in private keys* | High |
| **Live endpoints** | `sslyze`-driven TLS/SSH handshake probing against an **explicit target allowlist** (§10) | Negotiated protocol version, cipher suite, key exchange, full certificate chain and expiry — what is actually running, not what is configured | High (ground truth) |
| **Cloud & HSM** | Read-only provider API connectors | AWS KMS / Azure Key Vault / GCP KMS key specs, HSM-backed key algorithms, rotation policy | High |

**Why binary scanning was rescoped.** A YARA hit on an AES S-box tells you a constant table is present; it cannot tell you the key size, the mode, or whether the code path is even reachable — so the finding cannot be assigned an X, a Y, or a criticality, and it becomes an unscoreable dead-end row in the inventory. Resolving *which library at which version* is linked feeds the same knowledge base as dependency scanning and produces findings that flow through the whole pipeline.

#### Asset identity & de-duplication (hard requirement)

The same OpenSSL 3.0.11 will legitimately be found by the dependency scanner, the binary scanner, **and** the container scanner. Without a merge rule the inventory triple-counts and the Overview KPIs will not reconcile with the Inventory Explorer row count.

- **Identity key:** `(algorithm, normalised parameters, resolved library + version, location-class)` where `location-class` distinguishes a source call site from a linked library from a negotiated endpoint.
- **Merge semantics:** matching keys collapse into one asset carrying **multiple evidence records**. Confidence is the *maximum* across evidence; `detection_methods` is the union. Evidence from more than one independent technique raises confidence one level.
- Every count shown anywhere in the UI is a count of merged assets.

#### Output

Every finding normalises to **CycloneDX 1.7 CBOM (ECMA-424, 2nd Edition, Dec 2025)** using the `cryptographic-asset` component type and its `cryptoProperties`. Algorithm names and classifications are taken from the **CycloneDX Cryptography Registry** introduced in 1.7 rather than a bespoke naming table — the registry exists precisely to stop tools naming the same algorithm three different ways. This is a hard design constraint: real recognised standard output, not a bespoke JSON shape.

Note that `cryptoProperties.algorithmProperties.nistQuantumSecurityLevel` is **native** to the schema — part of our risk classification serialises into standard fields rather than into our extension.

### 6.2 Pillar II — Quantum & Compliance Risk Assessment

| Algorithm family | Quantum exposure | Status | Action |
|---|---|---|---|
| RSA, DSA, DH, ECDSA, ECDH | Shor fully solves the underlying problem | **Broken** | Migrate to ML-KEM / ML-DSA; hybrid now |
| AES-128, AES-192, SHA-256 | Grover/BHT speedups do not practically threaten these (§4.2) | **Adequate** | No quantum-driven change. Flag separately *only* if CNSA 2.0 applies |
| AES-256, SHA-384/512 | Margin reduced, comfortably strong | **Adequate** | No change |
| RSA-1024, 3DES, SHA-1 | Not publicly broken, but below acceptable strength / structurally weak (Sweet32, 64-bit blocks, collisions) | **Deprecated — insufficient** | Retire on classical grounds, independent of PQC timeline |
| MD5, DES, RC4 | Broken classically | **Broken (classical)** | Retire immediately |

Precision matters here: RSA-1024 has never been publicly factored and 3DES has not been "broken" — calling them broken undermines the credibility of the rows that *are* breaks.

A second, independent boolean applies on top: **harvest-now-decrypt-later** — does this asset protect data with a long confidentiality requirement? This feeds §6.3 directly.

A third flag: **regulatory** — `nist_8547_deprecated_2030`, `nist_8547_disallowed_2035`, `cnsa2_noncompliant`.

**Output per asset:** a `quantum_status` enum (one canonical field — not a separate "score"), a HNDL boolean, a regulatory flag set, and a confidence level.

### 6.3 Pillar III — Classification (Mosca's Inequality, made computable)

Mosca's test compares three durations. If the inequality holds, the asset is already in trouble — waiting is not a neutral choice.

```
X (data lifetime) + Y (migration time) > Z (time until a CRQC exists)
```

**Units.** `X` and `Y` are durations in years. `Z` is entered in the UI as a *year* (a slider) and converted at evaluation time: `Z_years = Z_year − current_year`. Every stored score records the `Z_year` used, so historical scores remain interpretable.

#### Where X, Y and criticality actually come from

v1.0 claimed these could be derived from CBOM metadata. They cannot, and pretending otherwise would make the centrepiece calculation quietly fictional:

- **No static analyser can know that a given AES call protects 25-year defence secrets.** `X` is a *business* fact.
- **Dependency depth is a poor migration-effort proxy.** A deeply-nested dependency is often *easier* to fix (bump a version) than a shallow one (rewrite in-house protocol code).

So they are explicit, visible, human-owned inputs with defaults:

| Input | Source | Default when untagged |
|---|---|---|
| `X` data lifetime | Asset/service tag, set in UI or checked-in `crypto-policy.yaml` mapping repo/service → data class | Data-class defaults: ephemeral 0.1y · operational 3y · financial 7y · PII 10y · regulated/defence 25y. Untagged → 7y, marked `assumed` |
| `Y` migration time | Rule table on `(asset_type × deployment_surface)` — e.g. containerised service behind LB 0.5y · public API with external clients 2y · embedded/field hardware 5y · third-party SaaS dependency 3y | Rule-table lookup, marked `estimated` |
| criticality | Service tag from `crypto-policy.yaml`, or manual in Inventory Explorer | `medium` |

Any asset scored on an assumed/estimated input is visually badged as such. This is a feature, not an apology: §8.1 requires every number be explainable, and an honest "we assumed 7 years, click to change" is more defensible to an auditor than a confident number with no provenance.

#### The priority formula

Mosca's inequality returns a boolean, and a boolean multiplied by a weight yields two buckets, not a ranking. We use the signed **exposure gap** instead, which preserves *how badly* an asset fails the test:

```
exposure_gap  = (X + Y) − Z_years             # years; positive ⇒ already overdue

urgency       = clamp(exposure_gap / URGENCY_SCALE, 0, 1)   # URGENCY_SCALE default 10y
compliance    = nearness of the earliest binding NIST IR 8547 deadline,
                rising from 0 to 1.0 over COMPLIANCE_HORIZON (default 10y),
                and 1.0 once the date has passed
vulnerability = 1.0 broken · 0.8 deprecated · 0.3 policy-only · 0.0 adequate

timing        = max(urgency, compliance, TIMING_FLOOR)      # TIMING_FLOOR default 0.5
risk          = vulnerability × timing × (0.6 + 0.4 × hndl_flag)
score         = risk × criticality_weight   # low 0.4 · medium 0.7 · high 1.0
```

**Vulnerability gates everything.** Timing modulates a real need to migrate; it never creates one. This is not a theoretical nicety — an earlier version of this spec took a flat `max()` across three peer axes, and the first scan of a real codebase (paramiko, which is mid-migration to ML-KEM) scored its **already post-quantum key exchange at 0.60**, purely because SSH session keys protect long-lived access. That is precisely the false urgency §4.2 exists to prevent. If there is nothing to migrate, no timeline makes it urgent, and adequate algorithms now score exactly zero whatever their data lifetime.

**The floor works the other way.** Weak cryptography protecting short-lived data is still worth replacing, so `timing` never falls to zero and 3DES on a session key still registers.

**Compliance pressure is a ramp, not a step.** A flat 1.0 from the day the rule was published pinned every Shor-broken asset to an identical score, which left Mosca unable to distinguish between them — and distinguishing between them is the entire point of Mosca. Scored as a ramp, the same RSA-2048 comes out at **1.00 protecting 25-year regulated data and 0.36 protecting ephemeral session data**, which is the ordering a migration plan actually needs.

All weights, `URGENCY_SCALE`, `COMPLIANCE_HORIZON` and `TIMING_FLOOR` are configurable in Settings and shown in the score-explanation panel.

**Worked example.** Payment-gateway TLS using RSA-2048, untagged, scored in 2026. `X` = 7y (financial default, marked *assumed*), `Y` = 2y (public-API rule), `Z_year` = 2031 → `Z_years` = 5. `exposure_gap = (7 + 2) − 5 = +4y` → overdue. `urgency` = 4/10 = 0.40; `compliance` = (10 − (2030 − 2026))/10 = 0.60; `timing` = max(0.40, 0.60, 0.50) = 0.60; `vulnerability` = 1.0; HNDL = true → `risk = 1.0 × 0.60 × 1.0 = 0.60`. The score is **deadline-driven, not Mosca-driven**, and the UI says so: at a +4-year gap the regulator's 2030 date is the nearer pressure.

**Output:** a criticality × urgency heat map and a priority-ordered list.

|  | Low urgency | Medium urgency | High urgency |
|---|---|---|---|
| **High criticality** | Internal audit log signing | Customer PII archive | Payment gateway TLS |
| **Medium criticality** | Partner API auth | Internal service mesh mTLS | Legacy VPN gateway |
| **Low criticality** | Dev environment certs | Internal wiki auth | Marketing site TLS |

### 6.4 Pillar IV — Recommendation

Recommendations name specific standards, never "quantum-safe crypto" generically.

| Standard | Algorithm | Replaces | Use | Status |
|---|---|---|---|---|
| FIPS 203 | ML-KEM (Kyber) | RSA / ECDH key exchange | Key encapsulation | **Final** (Aug 2024) |
| FIPS 204 | ML-DSA (Dilithium) | RSA / ECDSA / DSA signing | General-purpose signatures | **Final** (Aug 2024) |
| FIPS 205 | SLH-DSA (SPHINCS⁺) | ECDSA signing | Conservative stateless hash-based fallback; **signatures ~7.8 KB+** | **Final** (Aug 2024) |
| FIPS 206 | FN-DSA (Falcon) | ECDSA signing where bandwidth is tight | Smallest PQC signatures; risky floating-point signing implementation | **Draft** — submitted Aug 2025, final expected late 2026 / early 2027. Recommend only with an explicit "not yet final" badge |
| SP 800-208 | LMS / XMSS | RSA/ECDSA firmware & code signing | Stateful hash-based; **CNSA 2.0's mandate for firmware signing** | **Final**; state management is a hard operational requirement |
| (pending) | HQC | Backup KEM alongside ML-KEM | Code-based, different mathematical assumption than lattices — hedge against a lattice break | Selected Mar 2025, draft standardisation underway |

**Default recommendation is hybrid** (classical + PQC), so a break in either algorithm alone does not compromise the connection — the approach Chrome and Cloudflare already run in production (X25519 + ML-KEM-768 in TLS 1.3).

The engine ranks candidates per asset by:

1. **Risk score** from §6.3.
2. **Latency / bandwidth budget** — ML-KEM-768 public key ≈ 1184 B vs RSA-2048's ≈ 256 B; SLH-DSA signatures ≈ 7.8 KB vs ECDSA P-256's ≈ 64 B. Decisive for constrained IoT, near-irrelevant for a datacentre service. This is why FN-DSA and SLH-DSA are not interchangeable.
3. **Library / hardware support maturity** — is there a production-grade implementation for this language and platform yet?
4. **Compliance regime** — CNSA 2.0 forces AES-256, ML-KEM-1024, ML-DSA-87, LMS/XMSS for firmware.
5. **Rotation cost** — how expensive is reissuing this key/cert across its dependents (computed from the asset graph's in-edges).

**Output:** per-asset migration plan — recommended algorithm, hybrid vs pure-PQC, estimated effort, blocking dependencies, standard maturity badge.

---

## 7. System Architecture

Five stages. Every stage writes back to the CBOM asset graph, so re-running scanners shows **drift over time**, not just a snapshot.

```
┌───────────────┐   ┌───────────────┐   ┌────────────────┐   ┌────────────────────┐   ┌───────────────┐
│    Inputs     │   │   Scanners    │   │   CBOM store   │   │  Risk & Reco       │   │   Dashboard   │
├───────────────┤   ├───────────────┤   ├────────────────┤   ├────────────────────┤   ├───────────────┤
│ Source repos  │   │ Semgrep       │   │ Map to         │   │ Shor / classical   │   │ Inventory     │
│ Dep manifests │──▶│  static scan  │──▶│  CycloneDX 1.7 │──▶│  classifier        │──▶│  explorer     │
│ Binaries      │   │ Import/symbol │   │ Cryptography   │   │ NIST 8547 &        │   │ Risk heat map │
│ Container     │   │  resolution   │   │  Registry      │   │  CNSA 2.0 clocks   │   │ Asset graph   │
│  images       │   │ Syft layer    │   │  normalisation │   │ Mosca calculator   │   │ Recommend'ns  │
│ TLS/SSH       │   │  extraction   │   │ Identity merge │   │  (X,Y,Z)           │   │ Score         │
│  endpoints    │   │ sslyze probe  │   │  + de-dup      │   │ Criticality        │   │  explainer    │
│ Cloud KMS/HSM │   │  (allowlisted)│   │ Relationships  │   │  weighting         │   │ Export        │
│               │   │ Provider API  │   │ Scan history / │   │ PQC / hybrid rule  │   │  CBOM/PDF/CSV │
│               │   │  read-only    │   │  drift         │   │  base              │   │               │
└───────────────┘   └───────────────┘   └────────────────┘   └────────────────────┘   └───────────────┘
```

---

## 8. UX / UI Specification

### 8.1 Design principles

- **Severity is colour-coded consistently**: red (broken, act now), amber (deprecated/insufficient), green (adequate), grey (retire regardless of quantum timeline). Colour is always paired with an icon and text label — never colour alone — for colour-blind users.
- **Every number is explainable.** Clicking any score or rank opens a panel showing the X, Y, Z, flags and weights that produced it, including which inputs were *assumed* vs *tagged*.
- **`Z` is always visibly a dial, not a fact.** The quantum-arrival estimate is an adjustable control on every risk view with its current value always shown, so nobody mistakes it for a certainty. NIST deadline scoring is displayed *beside* it, labelled as fixed.
- **Confidence is always visible.** No finding is presented as more certain than the technique that found it.
- **Progressive disclosure.** Aggregates by default; drill into asset, then finding, then raw evidence.
- **Dark-mode-first**, information-dense but uncluttered, monospace for identifiers (paths, hashes, algorithm names) — Grafana/Snyk/Trivy aesthetic.

### 8.2 Screens

1. **Overview / Home** — KPIs: total merged assets, counts by status, HNDL-flagged count, assets past the 2030/2035 line, last scan per source type, drift since last scan. Condensed heat map preview and a "top 10 most urgent" list.
2. **Inventory Explorer** — searchable, filterable table. Columns: asset, source type, algorithm, key size, library + version, location, quantum status, regulatory flags, **confidence**, criticality, last seen. Row click opens detail: full metadata, every evidence record and the technique that produced it, related assets, raw CBOM entry.
3. **Risk Heat Map** — interactive criticality × urgency matrix; cell click filters the Explorer to that population. A visible **Z-slider** recomputes the map live. Companion timeline shows X, Y and Z on one axis for the selected asset with the exposure window shaded.
4. **Asset Graph View** — nodes (assets, certs, services, libraries), edges (`signed-by`, `depends-on`, `negotiated-by`, `bundled-in`). Traces blast radius: *"if this CA's signing algorithm breaks, which 40 certificates cascade?"* Node colour by status; zoom/pan; click-to-expand. Clusters above a node threshold rather than rendering everything.
5. **Recommendations** — per-asset or bulk-by-filter, against the FIPS 203/204/205/206 + SP 800-208 table, with hybrid-vs-pure choice, rotation cost, maturity badge (final vs draft). Exports a sequenced migration worklist.
6. **Reports / Export** — CycloneDX 1.7 JSON, PDF risk summary (board/compliance), CSV. **Exports respect current filters**, so a risk officer can export exactly "red + high criticality".
7. **Settings** — `Z` (global default, optional per-business-unit override), criticality weights and `URGENCY_SCALE`, data-class defaults for X, the Y rule table, scan schedules, target allowlists, and connected integrations. Every change here is audit-logged (§10).

### 8.3 States (specified, not assumed)

- **Empty / first run** — no scan yet: a single primary action ("Point CBOM Compass at a repo, image, or endpoint") plus the bundled sample environment as a one-click demo. This is the first thing a judge sees.
- **Scan in progress** — per-source progress with live findings counter; the dashboard is usable on partial results.
- **Partial failure** — one scanner failing (bad credentials, unreachable host, unparseable binary) degrades to a per-source error banner; it never blocks the other five sources or blanks the dashboard.
- **Stale** — any figure depending on `Z` is marked stale and offers "recompute" when `Z` changes; never silently wrong.

### 8.4 Interaction notes

- All tables support sort, multi-column filter, and column show/hide.
- Re-scans are diffed against the previous snapshot; new/changed/removed assets are flagged as **drift** rather than presented as an undifferentiated fresh list.

---

## 9. Data Model

**Asset** — one cryptographic artefact (key, cert, negotiated cipher suite, or algorithm usage site).
`id · identity_key · type · algorithm (registry-normalised) · key_size / parameters · source_type · location · confidence (high|medium|low) · detection_methods[] · evidence[] · first_seen · last_seen`

**Certificate** (Asset subtype, first-class) — `subject · issuer · not_before · not_after · signature_algorithm · public_key_algorithm · chain_depth · is_ca · san[]`. Expiry is tracked alongside quantum status; a cert expiring in 30 days is an operational emergency independent of Q-Day, and §2's motivating example depends on this existing.

**Relationship** — edges: `signed-by · depends-on · negotiated-by · bundled-in`.

**Risk classification** — per asset: `quantum_status` enum, `hndl_flag`, regulatory flag set, `X` + `x_source` (tagged|assumed), `Y` + `y_source` (tagged|estimated), `z_year_used`, `exposure_gap`, `criticality`, `score`.

**Recommendation** — per asset: recommended standard (FIPS 203/204/205/206, SP 800-208, or "no change"), `hybrid` flag, `maturity` (final|draft), estimated rotation cost, support-maturity rating, blocking dependencies.

**Scan run** — sources covered, target scope, timestamp, initiating principal, diff against previous run.

**Canonical serialisation:** Asset + Relationship serialise to CycloneDX 1.7 CBOM (ECMA-424 2nd Ed). Risk classification and Recommendation are CBOM Compass extensions layered on top of — and exported alongside — that standard payload, except where the schema already provides a field (e.g. `nistQuantumSecurityLevel`), which we populate natively.

---

## 10. Security & Trust Model (the tool itself)

CBOM Compass ingests KMS and HSM credentials, and its output is a ranked, filtered, exportable list of an organisation's weakest cryptography — an attacker's shopping list, pre-prioritised. Under a Cybersecurity problem statement this cannot be left implicit.

- **Credentials** — cloud/HSM connectors require **read-only, least-privilege** roles (`kms:DescribeKey`, `kms:ListKeys` class permissions only; never `Decrypt`, never `Sign`). Credentials are stored encrypted at rest with a separate key, never written to logs, never included in any export.
- **Scan authorization** — live TLS/SSH probing is gated on an **explicit target allowlist** plus a recorded authorization attestation naming who approved the scope. Without this the product is simply a network scanner pointed at arbitrary hosts. Scans of non-allowlisted targets are refused, not warned.
- **Access control** — RBAC per §5. `Z`, criticality weights, target allowlists and connector credentials are `risk_officer`-only; `auditor` is read/export only.
- **Audit log** — append-only record of scans run, settings changed (especially `Z`), exports produced, and by whom. Exports are the primary exfiltration path and are logged with their filter scope.
- **Data at rest** — CBOM store encrypted; discovered key *material* (e.g. a private key found baked into a container layer) is recorded as a **fingerprint and location only**, never the key bytes themselves.
- **Deployment** — ships self-hostable by default. No scan data leaves the customer boundary.

---

## 11. Tech Stack

| Layer | Choice | Why |
|---|---|---|
| Source-code scanning | **Semgrep** (OSS engine, custom rules) | AST matching across languages, no compiler needed. *tree-sitter dropped* — Semgrep already does AST matching; add tree-sitter only for a language Semgrep lacks |
| Binary scanning | LIEF (ELF/PE/Mach-O parsing), YARA as supplementary signal | Import/symbol/version resolution is the primary technique; constants are a fallback |
| Container scanning | Syft (SBOM) + layer walk | Reuse, don't reimplement |
| Network / TLS | **sslyze** directly | Ground truth on what is actually negotiated |
| CBOM generation | `cyclonedx-python-lib` targeting **1.7** + Cryptography Registry | Standard, tool-interoperable, and the registry gives us algorithm-name normalisation for free |
| Store | **Postgres + JSONB** (single decision, Neo4j dropped for v1) | One service, one query language; Cytoscape renders fine from an edge table. Neo4j earns its keep at a scale we will not reach in v1 — revisit if the graph exceeds ~10⁶ edges |
| Risk / Mosca engine | Python rules engine | Configurable `Z` and weights, composable rules, trivially unit-testable — and the formula in §6.3 *must* be unit-tested |
| Backend / API | Python (FastAPI) | Same language as scanners and rules engine |
| Dashboard | React + Cytoscape.js / D3 | Graph view and heat map |
| Packaging | Docker + CLI | Standalone or wired into CI/CD |

---

## 12. Roadmap

**Sequencing principle:** the §15 deliverables checklist is what gets scored, so **Milestone 1 lights up every box at shallow depth** before any pillar is deepened. A plan that perfects source scanning and reaches judging with no container, binary, or network story scores worse than one that does all nine adequately.

| Phase | Name | Scope |
|---|---|---|
| **Phase 0** | Schema, knowledge base & fixtures | Lock the CycloneDX 1.7 mapping; build the algorithm risk knowledge base (Shor / classical-deprecation / NIST 8547 / CNSA 2.0) sourced from the Cryptography Registry; define asset identity + merge rule; define Mosca input fields and the Y rule table. **Deliverables: (a) a labelled test corpus for measuring accuracy — it does not exist yet and §13 is unmeasurable without it; (b) a deliberately-vulnerable sample repo + container + local TLS endpoint as the demo target, since we cannot scan a judge's laptop.** |
| **Phase 1 — vertical slice** | All nine boxes, thin | Source scanning (Python/Java/JS) · dependency manifests · binaries via imports + version strings · containers via Syft · live TLS via sslyze on the sample endpoint · CycloneDX 1.7 export · Shor/classical classification + HNDL flag · Mosca score with the §6.3 formula · basic table + heat map UI. **Demo-complete end to end.** |
| **Phase 2** | Depth on discovery | More languages; binary symbol resolution for stripped builds; container layer key/cert discovery; certificate chain + expiry; confidence calibration against the Phase 0 corpus; de-dup hardening |
| **Phase 3** | Depth on judgement & polish | Full PQC/hybrid recommendation rule base with all five criteria; interactive graph view; score-explainer panel; PDF/CSV export; Settings + RBAC |
| **Phase 4 (stretch)** | Automation | Scan-on-commit CI plugin, cloud KMS/HSM connectors, drift trend tracking across repeated scans |

### Team split

| Role | Responsibility |
|---|---|
| Scanner engineer(s) | Source / binary / container detection rules, confidence calibration |
| Backend / data model | CBOM 1.7 schema mapping, asset identity + merge, graph store, risk engine |
| Frontend engineer | Dashboard, heat map, graph visualisation, score explainer, empty/progress/error states |
| Domain / research lead | PQC algorithms, Mosca parameters, NIST 8547 / CNSA 2.0 compliance mapping, **test corpus labelling** |
| Recommendation logic | PQC/hybrid rule base, tradeoff weighting |
| PM / presentation | Demo flow, judging Q&A, deliverable tracking, sample environment |

---

## 13. Success Metrics

| Metric | Definition | Why this and not the obvious one |
|---|---|---|
| **Recall** | % of known crypto assets in the labelled Phase 0 corpus that are discovered | Replaces v1.0's "% of organisational cryptographic surface" — that has no knowable denominator; you cannot measure what you never found |
| **Precision** | % of findings that are true positives, reported per confidence band | A tool with high recall and low precision is unusable; banding shows the confidence labels are honest |
| **Actionability** | % of flagged assets with a concrete recommendation (not "unknown" / "no rule matched") | Direct measure of the recommendation rule base's coverage |
| **De-dup correctness** | Overview KPI totals reconcile exactly with Inventory Explorer row counts | Guards the failure mode most likely to be caught live on stage |
| **Time-to-insight** | Point scanner at repo/image/endpoint → rendered heat map | Demo-critical |
| **Standard conformance** | Exported CBOM validates against the CycloneDX 1.7 / ECMA-424 2nd Ed schema with zero errors | Binary pass/fail, easy to demonstrate |

---

## 14. Risks & Open Questions

- **Detection is inherently uncertain.** Stripped binaries, obfuscated code, and runtime-selected algorithms defeat static analysis. Mitigated by per-finding confidence levels (§6.1) rather than presenting all findings as equally certain — but confidence bands must be *calibrated* against the Phase 0 corpus, or they are just decoration.
- **`Z` is genuinely unknowable.** Mitigated by making it a visible dial (§8.1) and by scoring the certain NIST/CNSA clocks alongside it, so the product is useful even to someone who thinks Q-Day is 2050.
- **Assumed X and Y weaken scores.** An untagged estimate is honest but soft. Mitigated by badging assumed inputs and making tagging cheap (`crypto-policy.yaml` + bulk-tag in the Explorer). Open question: how much tagging is realistic before a demo?
- **Live scanning needs credentials and authorization** that may be sensitive to grant in a hackathon context. Mitigated by the Phase 0 sample environment and the allowlist gate (§10).
- **Graph scale.** Large monorepos and container fleets produce very large graphs; Cytoscape must cluster and paginate rather than rendering every node. Deferred to Phase 3 with clustering designed in from the start.
- **FIPS 206 is not final.** Recommending FN-DSA carries standards risk; mitigated by the maturity badge and by never making it a default.
- **Open:** do we support per-business-unit `Z` overrides in v1, or is a single global `Z` sufficient? (Leaning global-only; overrides complicate the score-explainer.)

---

## 15. Deliverables Checklist

From the problem statement's Expected Solution. **Every box must be green at Milestone 1** (§12), not spread across phases.

- [ ] Scans source code repositories
- [ ] Scans compiled binaries
- [ ] Scans libraries / dependencies
- [ ] Scans container images
- [ ] Produces a standardised CBOM report (CycloneDX 1.7 / ECMA-424 2nd Ed) with versions and modes shown
- [ ] Quantum risk assessment — Shor classification + classical-deprecation + HNDL flag *(+ NIST 8547 / CNSA 2.0 clocks — beyond the ask)*
- [ ] Classifies assets by type, lifetime, and business criticality using Mosca's inequality
- [ ] Recommends PQC/hybrid alternatives, weighing risk, latency, and cost
- [ ] Interactive GUI to visualise scan, risk, and results

Beyond the stated ask, and worth calling out in judging: per-finding **confidence levels**, cross-source **de-duplication**, the **regulatory deadline** axis, and a **security model for the tool itself** (§10).

---

## 16. References

- CycloneDX — [Cryptography Bill of Materials (CBOM)](https://cyclonedx.org/capabilities/cbom/)
- CycloneDX — [v1.7 release announcement](https://cyclonedx.org/news/cyclonedx-v1.7-released/) (Oct 2025; ECMA-424 2nd Edition, Dec 2025)
- CycloneDX — [Cryptography Registry](https://cyclonedx.org/registry/cryptography/)
- Ecma International — [ECMA-424](https://ecma-international.org/publications-and-standards/standards/ecma-424/)
- NIST — [IR 8547 ipd, Transition to Post-Quantum Cryptography Standards](https://nvlpubs.nist.gov/nistpubs/ir/2024/NIST.IR.8547.ipd.pdf)
- NIST — FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), FIPS 205 (SLH-DSA), FIPS 206 ipd (FN-DSA), SP 800-208 (LMS/XMSS)
- NSA — CNSA 2.0 suite and timeline
- IBM — [CBOM reference implementation](https://github.com/IBM/CBOM)
- Mosca, M. — "Cybersecurity in an era with quantum computers: will we be ready?" (X + Y > Z)

---

*CBOM Compass · PRD v1.2 for SIH25164 · Revised 03 Sep 2026 · Working draft, open to revision.*
