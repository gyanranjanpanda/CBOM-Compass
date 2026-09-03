# Labelled accuracy corpus

Ground truth for measuring the source scanner. Run:

```bash
cbom-compass eval
```

## Why this exists

The PRD's original success metric was *"% of an organisation's cryptographic surface scanned"*. That
number cannot be computed: you do not know what you failed to find, so there is no denominator. This
corpus replaces it with precision and recall against usages that were labelled by hand.

**Labels are written from reading the source, never from scanner output.** Generating labels from
output would guarantee 100% and measure nothing. When a label and the scanner disagree, the default
assumption is that the scanner is wrong.

## Structure

```
labels.yaml          ground truth
python/ java/ js/ go/   fixture sources
```

Four of the eleven files are **negative controls**: they mention MD5, RSA, DES and AES in comments,
string literals, constant names and identifiers, and perform no cryptography at all. They exist
because that is precisely what makes a naive keyword matcher look good and be useless. Any finding
in those files is a false positive.

`python/hard_dynamic.py` holds cases static analysis genuinely cannot resolve — algorithm names read
from the environment, key sizes from variables, `getattr(hashlib, ...)` indirection. They are
labelled as expected findings and counted as misses. Excluding them would inflate recall by hiding
the limitation instead of measuring it.

## The two metric sets

| Set | Match on | Answers |
|---|---|---|
| **algorithm** | file + algorithm | Did we notice this file uses MD5 at all? |
| **strict** | file + algorithm + key size + mode + curve | Did we get the details right? |

The gap between them is the cost of imperfect attribute extraction, which is worth seeing separately
from the cost of missing a usage outright. A label that omits an attribute treats it as a wildcard.
Findings are de-duplicated per file, so three MD5 call sites in one file are one observation, not
three chances to be wrong.

## What the corpus caught

Every one of these was a live bug found by measurement, not by review:

| Bug | Symptom |
|---|---|
| `DESede` (JCA Triple-DES) unrecognised | false positive `DESEDE`, missed 3DES entirely |
| `des-ede3-cbc` (Node) resolved via its `des` prefix | Triple-DES reported as single DES |
| `EC` (JCA keypair algorithm) unrecognised | false positive `EC`, missed ECDSA |
| `crypto/des` import treated as DES usage | false positive — the package also serves Triple-DES |
| Cipher modes passed as arguments (`AES.MODE_ECB`) | every pycryptodome mode dropped |
| `aes-gcm` / `des-ede3-cbc` matched as whole aliases | the mode token was swallowed by the algorithm match |
| `elliptic.P256()` curve not extracted | could not distinguish P-256 from P-521 |

Algorithm-level accuracy went from 90.0% / 90.0% to 100% / 95.0% as a result.

## Extending it

Add fixture files, then label them in `labels.yaml` **before** running the scanner. Add a negative
control alongside any new language. If the scanner then disagrees, work out which one is wrong
before changing either.

`tests/test_evaluate.py` enforces floors. Raise them when accuracy improves; do not lower them to
make a build pass.
