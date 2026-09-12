# What the software everyone installs is actually using

`cbom-compass survey` over **32 widely depended-on open-source projects**, unmodified, at their default branch.

| | |
|---|---|
| Projects scanned | 32 |
| Cryptographic assets found | 3464 |
| **Contain cryptography a quantum computer breaks** | **81%** (26/32) |
| Contain harvest-now-decrypt-later exposure | 88% |
| **Contain any post-quantum algorithm** | **19%** (6/32) |
| Broken assets per project | median 7, mean 34.8, worst 311 |
| Wall-clock time | 127.4s |

## Reach, by algorithm

How many *projects* contain each — not how many call sites. A project with two hundred RSA call sites and one with a single call are both one migration to plan.

| Algorithm | Projects | Share |
|---|---:|---:|
| RSA | 20 | 62% |
| ECDSA | 16 | 50% |
| ECDH | 10 | 31% |
| MD5 | 9 | 28% |
| EdDSA | 7 | 22% |
| DH | 4 | 12% |
| RC4 | 3 | 9% |
| DSA | 2 | 6% |
| MD4 | 2 | 6% |
| RC2 | 1 | 3% |
| DES | 1 | 3% |

## Post-quantum adoption

| Algorithm | Projects |
|---|---:|
| ML-KEM | 5 |
| ML-DSA | 4 |
| SLH-DSA | 1 |

## What this is not

This is not a judgement on any project here. RSA and ECDSA are correct engineering decisions today, and every maintainer in this list is doing nothing wrong. The finding is the *size* of a migration that has barely started: the algorithms above are in the dependency tree of most software in production, and NIST IR 8547 disallows them after 2035.

It is also a sample, not a census. The projects were chosen for reach across seven languages, not at random, so treat the percentages as indicative of well-maintained popular code — which, if anything, is the optimistic end of the distribution.

## Reproducing it

```bash
cbom-compass survey tools/survey/targets.txt --report docs/ecosystem-survey.md
```

## Per project

| Project | Assets | Broken | HNDL | PQC |
|---|---:|---:|---:|---|
| github.com/pyca/cryptography | 1715 | 311 | 404 | ML-DSA, ML-KEM |
| github.com/google/tink | 714 | 307 | 324 | ML-DSA, SLH-DSA |
| github.com/briansmith/ring | 79 | 74 | 74 | — |
| github.com/golang/crypto | 144 | 69 | 83 | ML-KEM |
| github.com/go-jose/go-jose | 77 | 61 | 64 | — |
| github.com/rustls/rustls | 167 | 59 | 59 | ML-DSA, ML-KEM |
| github.com/jwtk/jjwt | 72 | 48 | 48 | — |
| github.com/jedisct1/libsodium | 26 | 26 | 26 | — |
| github.com/sfackler/rust-openssl | 52 | 25 | 21 | ML-DSA, ML-KEM |
| github.com/jstedfast/MimeKit | 25 | 21 | 21 | — |
| github.com/auth0/node-jsonwebtoken | 57 | 17 | 17 | — |
| github.com/curl/curl | 41 | 17 | 11 | — |
| github.com/jwt-dotnet/jwt | 32 | 17 | 17 | — |
| github.com/square/okhttp | 30 | 11 | 24 | — |
| github.com/paramiko/paramiko | 24 | 10 | 10 | ML-KEM |
| github.com/Mbed-TLS/mbedtls | 96 | 8 | 8 | — |
| github.com/urllib3/urllib3 | 11 | 6 | 6 | — |
| github.com/jpadilla/pyjwt | 6 | 6 | 6 | — |
| github.com/encode/httpx | 10 | 4 | 5 | — |
| github.com/pyca/pyopenssl | 9 | 4 | 4 | — |
| github.com/RustCrypto/hashes | 12 | 4 | 6 | — |
| github.com/digitalbazaar/forge | 3 | 2 | 2 | — |
| github.com/nodejs/undici | 15 | 2 | 4 | — |
| github.com/spf13/viper | 6 | 2 | 2 | — |
| github.com/psf/requests | 5 | 1 | 0 | — |
| github.com/StackExchange/StackExchange.Redis | 6 | 1 | 4 | — |
| github.com/pallets/flask | 1 | 0 | 1 | — |
| github.com/axios/axios | 0 | 0 | 0 | — |
| github.com/expressjs/express | 0 | 0 | 0 | — |
| github.com/dcodeIO/bcrypt.js | 1 | 0 | 0 | — |
| github.com/gorilla/websocket | 1 | 0 | 1 | — |
| github.com/libgit2/libgit2 | 27 | 0 | 12 | — |
