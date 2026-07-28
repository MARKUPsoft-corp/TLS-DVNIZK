TLS-DVNIZK — DVNIZK-ECC Integration in tlslite-ng
==================================================

This repository is a fork of [tlslite-ng](https://github.com/tlsfuzzer/tlslite-ng)
(version 0.9.0b2) modified to integrate **DVNIZK-ECC** (Designated-Verifier
Non-Interactive Zero-Knowledge on Elliptic Curves), a deniable authentication
mechanism for TLS 1.3.

Instead of a standard Ed25519 signature in `CertificateVerify`, the server
generates an OR proof of Schnorr proving knowledge of either the server's
private key or the client's ephemeral key. The client can simulate
indistinguishable proofs, making transcripts non-transferable.

Table of Contents
=================

1. Modifications
1. Requirements
1. Quick Start
1. Demo
1. Benchmark
1. Protocol
1. Project Structure
1. References

1 Modifications
===============

New files:
- `tlslite/dvnizk.py` — DVNIZK-ECC core: `generate_proof`, `verify_proof`,
  `simulate_proof`, serialization, X25519↔Ed25519 conversion
- `demo_dvnizk_server.py` — TLS 1.3 server with DVNIZK authentication
- `demo_dvnizk_client.py` — TLS 1.3 client with DVNIZK authentication
- `benchmark_dvnizk.py` — Benchmark suite (50 iterations)
- `test_dvnizk_tls13.py` — TLS 1.3 handshake tests

Modified files:
- `tlslite/constants.py` — added `dvnizk_ed25519 = (254, 0)` signature scheme
- `tlslite/handshakesettings.py` — added `dvnizk_ed25519` to `SIGNATURE_SCHEMES`
- `tlslite/tlsconnection.py` — server proof generation and client proof
  verification in TLS 1.3 handshake

2 Requirements
==============

- Python 3.10+
- PyNaCl 1.5.0+ (`pip install pynacl`)

3 Quick Start
=============

```bash
git clone https://github.com/MARKUPsoft-corp/TLS-DVNIZK.git
cd TLS-DVNIZK
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt  # or: pip install pynacl tlslite-ng
```

4 Demo
======

Terminal 1 (server):
```bash
source venv/bin/activate
python demo_dvnizk_server.py
```

Terminal 2 (client):
```bash
source venv/bin/activate
python demo_dvnizk_client.py
```

Expected output:
```
SERVEUR DVNIZK-ECC -- TLS 1.3
Handshake TLS 1.3 reussi !
    Algorithme : dvnizk_ed25519
    Recu client: Hello depuis le client DVNIZK-ECC !
```

5 Benchmark
===========

```bash
source venv/bin/activate
python benchmark_dvnizk.py
```

Results (50 iterations, Intel Core i7-8665U):

| Metric               | Ed25519     | DVNIZK-ECC | Difference |
|----------------------|-------------|------------|------------|
| Generation / sign    | 591 µs      | 205 µs     | -65%       |
| Verification         | 4648 µs     | 341 µs     | -93%       |
| Handshake total      | 19 277 µs   | 19 264 µs  | ~0%        |
| CertVerify size      | 64 bytes    | 160 bytes  | +96 bytes  |

Note: DVNIZK uses PyNaCl/libsodium (C native) while tlslite-ng's Ed25519
uses python-ecdsa (pure Python). A fair comparison on the same C backend
would show DVNIZK requiring 2-3 additional scalar multiplications.

6 Protocol
==========

Challenge computation (Fiat-Shamir domain separation):
```
c = SHA-512("DVNIZK-ECC" || R1 || R2 || P_server || P_client || transcript_hash)
```

Proof serialization: 160 bytes (2×32 compressed points + 3×32 scalars)

Signature scheme ID: `dvnizk_ed25519 = (254, 0)` (private use range per RFC 8446)

Key conversion: X25519 (Montgomery) ↔ Ed25519 (Edwards) via birational map
  y = (u - 1) / (u + 1) mod p

7 Project Structure
===================

```
tlslite/
  dvnizk.py           # DVNIZK-ECC implementation
  constants.py        # SignatureScheme.dvnizk_ed25519
  handshakesettings.py# SIGNATURE_SCHEMES list
  tlsconnection.py    # Handshake modifications (server + client)
  certs/              # Ed25519 test certificates
demo_dvnizk_server.py # Server demo script
demo_dvnizk_client.py # Client demo script
benchmark_dvnizk.py   # Performance benchmark
test_dvnizk_tls13.py  # TLS 1.3 handshake tests
```

8 References
============

- Original tlslite-ng: https://github.com/tlsfuzzer/tlslite-ng
- TLS 1.3 (RFC 8446): https://www.rfc-editor.org/rfc/rfc8446
- Ed25519 (RFC 8032): https://www.rfc-editor.org/rfc/rfc8032
- X25519 (RFC 7748): https://www.rfc-editor.org/rfc/rfc7748
- PyNaCl: https://github.com/pyca/pynacl/
- libsodium: https://doc.libsodium.org/
