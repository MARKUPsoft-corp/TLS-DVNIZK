"""
DVNIZK-ECC — Implémentation des Algorithmes 1, 2, 3
Basé sur : YAKAM TCHAMEGNI Emmanuel, Mémoire Master 2, UYI 2024-2025

Courbe : Ed25519
Groupe : <G> d'ordre n
Preuve : π = (R1, R2, s1, s2, c2) — 160 octets
"""

import hashlib
import os
import time
from nacl.bindings import (
    crypto_scalarmult_ed25519_base_noclamp,
    crypto_scalarmult_ed25519_noclamp,
    crypto_core_ed25519_add,
    crypto_core_ed25519_sub,
)

# Ordre du groupe Ed25519
n = 2**252 + 27742317777372353535851937790883648493

# Caractéristique du corps premier d'Ed25519
p = 2**255 - 19

def x25519_to_ed25519(u_bytes: bytes) -> bytes:
    """
    Convertit une clé publique X25519 (coordonnée u de Montgomery)
    en clé publique Ed25519 (coordonnée y d'Edwards).

    Correspondance birationnelle :
      u = (1 + y) / (1 - y)  ⇔  y = (u - 1) / (u + 1)  mod p
    """
    u = int.from_bytes(u_bytes, 'little') % p

    if u == (p - 1) % p:
        y = 1
    else:
        num = (u - 1) % p
        den = (u + 1) % p
        y = (num * pow(den, p - 2, p)) % p

    return y.to_bytes(32, 'little')

def eddsakey_to_scalar_and_pub(key) -> tuple:
    """
    Extrait le scalaire privé et la clé publique d'un objet EdDSAKey tlslite-ng.
    Utilise la dérivation de clé Ed25519 (RFC 8032) : SHA-512(seed) → clamp.
    """
    seed = key.private_key.to_string()
    h = hashlib.sha512(seed).digest()
    a = bytearray(h[0:32])
    a[0] &= 248
    a[31] &= 127
    a[31] |= 64
    scalar = int.from_bytes(bytes(a), 'little')
    pub = bytes(key.public_key.to_string())
    return scalar, pub

def random_scalar() -> int:
    """Génère un scalaire aléatoire dans Zn."""
    return int.from_bytes(os.urandom(32), 'little') % n

def scalar_to_bytes(s: int) -> bytes:
    """Scalaire → 32 octets little-endian."""
    return s.to_bytes(32, 'little')

def bytes_to_scalar(b: bytes) -> int:
    """32 octets little-endian → scalaire."""
    return int.from_bytes(b, 'little') % n

def point_mul(scalar: int, point: bytes) -> bytes:
    """Multiplication scalaire : scalar * point sur Ed25519."""
    return crypto_scalarmult_ed25519_noclamp(
        scalar_to_bytes(scalar), point
    )

def point_base_mul(scalar: int) -> bytes:
    """Multiplication par le générateur G : scalar * G."""
    return crypto_scalarmult_ed25519_base_noclamp(
        scalar_to_bytes(scalar)
    )

def hash_to_scalar(*args: bytes) -> int:
    """
    Fonction de hachage H : {0,1}* → Zn
    Modélise l'oracle aléatoire du mémoire.
    H(R1, R2, Pserver, Pclient, h)
    """
    h = hashlib.sha512()
    for arg in args:
        h.update(arg)
    digest = h.digest()
    return int.from_bytes(digest, 'little') % n


# ─────────────────────────────────────────────
# ALGORITHME 1 : Génération de la preuve (Serveur)
# Section 2.3.3 du mémoire
# ─────────────────────────────────────────────
def generate_proof(x_server: int,
                   P_server: bytes,
                   P_client: bytes,
                   transcript_hash: bytes) -> dict:
    """
    Génère une preuve DVNIZK-ECC.

    Input  : x_server (clé privée serveur), P_server, P_client, h
    Output : π = (R1, R2, s1, s2, c2) — 160 octets

    Algorithme 1 du mémoire :
    - Branche 1 (vraie)   : r1 aléatoire, R1 = r1·G
    - Branche 2 (simulée) : c2, s2 aléatoires, R2 = s2·G - c2·Pclient
    - Challenge FS        : c = H(R1, R2, Pserver, Pclient, h)
    - Réponse             : c1 = c - c2 mod n, s1 = r1 + c1·xserver mod n
    """
    t0 = time.perf_counter()

    # Branche 1 : vraie (serveur connaît x_server)
    r1 = random_scalar()
    R1 = point_base_mul(r1)                        # R1 = r1·G

    # Branche 2 : simulée
    c2 = random_scalar()
    s2 = random_scalar()
    # R2 = s2·G - c2·Pclient
    s2G   = point_base_mul(s2)
    c2Pc  = point_mul(c2, P_client)
    R2 = crypto_core_ed25519_sub(s2G, c2Pc)        # R2 = s2·G - c2·Pclient

    # Challenge global via Fiat-Shamir
    c  = hash_to_scalar(b"DVNIZK-ECC", R1, R2, P_server, P_client, transcript_hash)

    # Réponse branche 1
    c1 = (c - c2) % n
    s1 = (r1 + c1 * x_server) % n

    t1 = time.perf_counter()
    gen_time_us = (t1 - t0) * 1e6

    proof = {
        'R1': R1,           # 32 octets
        'R2': R2,           # 32 octets
        's1': s1,           # scalaire
        's2': s2,           # scalaire
        'c2': c2,           # scalaire
        'gen_time_us': gen_time_us
    }
    return proof


# ─────────────────────────────────────────────
# ALGORITHME 2 : Vérification de la preuve (Client)
# Section 2.3.3 du mémoire
# ─────────────────────────────────────────────
def verify_proof(proof: dict,
                 P_server: bytes,
                 P_client: bytes,
                 transcript_hash: bytes) -> tuple:
    """
    Vérifie une preuve DVNIZK-ECC.

    Input  : π = (R1, R2, s1, s2, c2), P_server, P_client, h
    Output : (True/False, temps_verification_us)

    Algorithme 2 du mémoire :
    - Recalcule c = H(R1, R2, Pserver, Pclient, h)
    - Calcule   c1 = c - c2 mod n
    - Vérifie   s1·G = R1 + c1·Pserver
    - Vérifie   s2·G = R2 + c2·Pclient
    """
    t0 = time.perf_counter()

    R1 = proof['R1']
    R2 = proof['R2']
    s1 = proof['s1']
    s2 = proof['s2']
    c2 = proof['c2']

    # Recalculer le challenge
    c  = hash_to_scalar(b"DVNIZK-ECC", R1, R2, P_server, P_client, transcript_hash)
    c1 = (c - c2) % n

    # Vérifier branche 1 : s1·G == R1 + c1·Pserver
    lhs1 = point_base_mul(s1)
    rhs1 = crypto_core_ed25519_add(R1, point_mul(c1, P_server))
    check1 = (lhs1 == rhs1)

    # Vérifier branche 2 : s2·G == R2 + c2·Pclient
    lhs2 = point_base_mul(s2)
    rhs2 = crypto_core_ed25519_add(R2, point_mul(c2, P_client))
    check2 = (lhs2 == rhs2)

    t1 = time.perf_counter()
    verify_time_us = (t1 - t0) * 1e6

    result = check1 and check2
    return result, verify_time_us


# ─────────────────────────────────────────────
# ALGORITHME 3 : Simulation par le client
# Section 2.3.4 du mémoire (non-transférabilité)
# ─────────────────────────────────────────────
def simulate_proof(x_client: int,
                   P_server: bytes,
                   P_client: bytes,
                   transcript_hash: bytes) -> dict:
    """
    Le client simule une preuve indistinguable de celle du serveur.
    Démontre la non-transférabilité (Théorème 4).

    Input  : x_client (clé privée éphémère client), P_server, P_client, h
    Output : π' indistinguable de π

    Algorithme 3 du mémoire :
    - Branche 2 (vraie pour le client) : r2 aléatoire, R2 = r2·G
    - Branche 1 (simulée)             : c1, s1 aléatoires, R1 = s1·G - c1·Pserver
    - Challenge FS                    : c = H(R1, R2, Pserver, Pclient, h)
    - Réponse                         : c2 = c - c1 mod n, s2 = r2 + c2·xclient mod n
    """
    # Branche 2 : vraie (client connaît x_client)
    r2 = random_scalar()
    R2 = point_base_mul(r2)                         # R2 = r2·G

    # Branche 1 : simulée
    c1 = random_scalar()
    s1 = random_scalar()
    # R1 = s1·G - c1·Pserver
    s1G   = point_base_mul(s1)
    c1Ps  = point_mul(c1, P_server)
    R1 = crypto_core_ed25519_sub(s1G, c1Ps)         # R1 = s1·G - c1·Pserver

    # Challenge global via Fiat-Shamir
    c  = hash_to_scalar(b"DVNIZK-ECC", R1, R2, P_server, P_client, transcript_hash)

    # Réponse branche 2
    c2 = (c - c1) % n
    s2 = (r2 + c2 * x_client) % n

    proof_sim = {
        'R1': R1,
        'R2': R2,
        's1': s1,
        's2': s2,
        'c2': c2,
    }
    return proof_sim


# ─────────────────────────────────────────────
# Fonctions de sérialisation
# ─────────────────────────────────────────────
def serialize_proof(proof: dict) -> bytes:
    """Sérialise une preuve en 160 octets."""
    return (
        proof['R1'] +                      # 32 octets
        proof['R2'] +                      # 32 octets
        scalar_to_bytes(proof['s1']) +     # 32 octets
        scalar_to_bytes(proof['s2']) +     # 32 octets
        scalar_to_bytes(proof['c2'])       # 32 octets
    )

def deserialize_proof(data: (bytes, bytearray)) -> dict:
    """Désérialise 160 octets en preuve."""
    if len(data) != 160:
        raise ValueError(f"Preuve invalide : {len(data)} octets au lieu de 160")
    
    return {
        'R1': bytes(data[0:32]),
        'R2': bytes(data[32:64]),
        's1': bytes_to_scalar(data[64:96]),
        's2': bytes_to_scalar(data[96:128]),
        'c2': bytes_to_scalar(data[128:160]),
    }


# ─────────────────────────────────────────────
# TEST RAPIDE
# ─────────────────────────────────────────────
if __name__ == "__main__":
    print("=== Test DVNIZK-ECC ===\n")

    # Générer les clés serveur
    x_server = random_scalar()
    P_server = point_base_mul(x_server)

    # Générer les clés éphémères client (simule ClientHello.key_share)
    x_client = random_scalar()
    P_client = point_base_mul(x_client)

    # Transcript hash simulé
    transcript_hash = hashlib.sha256(b"ClientHello||ServerHello||Certificate").digest()

    # ── Algorithme 1 : génération
    print("[1] Génération de la preuve (serveur)...")
    proof = generate_proof(x_server, P_server, P_client, transcript_hash)
    print(f"    Temps de génération : {proof['gen_time_us']:.1f} µs")
    print(f"    Taille preuve       : 160 octets (5 × 32)")

    # ── Algorithme 2 : vérification
    print("\n[2] Vérification de la preuve (client)...")
    valid, verify_us = verify_proof(proof, P_server, P_client, transcript_hash)
    print(f"    Résultat            : {'✓ VALIDE' if valid else '✗ INVALIDE'}")
    print(f"    Temps vérification  : {verify_us:.1f} µs")

    # ── Algorithme 3 : simulation (non-transférabilité)
    print("\n[3] Simulation par le client (Théorème 4)...")
    proof_sim = simulate_proof(x_client, P_server, P_client, transcript_hash)
    valid_sim, _ = verify_proof(proof_sim, P_server, P_client, transcript_hash)
    print(f"    Preuve simulée valide : {'✓ OUI' if valid_sim else '✗ NON'}")
    print(f"    → Le client peut produire des preuves indistinguables")
    print(f"    → NON-TRANSFÉRABILITÉ démontrée")

    # ── Test de sérialisation
    print("\n[4] Test de sérialisation...")
    serialized = serialize_proof(proof)
    print(f"    Taille sérialisée   : {len(serialized)} octets")
    deserialized = deserialize_proof(serialized)
    valid_deser, _ = verify_proof(deserialized, P_server, P_client, transcript_hash)
    print(f"    Preuve désérialisée : {'✓ VALIDE' if valid_deser else '✗ INVALIDE'}")

    # ── Comparaison tailles
    print("\n[5] Comparaison tailles :")
    print(f"    Signature EdDSA standard : 64 octets")
    print(f"    Preuve DVNIZK-ECC        : 160 octets (+96 octets)")