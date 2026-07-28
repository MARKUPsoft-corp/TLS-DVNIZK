# TLS-DVNIZK — Intégration DVNIZK-ECC dans tlslite-ng

Ce dépôt est un **fork** de [tlslite-ng](https://github.com/tlsfuzzer/tlslite-ng)
(version 0.9.0b2, commit 02d1506) modifié pour intégrer **DVNIZK-ECC**
(Designated-Verifier Non-Interactive Zero-Knowledge sur courbes elliptiques),
un mécanisme d'authentification non-transférable pour TLS 1.3.

Au lieu d'une signature Ed25519 standard dans `CertificateVerify`, le serveur
génère une preuve OU de Schnorr prouvant la connaissance de **soit** la clé
privée du serveur, **soit** la clé éphémère du client. Le client peut simuler
des preuves indistinguables, rendant les transcriptions **non-transférables** :
un tiers ne peut pas distinguer une transcription réelle d'une transcription
simulée.

---

## Table des matières

1. [Vue d'ensemble](#1-vue-densemble)
2. [Contexte théorique](#2-contexte-théorique)
3. [Architecture](#3-architecture)
4. [Module central : `tlslite/dvnizk.py`](#4-module-central-tls-litedvnizkpy)
5. [Intégration TLS 1.3](#5-intégration-tls-13)
6. [Fichiers modifiés](#6-fichiers-modifiés)
7. [Applications de démonstration](#7-applications-de-démonstration)
8. [Tests](#8-tests)
9. [Benchmark](#9-benchmark)
10. [Considérations de sécurité](#10-considérations-de-sécurité)
11. [Limites](#11-limites)
12. [Démarrage rapide](#12-démarrage-rapide)
13. [Références](#13-références)

---

## 1. Vue d'ensemble

### 1.1 Motivation

Les handshakes TLS 1.3 standards produisent des signatures **transférables** :
le message `CertificateVerify` du serveur est une signature Ed25519 (ou ECDSA)
standard du hash de transcription. Bien que TLS 1.3 chiffre tous les messages
après ServerHello (RFC 8446 §4.2.3) — protégeant CertificateVerify contre
l'interception passive sur le réseau — une divulgation ultérieure du transcript
(compromission d'endpoint, journalisation applicative, révélation volontaire)
permet à un tiers de présenter cette signature comme preuve d'authentification.
C'est un problème pour les applications sensibles à la vie privée (ex. : lanceurs
d'alerte, soins de santé, services financiers).

DVNIZK-ECC remplace la signature déterministe par une **preuve à divulgation
nulle de connaissance** que le serveur connaît sa clé privée **OU** la clé
éphémère du client. Le client peut simuler localement une preuve de
distribution identique, rendant toutes les transcriptions non-transférables.

### 1.2 Idée de haut niveau

La preuve est un **protocole Sigma** à deux branches parallèles (une
"preuve OU") :

| Branche | Qui connaît le secret ? | Prouve la connaissance de |
|---------|------------------------|---------------------------|
| 1 | Serveur | `x_server` tel que `P_server = x_server · G` |
| 2 | Client | `x_client` tel que `P_client = x_client · G` |

Le **serveur** connaît `x_server`, donc il simule la branche 2 (choisit un
défi `c2` et une réponse `s2` aléatoires, puis rétro-ajuste
`R2 = s2·G - c2·P_client`).

Le **client** connaît `x_client`, donc il simule la branche 1 (choisit un
défi `c1` et une réponse `s1` aléatoires, puis rétro-ajuste
`R1 = s1·G - c1·P_server`).

Le défi Fiat-Shamir global `c = H(R1 ‖ R2 ‖ ...)` est divisé :
`c1 + c2 ≡ c (mod n)`.

### 1.3 Propriété de non-transférabilité

Une transcription capturée `(R1, R2, s1, s2, c2)` est **indistinguable** de
celle produite par `simulate_proof()` en utilisant uniquement le secret du
client. Puisque le client peut toujours prétendre de manière plausible avoir
généré la transcription localement, la preuve est **non-transférable**
(également appelée "non-reniable" ou "à vérificateur désigné").

---

## 2. Contexte théorique

### 2.1 Preuves OU (Cramer–Damgård–Schoenmakers)

Une **preuve OU** permet à un prouveur de démontrer la connaissance d'un
secret pour **l'une** de deux (ou plusieurs) déclarations sans révéler
laquelle. La construction utilise la technique de composition parallèle
des **protocoles Sigma** :

- Pour la branche où le prouveur connaît le témoin, il se comporte
  honnêtement (engagement aléatoire, calcul de la réponse étant donné le défi).
- Pour l'autre branche, il **simule** en utilisant un défi et une réponse
  aléatoires, puis rétro-ajuste l'engagement.

Le vérifieur vérifie les deux branches avec le **même** défi global `c`,
qui est égal à `c1 + c2 mod n`. Le prouveur ne peut pas tricher car cela
nécessiterait de résoudre le logarithme discret pour les deux branches
simultanément.

### 2.2 Transformée de Fiat-Shamir

Le protocole Sigma interactif est rendu **non-interactif** (NIZK) via
l'heuristique de Fiat-Shamir :

```
c = H( chaîne_contexte ‖ R1 ‖ R2 ‖ P_serveur ‖ P_client ‖ hash_transcription )
```

Cela lie la preuve au contexte complet de la session, empêchant le rejeu
et les attaques par collision de transcription.

### 2.3 Solidité (Théorème 1 du mémoire)

Si le problème du logarithme discret est difficile dans le groupe Ed25519,
un adversaire qui produit une preuve valide sans connaître `x_serveur` ni
`x_client` peut être extrait pour résoudre le logarithme discret d'au moins
une des clés publiques. Deux stratégies d'extraction existent :

- **Extraction serveur** (l'adversaire agit comme le serveur) : rembobiner
  l'adversaire pour obtenir deux preuves avec des défis différents.
- **Extraction client** (l'adversaire agit comme le client) : même technique
  appliquée à la branche 2.

La preuve complète est donnée dans le mémoire de master associé (§2.3.5).

### 2.4 Divulgation nulle de connaissance / Non-transférabilité (Théorème 4)

La fonction `simulate_proof` produit une preuve dont la distribution est
**statistiquement indistinguable** d'une preuve réelle. Le simulateur
connaît `x_client` et échange les rôles : la branche 2 est réelle, la
branche 1 est simulée. Puisque `c1`, `c2` sont uniformément aléatoires
et `R1`, `R2` sont des éléments de groupe uniformément distribués, aucun
distinguheur ne peut faire la différence sans résoudre le problème DDH
dans le modèle de l'oracle aléatoire.

---

## 3. Architecture

### 3.1 Arborescence des fichiers

```
tlslite-ng/
├── tlslite/
│   ├── dvnizk.py              # Module central DVNIZK-ECC (nouveau)
│   ├── constants.py           # Identifiant de schéma (254, 0) (modifié)
│   ├── handshakesettings.py   # Enregistrement du schéma (modifié)
│   └── tlsconnection.py       # Intégration handshake (modifié)
├── dvnizk_ecc/
│   ├── certs/
│   │   ├── server.crt         # Certificat Ed25519 auto-signé
│   │   └── server.key         # Clé privée Ed25519
│   └── graphs/
│       ├── graph1_comparison_times.png
│       ├── graph2_proof_sizes.png
│       ├── graph3_handshake_overhead.png
│       ├── graph5_overhead_breakdown.png
│       └── graph6_comparison_summary.png
├── demo_dvnizk_server.py      # Démo serveur (nouveau)
├── demo_dvnizk_client.py      # Démo client (nouveau)
├── benchmark_dvnizk.py        # Benchmark performance (nouveau)
├── test_dvnizk_tls13.py       # Test unitaire handshake (nouveau)
├── README.md                  # Ce fichier
└── ...                        # Fichiers originaux tlslite-ng (inchangés)
```

### 3.2 Flux de données

```
Serveur                                      Client
  │                                             │
  │  x_serveur, P_serveur                       │
  │  P_client (depuis ClientHello key_share)    │
  │  hash_transcription                         │
  │                                             │
  │  Algo 1 : generate_proof()                  │
  │    → R1 = r1·G        (branche réelle)      │
  │    → R2 = s2·G - c2·P (branche simulée)     │
  │    → c = SHA-512(...)                       │
  │    → s1 = r1 + c1·x                        │
  │                                             │
  │  sérialisation : 160 octets                 │
  │                                             │
  │  ──── CertificateVerify ─────────────────→  │
  │                                             │
  │                            Algo 2 : verify_proof()
  │                              → c = SHA-512(...)
  │                              → vérifier s1·G = R1 + c1·P_serveur
  │                              → vérifier s2·G = R2 + c2·P_client
  │                                             │
  │                            (optionnel)
  │                            Algo 3 : simulate_proof()
  │                              → distribution identique
```

---

## 4. Module central : `tlslite/dvnizk.py`

### 4.1 Constantes

| Symbole | Valeur | Description |
|---------|--------|-------------|
| `n` | `2²⁵² + 27742317777372353535851937790883648493` | Ordre du groupe Ed25519 |
| `p` | `2²⁵⁵ − 19` | Caractéristique du corps premier |

### 4.2 Conversion de clés

```python
def x25519_to_ed25519(u_bytes: bytes) -> bytes
```

Convertit une coordonnée u Montgomery X25519 (32 octets) en coordonnée y
Edwards Ed25519 (32 octets) via la correspondance birationnelle :

```
u = (1 + y) / (1 − y)   ⇔   y = (u − 1) / (u + 1)  mod p
```

Nécessaire car TLS 1.3 négocie X25519 pour l'échange de clés (RFC 7748)
mais nous devons représenter la clé publique du client comme un point
Ed25519 pour la preuve OU. La conversion est déterministe et sans perte
pour les clés publiques X25519 valides.

```python
def eddsakey_to_scalar_and_pub(key) -> tuple
```

Extrait le scalaire privé (après dérivation SHA-512 de la graine et
clampage selon RFC 8032 §5.1.5) et les octets bruts de la clé publique
d'un objet `EdDSAKey` de tlslite-ng. La graine est
`key.private_key.to_string()` (32 octets) ; le scalaire est
`SHA-512(graine)[0:32]` avec le clampage Ed25519 standard.

### 4.3 Utilitaires sur les scalaires

| Fonction | Description |
|----------|-------------|
| `random_scalar()` | Retourne `os.urandom(32) mod n` |
| `scalar_to_bytes(s)` | Encodage 32 octets little-endian |
| `bytes_to_scalar(b)` | Décode 32 octets `mod n` |

### 4.4 Opérations de groupe (via PyNaCl/libsodium)

| Fonction | Opération | Liaison PyNaCl |
|----------|-----------|----------------|
| `point_base_mul(s)` | `s · G` | `crypto_scalarmult_ed25519_base_noclamp` |
| `point_mul(s, P)` | `s · P` | `crypto_scalarmult_ed25519_noclamp` |
| — (add) | `P + Q` | `crypto_core_ed25519_add` |
| — (sub) | `P − Q` | `crypto_core_ed25519_sub` |

Toutes les opérations utilisent les variantes **no-clamp** pour permettre
des scalaires arbitraires dans le groupe complet `ℤₙ`.

### 4.5 Hachage du défi

```python
def hash_to_scalar(*args: bytes) -> int
```

Calcule `SHA-512(args[0] ‖ args[1] ‖ ...)` et réduit le digest modulo `n`.
Le séparateur de domaine `"DVNIZK-ECC"` est passé comme premier argument
à chaque appel pour prévenir les attaques inter-protocoles.

### 4.6 Algorithme 1 — Génération de la preuve (Serveur)

```python
def generate_proof(x_serveur: int, P_serveur: bytes, P_client: bytes,
                   hash_transcription: bytes) -> dict
```

**Entrées :**
- `x_serveur` : scalaire privé du serveur (après clampage)
- `P_serveur` : clé publique Ed25519 du serveur (32 octets)
- `P_client` : clé publique Ed25519 du client (32 octets, convertie de X25519)
- `hash_transcription` : hash de transcription TLS 1.3 (SHA-256)

**Algorithme :**
```
1. r1 ← aléatoire ℤₙ, R1 = r1·G
2. c2 ← aléatoire ℤₙ, s2 ← aléatoire ℤₙ, R2 = s2·G − c2·P_client
3. c = SHA-512("DVNIZK-ECC", R1, R2, P_serveur, P_client, hash_transcription) mod n
4. c1 = c − c2 mod n, s1 = r1 + c1·x_serveur mod n
5. Retourner (R1, R2, s1, s2, c2)
```

**Dict de sortie :**
| Clé | Type | Taille |
|-----|------|--------|
| `R1` | bytes | 32 |
| `R2` | bytes | 32 |
| `s1` | int | scalaire |
| `s2` | int | scalaire |
| `c2` | int | scalaire |
| `gen_time_us` | float | mesure |

### 4.7 Algorithme 2 — Vérification de la preuve (Client)

```python
def verify_proof(preuve: dict, P_serveur: bytes, P_client: bytes,
                 hash_transcription: bytes) -> tuple
```

**Retourne :** `(valide: bool, temps_vérification_us: float)`

**Algorithme :**
```
1. Analyser (R1, R2, s1, s2, c2) depuis la preuve
2. c = SHA-512("DVNIZK-ECC", R1, R2, P_serveur, P_client, hash_transcription) mod n
3. c1 = c − c2 mod n
4. Vérifier : s1·G == R1 + c1·P_serveur
5. Vérifier : s2·G == R2 + c2·P_client
6. Retourner Vrai ssi les deux vérifications passent
```

### 4.8 Algorithme 3 — Simulation de la preuve (Client)

```python
def simulate_proof(x_client: int, P_serveur: bytes, P_client: bytes,
                   hash_transcription: bytes) -> dict
```

**Algorithme :**
```
1. r2 ← aléatoire ℤₙ, R2 = r2·G
2. c1 ← aléatoire ℤₙ, s1 ← aléatoire ℤₙ, R1 = s1·G − c1·P_serveur
3. c = SHA-512("DVNIZK-ECC", R1, R2, P_serveur, P_client, hash_transcription) mod n
4. c2 = c − c1 mod n, s2 = r2 + c2·x_client mod n
5. Retourner (R1, R2, s1, s2, c2)
```

### 4.9 Sérialisation

| Fonction | Description |
|----------|-------------|
| `serialize_proof(preuve) → bytes` | Concatène `R1 ‖ R2 ‖ s1_octets ‖ s2_octets ‖ c2_octets` = 160 octets |
| `deserialize_proof(données) → dict` | Divise 160 octets en composants ; lève `ValueError` si longueur erronée |

Format de sérialisation (ordre sur le fil) :

```
Offset  Taille  Contenu
0       32      R1 (point Ed25519 compressé)
32      32      R2 (point Ed25519 compressé)
64      32      s1 (scalaire little-endian)
96      32      s2 (scalaire little-endian)
128     32      c2 (scalaire little-endian)
```

---

## 5. Intégration TLS 1.3

### 5.1 Identifiant du schéma de signature

```python
# tlslite/constants.py
dvnizk_ed25519 = (254, 0)   # Plage d'usage privé RFC 8446 (0xFE00)
```

La valeur `(254, 0)` correspond à l'octet `0xFE00` au format TLS,
qui tombe dans la plage **d'usage privé** (0xFE00–0xFEFF) réservée par
RFC 8446 §4.2.3. Cela garantit l'absence de collision avec les schémas
de signature enregistrés par l'IANA.

### 5.2 Côté serveur (Génération de la preuve)

Emplacement : `tlsconnection.py:3192–3227`

Lorsque la clé du serveur est Ed25519 et que les schémas de signature
annoncés par le client incluent `dvnizk_ed25519` :

1. **Analyser le key_share du ClientHello** — extraire la clé publique
   X25519 du client depuis la première extension key_share.
2. **Convertir X25519 → Ed25519** — appeler `x25519_to_ed25519()`
   (si X25519 est utilisé).
3. **Extraire le scalaire serveur** — appeler `eddsakey_to_scalar_and_pub()`
   pour dériver le scalaire Ed25519 clampé et les octets de la clé publique.
4. **Calculer le hash de transcription** —
   `self._handshake_hash.digest(prf_name)` inclut : ClientHello, ServerHello,
   EncryptedExtensions, Certificate, et CertificateVerify (jusqu'à la
   signature elle-même).
5. **Générer la preuve** —
   `dvnizk.generate_proof(x_serveur, P_serveur, P_client, hash_transcription)`.
6. **Sérialiser et envoyer** — sérialiser en 160 octets, emballer dans un
   message `CertificateVerify` avec `signatureAlgorithm = dvnizk_ed25519`.

### 5.3 Côté client (Vérification de la preuve)

Emplacement : `tlsconnection.py:1459–1496`

Lorsque le client reçoit un `CertificateVerify` avec `dvnizk_ed25519` :

1. **Désérialiser** — `dvnizk.deserialize_proof(certificate_verify.signature)`.
2. **Obtenir la clé publique du serveur** — octets Ed25519 bruts depuis le
   certificat serveur.
3. **Obtenir la clé éphémère du client** — calculer la valeur publique depuis
   la clé privée locale du client ; convertir X25519 → Ed25519 si nécessaire.
4. **Calculer le hash de transcription** — `srv_cert_verify_hh.digest(prfName)`.
5. **Vérifier** — `dvnizk.verify_proof(objet_preuve, P_serveur, P_client,
   hash_transcription)`.
6. **Échouer gracieusement** — en cas d'échec, envoyer une alerte
   `decrypt_error` et abandonner le handshake.

### 5.4 Sécurisation du défi

Le défi Fiat-Shamir lie :

| Composant | Source | Objectif |
|-----------|--------|----------|
| `"DVNIZK-ECC"` | chaîne constante | Séparation de domaine |
| `R1, R2` | engagements de la preuve | Empêche le rejeu des engagements |
| `P_serveur` | certificat serveur | Lie la preuve à l'identité du serveur |
| `P_client` | ClientHello key_share | Lie la preuve à la session |
| `hash_transcription` | hash de handshake TLS 1.3 | Lie la preuve à la transcription complète |

### 5.5 Intégration au schéma de clés

DVNIZK-ECC **ne modifie pas** le schéma de clés TLS 1.3. Le handshake
dérive toujours `client_handshake_traffic_secret`,
`server_handshake_traffic_secret` et `master_secret` à l'identique de
RFC 8446. Le message `CertificateVerify` (après vérification de la preuve)
est alimenté dans le hash de transcription exactement comme une signature
standard. Les messages `Finished` vérifient ensuite la transcription
complète incluant la preuve DVNIZK, garantissant l'intégrité de
l'authentification.

### 5.6 Déroulement du handshake

```
ClientHello (key_share : X25519 éphémère)
    │
ServerHello (key_share : X25519 éphémère)
    │
EncryptedExtensions
    │
Certificate (certificat Ed25519)
    │
CertificateVerify (preuve dvnizk_ed25519 — 160 octets)
    │
Finished (la transcription inclut la preuve)
    │
─────────────────────────────────
    │
Finished (la transcription inclut la preuve)
    │
[Données d'application]
```

---

## 6. Fichiers modifiés

### 6.1 `tlslite/constants.py`

- Ajout de `dvnizk_ed25519 = (254, 0)` à la classe `SignatureScheme`
  (ligne 268).
- Extension de `getKeyType()` pour retourner `"eddsa"` pour
  `"dvnizk_ed25519"` (ligne 287), garantissant qu'il est traité comme
  un type de clé EdDSA dans toute la logique de handshake.

### 6.2 `tlslite/handshakesettings.py`

- Ajout de `"dvnizk_ed25519"` à la liste `SIGNATURE_SCHEMES` (ligne 39),
  inséré après `"ed25519"` pour être pris en compte lors de la négociation
  des algorithmes de signature.

### 6.3 `tlslite/tlsconnection.py`

**Trois points d'intégration :**

1. **Vérification côté client** (lignes 1459–1496) : dans le gestionnaire
   `_clientReceiveCertificateVerify` du client, une nouvelle branche vérifie
   `signature_scheme == dvnizk_ed25519` et appelle `dvnizk.verify_proof()`.

2. **Génération côté serveur** (lignes 3192–3227) : dans
   `_serverSendCertificateVerify`, une nouvelle branche pour
   `scheme == "dvnizk_ed25519"` génère et sérialise la preuve via
   `dvnizk.generate_proof()`.

3. **Filtrage des algorithmes de signature** (ligne 5188) : la méthode
   `_clientFilterSigAlgs` est modifiée pour accepter `dvnizk_ed25519`
   lorsque le type de certificat est `"Ed25519"`, garantissant que le
   schéma apparaît dans l'extension `signature_algorithms` du client.

---

## 7. Applications de démonstration

### 7.1 Serveur (`demo_dvnizk_server.py`)

Un serveur TLS 1.3 autonome qui :
- Charge un certificat et une clé Ed25519 depuis `dvnizk_ecc/certs/server.{crt,key}`.
- Écoute sur un port configurable (défaut 8443).
- Gère chaque connexion client dans un thread séparé.
- Utilise `dvnizk_ed25519` pour le CertificateVerify du serveur.
- Renvoie un message de bienvenue et lit un message du client.

**Utilisation :**
```bash
python demo_dvnizk_server.py [port]
```

### 7.2 Client (`demo_dvnizk_client.py`)

Un client TLS 1.3 autonome qui :
- Se connecte à un serveur DVNIZK sur un hôte/port configurable
  (défaut `127.0.0.1:8443`).
- Annonce à la fois `dvnizk_ed25519` et `ed25519` dans
  signature_algorithms (avec DVNIZK préféré).
- Vérifie la preuve DVNIZK du serveur à la réception de CertificateVerify.
- Lit le message de bienvenue du serveur et envoie une réponse.

**Utilisation :**
```bash
python demo_dvnizk_client.py [hôte] [port]
```

### 7.3 Génération des certificats

Les certificats de test dans `dvnizk_ecc/certs/` sont des certificats
auto-signés Ed25519 générés avec :
```bash
openssl req -x509 -newkey ed25519 -keyout server.key -out server.crt -days 365 -nodes
```

---

## 8. Tests

### 8.1 Test unitaire (`test_dvnizk_tls13.py`)

Un `unittest.TestCase` qui effectue un handshake TLS 1.3 complet entre
deux objets `TLSConnection` via une paire de sockets en mémoire :

- Charge le certificat et la clé Ed25519 du serveur.
- Configure le client pour annoncer `dvnizk_ed25519` (avec repli sur
  `ed25519`).
- Pilote les générateurs de handshake asynchrones
  (`handshakeServerAsync` / `handshakeClientCert`) via un helper
  `_perform_handshake` qui échange les tampons d'écriture
  bidirectionnellement.
- Vérifie que `handshake_completed` est `True` pour les deux côtés et
  que l'algorithme négocié est `dvnizk_ed25519`.

**Exécution :**
```bash
python -m pytest test_dvnizk_tls13.py -v
```

### 8.2 Auto-test (`dvnizk.py __main__`)

L'exécution directe de `dvnizk.py` exerce les quatre opérations
principales avec des clés aléatoires et un hash de transcription
simulé :
```bash
python -m tlslite.dvnizk
```
Sortie attendue :
```
[1] Génération de la preuve (serveur)...
    Temps de génération : 160.9 µs
    Taille preuve       : 160 octets (5 × 32)

[2] Vérification de la preuve (client)...
    Résultat            : ✓ VALIDE
    Temps vérification  : 286.1 µs

[3] Simulation par le client (Théorème 4)...
    Preuve simulée valide : ✓ OUI
    → Non-transférabilité démontrée

[4] Test de sérialisation...
    Taille sérialisée   : 160 octets
    Preuve désérialisée : ✓ VALIDE

[5] Comparaison tailles :
    Signature EdDSA standard : 64 octets
    Preuve DVNIZK-ECC       : 160 octets (+96 octets)
```

---

## 9. Benchmark

### 9.1 Script de benchmark (`benchmark_dvnizk.py`)

Le benchmark mesure :

| Test | Description | Méthode |
|------|-------------|---------|
| 1. Primitives Ed25519 | `hashAndSign` / `hashAndVerify` (python-ecdsa) | 100 itérations |
| 2. Primitives DVNIZK | `generate_proof` / `verify_proof` / `simulate_proof` (PyNaCl) | 100 itérations |
| 3. Handshake Ed25519 | Handshake TLS 1.3 complet, CertificateVerify ed25519 | 100 itérations |
| 4. Handshake DVNIZK | Handshake TLS 1.3 complet, CertificateVerify dvnizk_ed25519 | 100 itérations |
| 5. Tailles des paquets | Tailles des payloads CertificateVerify | mesure directe |

**Options :**
```bash
python benchmark_dvnizk.py --iterations 200    # Changer le nombre d'itérations
python benchmark_dvnizk.py --output ./graphs/  # Générer des graphiques matplotlib
python benchmark_dvnizk.py --no-charts         # Désactiver les graphiques
```

### 9.2 Résultats (Intel Core i7-8665U, 50 itérations)

| Métrique | Ed25519 | DVNIZK-ECC | Différence |
|----------|---------|------------|------------|
| Génération / signature | 591 µs | 205 µs | −65 % |
| Vérification | 4648 µs | 341 µs | −93 % |
| Handshake total | 19 277 µs | 19 264 µs | ~0 % |
| Taille CertificateVerify | 64 octets | 160 octets | +96 octets |

### 9.3 Interprétation

DVNIZK-ECC semble significativement plus rapide qu'Ed25519 dans ce
benchmark, mais il s'agit d'un **artefact de backend** :

- **Ed25519** utilise la bibliothèque `python-ecdsa` intégrée à
  tlslite-ng (Python pur).
- **DVNIZK-ECC** utilise PyNaCl, qui encapsule **libsodium** (C optimisé
  avec opérations en temps constant).

Dans une implémentation C native (ex. les deux utilisant OpenSSL), le
surcoût de DVNIZK-ECC serait d'environ **2–3 multiplications scalaires**
par rapport à une signature Ed25519 standard — soit un ralentissement
d'environ 2–3× au niveau des primitives cryptographiques. Pour le
handshake complet, la différence est négligeable (<0,1 %) car les E/S
réseau et l'échange de clés asymétrique dominent.

La garantie de temps constant s'applique à la **couche C de libsodium**,
pas à la couche Python ; le flux de contrôle Python (vérifications
conditionnelles, appels de fonction) peut introduire des variations
temporelles dépendant des données au niveau de la microseconde.

### 9.4 Graphiques de benchmark

Des graphiques pré-générés sont disponibles dans `dvnizk_ecc/graphs/` :

| Graphique | Fichier | Description |
|-----------|---------|-------------|
| Graphique 1 | `graph1_comparison_times.png` | Temps d'exécution des primitives |
| Graphique 2 | `graph2_proof_sizes.png` | Tailles des preuves |
| Graphique 3 | `graph3_handshake_overhead.png` | Surcoût du handshake |
| Graphique 5 | `graph5_overhead_breakdown.png` | Répartition du surcoût |
| Graphique 6 | `graph6_comparison_summary.png` | Résumé comparatif |

---

## 10. Considérations de sécurité

### 10.1 Non-transférabilité

La fonction `simulate_proof` (Algorithme 3) génère des preuves
**statistiquement indistinguables** des preuves réelles générées par
le serveur. Cela signifie :

- Un tiers possédant une transcription ne peut pas déterminer si elle
  a été produite par le serveur ou simulée par le client.
- Le client peut toujours répudier une transcription en prétendant
  l'avoir simulée.
- **Mise en garde :** La non-transférabilité s'applique uniquement à
  la couche d'authentification. Les informations de canaux auxiliaires
  (adresses IP, synchronisation, contenu des données d'application)
  peuvent toujours lier une session à une partie spécifique.

### 10.2 Solidité

Un adversaire qui produit une preuve valide sans connaître `x_serveur`
ni `x_client` doit résoudre le problème du logarithme discret pour au
moins une clé publique. Ceci est garanti par la propriété d'extraction
des preuves OU : le rembobinage de l'adversaire donne deux preuves
avec les défis `c` et `c'` (`c ≠ c'`), à partir desquels le témoin
peut être calculé via :

```
x = (s1 − s1') / (c1 − c1')  mod n   (extraction serveur)
x = (s2 − s2') / (c2 − c2')  mod n   (extraction client)
```

### 10.3 Séparation de domaine

Le hachage du défi inclut la chaîne fixe `"DVNIZK-ECC"` comme préfixe.
Cela garantit que les preuves DVNIZK-ECC ne peuvent pas être rejouées
comme des signatures Ed25519 standard ou comme des preuves pour d'autres
protocoles qui pourraient utiliser des constructions Fiat-Shamir
similaires.

### 10.4 Liaison à la transcription

Le `hash_transcription` passé au hachage du défi inclut tous les messages
du handshake TLS 1.3 jusqu'au message Certificate inclus (selon RFC 8446
§4.4.3). Cela lie la preuve au contexte exact du handshake, empêchant les
attaques par copier-coller entre sessions.

### 10.5 Compromission de clés

- **Compromission de la clé serveur :** un attaquant avec `x_serveur`
  peut générer des preuves valides, mais la capacité de simulation du
  client signifie que le serveur peut toujours nier avoir authentifié
  une session particulière.
- **Compromission de la clé éphémère du client :** un attaquant avec
  `x_client` peut simuler des preuves pour n'importe quel serveur auquel
  le client s'est connecté. Ceci est atténué par l'utilisation de clés
  X25519 éphémères (par session), donc la compromission de la clé
  éphémère d'une session n'affecte pas les sessions passées ou futures.

---

## 11. Limites

### 11.1 Surcoût de performance (backend natif)

Dans un déploiement de production utilisant des bibliothèques C natives
(ex. OpenSSL, BoringSSL) pour Ed25519 et DVNIZK-ECC, la génération de
preuve nécessiterait environ 2–3× plus de multiplications scalaires
qu'une signature Ed25519 standard :
- Ed25519 signe : 1 multiplication scalaire (nonce déterministe via SHA-512)
- DVNIZK-ECC gen : 4 multiplications scalaires (2 pour la branche 1,
  2 pour la branche 2)

La preuve de 160 octets est également 2,5× plus grande qu'une signature
Ed25519 de 64 octets.

### 11.2 Maturité de l'implémentation

- L'implémentation est une **preuve de concept** et n'a pas fait l'objet
  d'un audit de sécurité par un tiers.
- Le backend Ed25519 `python-ecdsa` est connu pour être plus lent que
  libsodium pour la vérification — la comparaison du benchmark est
  biaisée par le choix du backend.
- Un seul **schéma de signature** (`dvnizk_ed25519`) est implémenté ;
  l'extension à Ed448 ou ECDSA (P-256/P-384) est directe mais n'a pas
  été réalisée.

### 11.3 Garanties de temps constant

Bien que libsodium fournisse des opérations de courbe en temps constant,
la couche Python ajoute un flux de contrôle non constant :
- Instructions `if` Python, gestion d'exceptions, `int.from_bytes` /
  `.to_bytes`
- Chemins de code conditionnels dans la génération de preuve (non
  présents — les deux branches calculent toujours les mêmes opérations)

Une implémentation de production devrait minimiser les branches au
niveau Python ou implémenter la preuve entière en C/Rust.

### 11.4 Hypothèse de key_share unique

L'implémentation suppose que le client envoie un seul key_share X25519
dans `ClientHello.key_share`. C'est la configuration la plus courante
mais ne gère pas le cas où le client envoie plusieurs key_shares ou
utilise une courbe différente.

---

## 12. Démarrage rapide

### 12.1 Installation

```bash
git clone https://github.com/MARKUPsoft-corp/TLS-DVNIZK.git
cd TLS-DVNIZK
python3 -m venv venv
source venv/bin/activate
pip install pynacl
```

### 12.2 Auto-test

```bash
python -m tlslite.dvnizk
```

### 12.3 Démo (deux terminaux)

Terminal 1 (serveur) :
```bash
source venv/bin/activate
python demo_dvnizk_server.py
```

Terminal 2 (client) :
```bash
source venv/bin/activate
python demo_dvnizk_client.py
```

Sortie attendue :
```
SERVEUR DVNIZK-ECC — TLS 1.3
Handshake TLS 1.3 réussi !
    Algorithme : dvnizk_ed25519
```

### 12.4 Exécution des tests

```bash
python -m pytest test_dvnizk_tls13.py -v
```

### 12.5 Benchmark

```bash
python benchmark_dvnizk.py --output dvnizk_ecc/graphs
```

---

## 13. Références

### Académiques

- **YAKAM TCHAMEGNI Emmanuel.** *Conception et implémentation d'un mécanisme
  d'authentification non-transférable pour TLS 1.3 utilisant des preuves à
  divulgation nulle de connaissance.* Mémoire de Master 2, Université de
  Yaoundé I, 2024–2025.
- **Cramer, R., Damgård, I., Schoenmakers, B.** (1994). Proofs of partial
  knowledge and simplified design of witness hiding protocols. *CRYPTO '94*.
- **Bernstein, D. J. et al.** (2012). High-speed high-security signatures.
  *Journal of Cryptographic Engineering*, 2(2):77–89.
- **Bernstein, D. J.** (2006). Curve25519: New Diffie-Hellman speed records.
  *PKC 2006*.

### Normes

- **RFC 8446** — The Transport Layer Security (TLS) Protocol Version 1.3
- **RFC 8032** — EdDSA (Ed25519 and Ed448)
- **RFC 7748** — Elliptic Curves for Security (Curve25519 and Curve448)

### Logiciels

- **tlslite-ng :** https://github.com/tlsfuzzer/tlslite-ng
- **PyNaCl :** https://github.com/pyca/pynacl/
- **libsodium :** https://doc.libsodium.org/
- **Dépôt TLS-DVNIZK :** https://github.com/MARKUPsoft-corp/TLS-DVNIZK

---

Vous trouverez ci-dessous le **README original de tlslite-ng** (v0.9.0b2)
documentant les fonctionnalités de la bibliothèque de base, l'installation
et l'utilisation de l'API.

---

tlslite-ng version 0.9.0b2 (2025-09-26)

[![GitHub CI](https://github.com/tlsfuzzer/tlslite-ng/actions/workflows/ci.yml/badge.svg)](https://github.com/tlsfuzzer/tlslite-ng/actions/workflows/ci.yml)
[![Read the Docs](https://img.shields.io/readthedocs/tlslite-ng)](https://tlslite-ng.readthedocs.io/en/latest/)
[![Coverage Status](https://coveralls.io/repos/tlsfuzzer/tlslite-ng/badge.svg?branch=master)](https://coveralls.io/r/tlsfuzzer/tlslite-ng?branch=master)
[![Code Climate](https://codeclimate.com/github/tlsfuzzer/tlslite-ng/badges/gpa.svg)](https://codeclimate.com/github/tlsfuzzer/tlslite-ng)

Table of Contents
==================

1. Introduction
1. License/Acknowledgements
1. Installation
1. Getting Started with the Command-Line Tools
1. Getting Started with the Library
1. Using tlslite-ng with httplib
1. Using tlslite-ng with poplib or imaplib
1. Using tlslite-ng with smtplib
1. Using tlslite-ng with SocketServer
1. Using tlslite-ng with asyncore
1. History

1 Introduction
===============

tlslite-ng is an open source python library that implements SSL and
[TLS](https://en.wikipedia.org/wiki/Transport_Layer_Security)
cryptographic protocols. It can be used either as a standalone wrapper around
python socket interface or as a backend for multiple other libraries.
tlslite-ng is pure python, however it can use other libraries for faster crypto
operations. tlslite-ng integrates with several stdlib networking libraries.

API documentation is available in the `docs/_build/html` directory of the PyPI
package
or can be automatically generated using `make docs` with Sphinx installed.

If you have questions or feedback, feel free to contact me (Alicja Kario
&lt;hkario at redhat.com>). Issues and pull
requests can also be submitted through github issue tracking system, at the
project's main page at [GitHub](https://github.com/tlsfuzzer/tlslite-ng), see
[CONTRIBUTING.md](https://github.com/tlsfuzzer/tlslite-ng/blob/master/CONTRIBUTING.md)
file for more information.

tlslite-ng aims to be a drop in replacement for the original TLS Lite.

Security policy of the project is available in the
[SECURITY.md](https://github.com/tlsfuzzer/tlslite-ng/blob/master/SECURITY.md)
file.

Implemented TLS features include:

* SSLv3, TLSv1.0, TLSv1.1, TLSv1.2 and TLSv1.3
* ciphersuites with DHE, ADH, ECDHE, AECDH, ML-KEM, RSA and SRP
  key exchange together
  with AES (CBC, GCM, CCM and CCM_8), 3DES, RC4 and ChaCha20 (both the official
  standard and the IETF draft) symmetric ciphers and NULL encryption.
* PSK and PSK-(EC)DHE key exchange in TLSv1.3
* Secure Renegotiation
* Encrypt Then MAC extension
* TLS_FALLBACK_SCSV
* Extended master secret
* padding extension
* keying material exporter
* RSA, RSA-PSS, DSA, ECDSA, EdDSA, and ML-DSA certificates
* ticket based session resumption
* 1-RTT handshake, Hello Retry Request, middlebox compatibility mode,
  cookie extension, post-handshake authentication and KeyUpdate
  (TLS 1.3)
* FFDHE supported_groups extension
* X25519 and X448 ECDHE key exchange
* Ed25519 and Ed448 EdDSA signatures
* (experimental) TACK extension
* heartbeat extension and protocol
* Record Size Limit extension
* Delegated Credential for TLS

2 Licenses/Acknowledgements
============================

tlslite-ng is a fork of TLS Lite, it is currently maintained and developed by
Alicja Kario. TLS Lite was written (mostly) by Trevor
Perrin. It includes code from Bram Cohen, Google, Kees Bos, Sam Rushing,
Dimitris Moraitis, Marcelo Fernandez, Martin von Loewis, Dave Baggett, Yngve
N. Pettersen (ported by Paul Sokolovsky), Mirko Dziadzka, David Benjamin,
Sidney Markowitz, and Alicja Kario.

Original code in TLS Lite has either been dedicated to the public domain by its
authors, or placed under a BSD-style license. See the LICENSE file for
details.

Currently it is distributed under Gnu LGPLv2 license.

3 Installation
===============

Requirements:

* Python 2.6 or higher is required.
* Python 3.7 or higher is supported.
* python ecdsa >= 0.13.3 library
  ([GitHub](https://github.com/warner/python-ecdsa),
  [PyPI](https://pypi.python.org/pypi/ecdsa))

Options:

* If you have the `m2crypto` interface to OpenSSL, this will be used for fast
  RSA operations and fast ciphers.
* If you have `pycrypto` this will be used for fast RSA operations and fast
  ciphers.
* If you have the `gmpy` interface to libgmp, this will be used for fast RSA,
  FFDH and SRP operations.
* These modules don't need to be present at installation - you can install
  them any time.

3.1 Automatic
-------------

Run:

```
pip install tlslite-ng
```

In case your system doesn't have pip, you can install it by first downloading
[get-pip.py](https://bootstrap.pypa.io/get-pip.py) and running

```
python get-pip.py
```

3.2 Manual
----------

Run 'python setup.py install'

Test the Installation

* From the distribution's directory, run:

    ```
    make test
    ```

* If it says "Test succeeded" at the end, you're ready to go.

4 Getting Started with the Command-Line Tools
==============================================

tlslite-ng installs two command-line scripts: `tlsdb.py` and `tls.py`.

`tls.py` lets you run test clients and servers. It can be used for testing
other TLS implementations, or as example code. Note that `tls.py server` runs
an HTTPS server which will serve files rooted at the current directory by
default, so be careful.

`tlsdb.py` lets you manage SRP verifier databases. These databases are used by
a TLS server when authenticating clients with SRP.

X.509
------

To run an X.509 server, go to the ./tests directory and do:

```
tls.py server -k serverX509Key.pem -c serverX509Cert.pem localhost:4443
```

Try connecting to the server with a web browser, or with:

```
tls.py client localhost:4443
```

X.509 with TACK
----------------

To run an X.509 server using a TACK, install TACKpy, then run the same server
command as above with added arguments:

```
... -t TACK1.pem localhost:4443
```

SRP
----

To run an SRP server, try something like:

```
tlsdb.py createsrp verifierDB
tlsdb.py add verifierDB alice abra123cadabra 1024
tlsdb.py add verifierDB bob swordfish 2048

tls.py server -v verifierDB localhost:4443
```

Then try connecting to the server with:

```
tls.py client -u alice -p abra123cadabra localhost:4443
```

HTTPS
------

To run an HTTPS server with less typing, run `./tests/httpsserver.sh`.

To run an HTTPS client, run `./tests/httpsclient.py`.

5 Getting Started with the Library
===================================

Whether you're writing a client or server, there are six steps:

1. Create a socket and connect it to the other party.
1. Construct a TLSConnection instance with the socket.
1. Call a handshake function on TLSConnection to perform the TLS handshake.
1. Check the results to make sure you're talking to the right party.
1. Use the TLSConnection to exchange data.
1. Call close() on the TLSConnection when you're done.

tlslite-ng also integrates with several stdlib python libraries. See the
sections following this one for details.

5 Step 1 - create a socket
---------------------------

Below demonstrates a socket connection to Amazon's secure site.

```
  from socket import *
  sock = socket(AF_INET, SOCK_STREAM)
  sock.connect( ("www.amazon.com", 443) )
```

5 Step 2 - construct a TLSConnection
-------------------------------------

You can import tlslite objects individually, such as:

```
  from tlslite import TLSConnection
```

Or import the most useful objects through:

```
  from tlslite.api import *
```

Then do:

```
  connection = TLSConnection(sock)
```

5 Step 3 - call a handshake function (client)
----------------------------------------------

If you're a client, there's two different handshake functions you can call,
depending on how you want to authenticate:

```
  connection.handshakeClientCert()
  connection.handshakeClientCert(certChain, privateKey)

  connection.handshakeClientSRP("alice", "abra123cadabra")
```

The ClientCert function without arguments is used when connecting to a site
like Amazon, which doesn't require client authentication, but which will
authenticate itself using an X.509 certificate chain.

The ClientCert function can also be used to do client authentication with an
X.509 certificate chain and corresponding private key. To use X.509 chains,
you'll need some way of creating these, such as OpenSSL (see
[HOWTO](http://www.openssl.org/docs/HOWTO/) for details).

Below is an example of loading an X.509 chain and private key:

```
  from tlslite import X509, X509CertChain, parsePEMKey
  s = open("./test/clientX509Cert.pem").read()
  x509 = X509()
  x509.parse(s)
  certChain = X509CertChain([x509])
  s = open("./test/clientX509Key.pem").read()
  privateKey = parsePEMKey(s, private=True)
```

The SRP function does mutual authentication with a username and password - see
RFC 5054 for details.

If you want more control over the handshake, you can pass in a
HandshakeSettings instance. For example, if you're performing SRP, but you
only want to use SRP parameters of at least 2048 bits, and you only want to
use the AES-256 cipher, and you only want to allow TLS (version 3.1), not SSL
(version 3.0), you can do:

```
  settings = HandshakeSettings()
  settings.minKeySize = 2048
  settings.cipherNames = ["aes256"]
  settings.minVersion = (3,1)
  settings.useExperimentalTACKExtension = True  # Needed for TACK support

  connection.handshakeClientSRP("alice", "abra123cadabra", settings=settings)
```

If you want to check the server's certificate using TACK, you should set the
"useExperiementalTACKExtension" value in HandshakeSettings. (Eventually, TACK
support will be enabled by default, but for now it is an experimental feature
which relies on a temporary TLS Extension number, and should not be used for
production software.) This will cause the client to request the server to send
you a TACK (and/or any TACK Break Signatures):

Finally, every TLSConnection has a session object. You can try to resume a
previous session by passing in the session object from the old session. If the
server remembers this old session and supports resumption, the handshake will
finish more quickly. Otherwise, the full handshake will be done. For example:

```
  connection.handshakeClientSRP("alice", "abra123cadabra")
  .
  .
  oldSession = connection.session
  connection2.handshakeClientSRP("alice", "abra123cadabra", session=
  oldSession)
```

5 Step 3 - call a handshake function (server)
----------------------------------------------

If you're a server, there's only one handshake function, but you can pass it
several different parameters, depending on which types of authentication
you're willing to perform.

To perform SRP authentication, you have to pass in a database of password
verifiers.  The VerifierDB class manages an in-memory or on-disk verifier
database.

```
  verifierDB = VerifierDB("./test/verifierDB")
  verifierDB.open()
  connection.handshakeServer(verifierDB=verifierDB)
```

To perform authentication with a certificate and private key, the server must
load these as described in the previous section, then pass them in.  If the
server sets the reqCert boolean to True, a certificate chain will be requested
from the client.

```
  connection.handshakeServer(certChain=certChain, privateKey=privateKey,
                             reqCert=True)
```

You can pass in a verifier database and/or a certificate chain+private key.
The client will use one or both to authenticate the server.

You can also pass in a HandshakeSettings object, as described in the last
section, for finer control over handshaking details.

If you are passing in a certificate chain+private key, you may additionally
provide a TACK to assist the client in authenticating your certificate chain.
This requires the TACKpy library. Load a TACKpy.TACK object, then do:

```
  settings = HandshakeSettings()
  settings.useExperimentalTACKExtension = True  # Needed for TACK support

  connection.handshakeServer(certChain=certChain, privateKey=privateKey,
                             tack=tack, settings=settings)
```

Finally, the server can maintain a SessionCache, which will allow clients to
use session resumption:

```
  sessionCache = SessionCache()
  connection.handshakeServer(verifierDB=verifierDB, sessionCache=sessionCache)
```

It should be noted that the session cache, and the verifier databases, are all
thread-safe.

5 Step 4 - check the results
-----------------------------

If the handshake completes without raising an exception, authentication
results will be stored in the connection's session object.  The following
variables will be populated if applicable, or else set to None:

```
  connection.session.srpUsername       # string
  connection.session.clientCertChain   # X509CertChain
  connection.session.serverCertChain   # X509CertChain
  connection.session.tackExt           # TACKpy.TACK_Extension
```

X.509 chain objects return the end-entity fingerprint via getFingerprint(),
and ignore the other certificates.

TACK objects return the (validated) TACK ID via getTACKID().

To save yourself the trouble of inspecting certificates after the handshake,
you can pass a Checker object into the handshake function. The checker will be
called if the handshake completes successfully. If the other party isn't
approved by the checker, a subclass of TLSAuthenticationError will be raised.

If the handshake fails for any reason, including a Checker error, an exception
will be raised and the socket will be closed. If the socket timed out or was
unexpectedly closed, a socket.error or TLSAbruptCloseError will be raised.

Otherwise, either a TLSLocalAlert or TLSRemoteAlert will be raised, depending
on whether the local or remote implementation signalled the error. The
exception object has a 'description' member which identifies the error based
on the codes in RFC 2246. A TLSLocalAlert also has a 'message' string that may
have more details.

Example of handling a remote alert:

```
  try:
      [...]
  except TLSRemoteAlert as alert:
      if alert.description == AlertDescription.unknown_psk_identity:
          print "Unknown user."
  [...]
```

Below are some common alerts and their probable causes, and whether they are
signalled by the client or server.

Client `handshake_failure`:

* SRP parameters are not recognized by client
* Server's TACK was unrelated to its certificate chain

Client `insufficient_security`:

* SRP parameters are too small

Client `protocol_version`:

* Client doesn't support the server's protocol version

Server `protocol_version`:

* Server doesn't support the client's protocol version

Server `bad_record_mac`:

* bad SRP username or password

Server `unknown_psk_identity`:

* bad SRP username (`bad_record_mac` could be used for the same thing)

Server `handshake_failure`:

* no matching cipher suites

5 Step 5 - exchange data
-------------------------

Now that you have a connection, you can call read() and write() as if it were
a socket.SSL object. You can also call send(), sendall(), recv(), and
makefile() as if it were a socket. These calls may raise TLSLocalAlert,
TLSRemoteAlert, socket.error, or TLSAbruptCloseError, just like the handshake
functions.

Once the TLS connection is closed by the other side, calls to read() or recv()
will return an empty string. If the socket is closed by the other side without
first closing the TLS connection, calls to read() or recv() will return a
TLSAbruptCloseError, and calls to write() or send() will return a
socket.error.

5 Step 6 - close the connection
--------------------------------

When you're finished sending data, you should call close() to close the
connection and socket. When the connection is closed properly, the session
object can be used for session resumption.

If an exception is raised the connection will be automatically closed; you
don't need to call close(). Furthermore, you will probably not be able to
re-use the socket, the connection object, or the session object, and you
shouldn't even try.

By default, calling close() will close the underlying socket. If you set the
connection's closeSocket flag to False, the socket will remain open after
close. (NOTE: some TLS implementations will not respond properly to the
`close_notify` alert that close() generates, so the connection will hang if
closeSocket is set to True.)

6 Using tlslite-ng with httplib
===============================

tlslite-ng comes with an HTTPTLSConnection class that extends httplib to work
over SSL/TLS connections.  Depending on how you construct it, it will do
different types of authentication.

```
  #No authentication whatsoever
  h = HTTPTLSConnection("www.amazon.com", 443)
  h.request("GET", "")
  r = h.getresponse()
  [...]

  #Authenticate server based on its TACK ID
  h = HTTPTLSConnection("localhost", 4443,
          tackID="B3ARS.EQ61B.F34EL.9KKLN.3WEW5", hardTack=False)
  [...]

  #Mutually authenticate with SRP
  h = HTTPTLSConnection("localhost", 443,
          username="alice", password="abra123cadabra")
  [...]
```

7 Using tlslite-ng with poplib or imaplib
=========================================

tlslite-ng comes with `POP3_TLS` and `IMAP4_TLS` classes that extend poplib and
imaplib to work over SSL/TLS connections.  These classes can be constructed
with the same parameters as HTTPTLSConnection (see previous section), and
behave similarly.

```
  #To connect to a POP3 server over SSL and display its fingerprint:
  from tlslite.api import *
  p = POP3_TLS("---------.net", port=995)
  print p.sock.session.serverCertChain.getFingerprint()
  [...]

  #To connect to an IMAP server once you know its fingerprint:
  from tlslite.api import *
  i = IMAP4_TLS("cyrus.andrew.cmu.edu",
          x509Fingerprint="00c14371227b3b677ddb9c4901e6f2aee18d3e45")
  [...]
```

8 Using tlslite-ng with smtplib
===============================

tlslite-ng comes with an `SMTP_TLS` class that extends smtplib to work
over SSL/TLS connections.  This class accepts the same parameters as
HTTPTLSConnection (see previous section), and behaves similarly.  Depending
on how you call starttls(), it will do different types of authentication.

```
  #To connect to an SMTP server once you know its fingerprint:
  from tlslite.api import *
  s = SMTP_TLS("----------.net", port=587)
  s.ehlo()
  s.starttls(x509Fingerprint="7e39be84a2e3a7ad071752e3001d931bf82c32dc")
  [...]
```

9 Using tlslite-ng with SocketServer
====================================

You can use tlslite-ng to implement servers using Python's SocketServer
framework.  tlslite-ng comes with a TLSSocketServerMixIn class.  You can combine
this with a TCPServer such as HTTPServer.  To combine them, define a new class
that inherits from both of them (with the mix-in first). Then implement the
handshake() method, doing some sort of server handshake on the connection
argument.  If the handshake method returns True, the RequestHandler will be
triggered.  See the tests/httpsserver.py example.

10 Using tlslite-ng with asyncore (or asyncio - Python 3.12+)
=================================

tlslite-ng can be used with subclasses of asyncore.dispatcher.  See the comments
in TLSAsyncDispatcherMixIn.py for details.  This is still experimental, and
may not work with all asyncore.dispatcher subclasses.

as said above, asyncore is deprecated in Python 3.12, and asyncio should be used.
Implementation is similar to TLSAsyncDispatcherMixIn.py, but instead, use the class
TLSAsyncioDispatcherMixIn.py.

11 Using the ```credential``` tool
=================================

The credential tool is a command-line utility used to generate a [Delegated Credential](https://datatracker.ietf.org/doc/rfc9345/) for a TLS 1.3 server.

To generate the Delegated Credential:

```
tls.py credential [-c CERT] [-k KEY] [--dc-pub KEY] [--dc-sig-scheme SIG] [--dc-file DCFILE]
```

To generate the DC the following MUST be provided: the certificate, the certificate's private key, the public key of the Delegated Credential and the output file. Providing signature scheme is optional.

The content is saved into the output file in ```.pem``` format.

The following command provides an illustrative example using RSA keys for both the main server certificate and the delegated credential's public key to create Delegated Credential. Go to the tests directory and run:

```
tls.py credential -k serverX509Key.pem -c serverX509Cert.pem --dc-pub serverDelCredRSAPSSPub.pem --dc-file  serverRSAPSSDC.pem
```

After that the server can be run without the certificate's private key, but with the Delegated Credential:
```
tls.py server -c serverX509Cert.pem --dc-key serverDelCredRSAPSSKey.pem --dc-file serverRSAPSSDC.pem localhost:4433
```

The client must indicate the support of Delegated Credential by provideng the signature algorithm it supports in the Delegated Credential's extesion in Client Hello.

In case creating the file with saved Delegated Credential is not an option, the server can create the Delegated Credential on the fly before the handshake.
To do so, run:
```
tls.py server -k serverX509Key.pem -c serverX509Cert.pem --dc-key serverDelCredRSAPSSKey.pem --dc-pub serverDelCredRSAPSSPub.pem localhost:4433
```
### Important Note

According to RFC 5280, [Section 4.2.1.3](https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.3) and specifically [RFC 9260](https://datatracker.ietf.org/doc/rfc9345/) (Delegated Credentials), Section 4, the X.509 certificate used by the server to sign a delegated credential MUST contain the ```digitalSignature``` Key Usage extension. The ```credential``` tool and the delegated credential generation feature within the ```server``` tool are designed primarily for **testing and development purposes**. Hence, these tools do not perform strict validation to ensure that the provided main server certificate actually possesses the ```digitalSignature``` Key Usage extension.
Similarly, while delegated credentials have a valid time option, it is not enforced. The current certificate implementation lacks time validation, a requirement that is also omitted for delegated credentials.


12 History
===========

0.9.0b2 - 2025-09-26
* support for Delegated Credentials (Ganna Starovoytova)
* (Experimental) support for ML-DSA certificates in TLS

0.8.2 - 2025-01-22
* additional test vectors for the RSA implicit rejection mechanism
* fix negotiation of TLS 1.2 Brainpool key exchanges in TLS 1.3, only
  TLS 1.3 specific groups now can be negotiated in TLS 1.3

0.8.1 - 2025-01-02
* apply checks to `ec_point_formats` extension only when negotiating TLS 1.2
  or earlier (Ganna Starovoytova)

0.8.0 - 2024-12-17
* DEPRECATION NOTICE: camelCase method and argument names are considered now
  deprecated, ones that use underscore_separator are now the primary ones
  (the procedure to support it is not yet finished, but any new code must
  follow this new style and new deprecations will be introduced as time goes
  on. Please run your test suite with `-Wd` to see where the depracated calls
  are being made, the python standard DeprecationWarning will be emited there)
* Python 3.2, 3.3, and 3.4 is not supported any more (dropped by python-ecdsa)
* fix compatibility issue with 8192 bit SRP group from RFC 5054
* fix CVE-2018-1000159 - incorrect verification of MAC in MAC then Encrypt
  mode
* workaround CVE-2020-26263 - Bleichenbacher oracle in RSA decryption.
  Please note that while the code was fortified, because of peculiarities of
  python, it's not possible to fully fix it. If you require resistance against
  side-channel attacks please use a different library.
* fix Python_RSAKey multithreading support - performing private key operation
  in two threads at the same time could make all future calls return incorrect
  results
* Python 3.7 support (`async` is now a keyword) (Pierre Ståhl)
* Python 3.8 test suite compatibility
* Python 3.9 support (slight changes in imaplib caused our wrapper to stop
  working)
* Compatibility with M2Crypto on Python 3
* fix Python 2 comaptibility issue with X.509 DER parsing (Erkki Vahala)
* TLS 1.3
  * final RFC 8446 support
  * TLS 1.3 specific ciphers (AES-GCM, AES-CCM, AES-CCM8 and Chacha20)
  * TLS 1.3 specific extensions and extension code points
  * 1-RTT handshake mode
  * HelloRetryRequest support
  * PSK with (EC)DH key exchange
  * pure PSK
  * session resumption in TLS 1.3 using PSK tickets
  * padding support (Stanislav Zidek)
  * 0-RTT handshake tolerance (the early data will be ignored but handshake
    will succeed)
  * cookie extension
  * downgrade sentinels in ServerHello.random
  * TLS Keying Material Exporter support in TLS 1.3 (Simo Sorce)
  * client certificate support (Simo Sorce)
  * KeyUpdate support
  * post-handshake key authentication
* fix minor compatibility issue with Jython2.7 (Filip Goldefus)
* higher precision of throughput measurement on non-Linux platforms
  (Efthimis Iosifidis)
* refactor keyexchange.py module to make (EC)DH key exchange standalone
* more human readable errors upon receiving unexpected messages
* `__eq__` supported on all Handshake messages
* fix minor bugs in message objects, extend test coverage for tlslite.messages
* repr() for Certificate and few extensions
* OCSP response parsing (Anna Khaitovich)
* OCSP signature verification (Anna Khaitovich)
* matching OCSP response to EE and CA certificate (Anna Khaitovich)
* fix HTTP header length leak in the test server (`tls.py`) (Róbert Kolcún)
* minor fixes with sent alerts when encountering error conditions
* fix lack of checking if the padding in SSLv3 is minimal
* Pure Python 3DES implementation (Adam Varga)
* heartbeat (RFC 6520) (Milan Lysonek)
* support chain of certificates in the `tls.py` script
* fix sending of RSA-PSS certificate when the client didn't advertise support
  for `rsa_pss_pss_*` signature methods
* clearly state in documentation that inputs to signature and verification
  methods of RSA keys need to be bytes-like objects
* support for setting maximum supported version in tls.py server and client
* support for record_size_limit extension from RFC 8449
* make the number of session tickets sent to client configurable (TLS 1.3
  specific)
* reimplement HMAC in pure python to work-around platforms that disable MD5
  HMAC in python (this goes against FIPS requirements)
* fix few minor bugs in handling heartbeat messages
* support for ECDSA certificates (server and client, all versions of TLS)
* support for multiple certificates on the server (RSA, RSA-PSS, ECDSA
  can be configured together, including multiple instances of the same type,
  server will select automatically the one that matches requirements from
  ClientHello)
* support for HelloRequest messages (only for encoding/decoding, renegotiation
  is still unsupported)
* nicer error messages when parsing malformed exceptions, TLS messages in
  general
* AES-CCM and AES-CCM8 support (in TLS 1.2 and TLS 1.3) (Ivan Nikolchev)
* added support for configuring enabled ciphers in `tls.py` (Ivan Nikolchev)
* two times faster 3DES when using m2crypto (Alexander Sosedkin)
* correct handling of malformed X.509 certificates (Ivan Nikolchev)
* speed up AES-CCM and AES-GCM when m2crypto is installed (Ivan Nikolchev)
* client side checks for downgrade protection from TLS 1.3 (Ivan Nikolchev)
* use TLS 1.3 test vectors to verify the implementation (Ivan Nikolchev)
* unify master secret and finished calculation (Ivan Nikolchev)
* detect pycryptodome, disable pycrypto code if it's present
* add multiple well-known DH groups from RFC 2409, RFC 5114 and RFC 3526,
  unify formatting of the existing DH group (use exactly the formatting used
  in the RFC's)
* add benchmarking tool for RSA (`scripts/speed.py`)
* add support for gmpy2, use it and gmpy in more places for RSA calculations
  (minor speed up for RSA operations)
* refactor certificate selection, make server select certificate based on
  curves and signature algorithms advertised by client (Ivan Nikolchev)
* basic support for DSA certificates; verification of DSA signatures
  in ServerKeyExchange (Frantisek Krenzelok)
* support for DSA client certificates
* small optimisations to PRF methods, speeds to handshake
* support for MD5 signatures in X.509 certificates (Jean-Romain Garnier)
* add support for Brainpool curves in TLS 1.2 and earlier (pytz)
* fix wrong error message in AES implementation (Bernt Røskar Brenna)
* migrate to Github Action for CI
* fix API break caused by the workaround for Bleichenbacher; RSA keys generated
  in-memory with m2crypto wouldn't work for decryption/encryption
* handle too short RSA ciphertexts for the key size consistently between
  backends
* strict handling of CCS in TLS 1.3 (don't allow it post handshake)
* detect and reject multi-byte CCS messages
* improved RSA key generation - don't generate biased primes
* support for both encodings of RSA-PSS algorithm identifier in X.509
* Support for EdDSA (Ed25519 and Ed448) in TLS 1.2 and TLS 1.3, both
  for server and client certificates
* Support for echo server in the example tls.py script
* Better handling of HMACs in FIPS mode
* Generate RSA keys with 65537 as public exponent with m2crypto (as with
  other backends)
* Ticket based session resumption in TLS 1.2 and earlier
* strict size checking of `session_id` field in ClientHello
* use python-ecdsa code for parsing ECDH key shares, speed up calculation
  of shared secrets (Ganna Starovoytova)
* fix sending of session ticket extension from the server without
  a ticket (George Pantelakis)
* add support for Brainpool curves in TLS 1.3 from RFC 8734
* add support for compress_certificate extension from RFC 8879
  (George Pantelakis)
* Fix int_to_bytes and numberToByteArray encoding of 0 with length not
  specified, and thus also ClientKeyExchange handling for DHE with missing
  key share
* (Experimental) Support for hybrid KEM key exchange groups from
  draft-kwiatkowski-tls-ecdhe-mlkem-02. To work, kyber-py v1.0 library must
  be installed.
* support for setting a list of supported key exchange groups in the
  `tls.py server`
* support for ec_point_format extension (Ganna Starovoytova)

0.7.0 - 2017-07-31

* enable and add missing definitions of TLS_ECDHE_RSA_WITH_RC4_128_SHA and
  TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA
* add definitions of some ECDHE_ECDSA, ECDH_ECDSA and ECDH_RSA ciphersuites,
  they remain unsupported, but IDs are useful for other projects
* basic support for RSA-PSS (Tomas Foukal)
* support for RSA-PSS in TLSv1.2
* better documentation for Parser and ASN1Parser
* stricter checks on network messages
* faster Codec (faster encoding of messages to binary format)
* faster AES implementation initialization
* ability to set custom Diffie-Hellman parameters for connection
* support for negotiation of bigger Diffie-Hellman groups using RFC 7919
  mechanism
* fix sent alerts in case the ALPN extension is malformed
* add support for checking SNI on server side, making sure we send valid
  hostnames in extension
* fix testsuite when run on Windows
* fix interoperability issue in DHE key exchange (failure happening in about
  1 in 256 negotiations) caused by handling of Server Key Exchange messages
* Fix incorrect handling of Extended Master Secret with client certificates,
  follow RFC recommendations with regards to session resumption, reject
  non-empty
* Allow negotiation of ECDHE ciphersuites even if client doesn't advertise
  any curves, default to P-256 curve support, support configuring the default
* Stricter checks on received SNI (server_name) extension
* Support for x25519 and x448 curve for ECDHE

0.6.0 - 2016-09-07

* added support for ALPN from RFC 7301
* fixed handling of SRP databases
* fixed compatibility issues with Python 3
* fixed compatibility with Python 2.7.3
* AECDH support on server side (Milan Lysonek)
* make the Client Hello parser more strict, it will now abort if the
  extensions extend past the length of extension field
* make the decoder honour the 2^14 byte protocol limit on plaintext per record
* fix sending correct alerts on receiving malformed or invalid messages in
  handshake
* proper signalling for Secure Renegotiation (renegotiation remains unsupported
  but server now indicates that the extension was understood and will abort
  if receiving a renegotiated hello)
* stop server from leaking lengths of headers in HTTP responses when using
  standard library modules
* HMAC-based Extract-and-Expand Key Derivation Function (HKDF) implementation
  from RFC 5869 (Tomas Foukal)
* added protection against
  [RSA-CRT key leaks](https://people.redhat.com/~fweimer/rsa-crt-leaks.pdf)
  (Tomas Foukal)
* Keying material exporter from RFC 5705
* Session Hash a.k.a. Extended Master Secret extension from RFC 7627
* make the library work on systems working in FIPS mode
* support for the padding extension from RFC 7685 (Karel Srot)
* abitlity to perform reverse lookups on many of the TLS type enumerations
* added ECDHE_RSA key exchange together with associated ciphersuites
* refactor key exchange code to remove duplication and make adding new methods
  easier
* add support for all hashes for ServerKeyExchange and CertificateVerify
  messages in TLS 1.2
* mark library as compatible with Python 3.5 (it was previously, but now
  it is verified with Continous Integration)
* cleanups (style fixes, deduplication of code) and more documentation
* add support for ChaCha20 and Poly1305 (both the IETF draft and released
  standard) with both ECDHE_RSA and DHE_RSA key exchange
* expose padding and MAC-ing functions and blockSize property in RecordLayer

0.5.1 - 2015-11-05

* fix SRP_SHA_RSA ciphersuites in TLSv1.2 (for real this time)
* minor enchancements in test scripts
* NOTE: KeyExchange class is not part of stable API yet (it will be moved to
  different module later)!

0.5.0 - 10/10/2015

* fix generators in AsyncStateMachine to work on Python3 (Theron Lewis)
* fix CVE-2015-3220 - remote DoS caused by incorrect malformed packet handling
* removed RC4 from ciphers supported by default
* add supported_groups, supported_point_formats, signature_algorithms and
  renegotiation_info extensions
* remove most CBC MAC-ing and padding timing side-channel leaks (should fix
  CVE-2013-0169, a.k.a. Lucky13)
* add support for NULL encryption - TLS_RSA_WITH_NULL_MD5,
  TLS_RSA_WITH_NULL_SHA and TLS_RSA_WITH_NULL_SHA256 ciphersuites
* add more ADH ciphers (TLS_DH_ANON_WITH_RC4_128_MD5,
  TLS_DH_ANON_WITH_3DES_EDE_CBC_SHA, TLS_DH_ANON_WITH_AES_128_CBC_SHA256,
  TLS_DH_ANON_WITH_AES_256_CBC_SHA256, TLS_DH_ANON_WITH_AES_128_GCM_SHA256,
  TLS_DH_ANON_WITH_AES_256_GCM_SHA384)
* implement a TLS record layer abstraction that makes it very easy to handle
  TLS handshake and alert protocol messages (MessageSocket)
* fix reqCert option in tls.py server
* implement AES-256-GCM ciphersuites and SHA384 PRF
* implement AES-GCM cipher and AES-128-GCM ciphersuites (David Benjamin -
  Chromium)
* implement client side DHE_RSA key exchange and DHE with certificate based
  client authentication
* implement server side DHE_RSA key exchange (David Benjamin - Chromium)
* don't use TLSv1.2 ciphers in earlier protocols (David Benjamin - Chromium)
* fix certificate-based client authentication in TLSv1.2 (David Benjamin -
  Chromium)
* fix SRP_SHA_RSA ciphersuites
* properly implement record layer fragmentation (previously worked just for
  Application Data) - RFC 5246 Section 6.2.1
* Implement RFC 7366 - Encrypt-then-MAC
* generate minimal padding for CBC ciphers (David Benjamin - Chromium)
* implementation of `FALLBACK_SCSV` (David Benjamin - Chromium)
* fix issue with handling keys in session cache (Mirko Dziadzka)
* coverage measurement for unit tests
* introduced Continous Integration, targetting 2.6, 2.7, 3.2, 3.3 and 3.4
* support PKCS#8 files with m2crypto installed for loading private keys
* fix Writer not to silently overflow integers
* fix Parser getFixBytes boundary checking
* big code refactors, mainly TLSRecordLayer and TLSConnection, lot of code put
  under unit test coverage

0.4.8 - 11/12/2014

* Added more acknowledgements and security considerations

0.4.7 - 11/12/2014

* Added TLS 1.2 support (Yngve Pettersen and Paul Sokolovsky)
* Don't offer SSLv3 by default (e.g. POODLE)
* Fixed bug with `PyCrypto_RSA` integration
* Fixed harmless bug that added non-prime into sieves list
* Added "make test" and "make test-dev" targets (Alicja Kario)

0.4.5 - 3/20/2013

* **API CHANGE**: TLSClosedConnectionError instead of ValueError when writing
  to a closed connection.  This inherits from socket.error, so should
  interact better with SocketServer (see [issue14574](http://bugs.python.org/issue14574))
  and other things expecting a socket.error in this situation.
* Added support for RC4-MD5 ciphersuite (if enabled in settings)
  * This is allegedly necessary to connect to some Internet servers.
* Added TLSConnection.unread() function
* Switched to New-style classes (inherit from 'object')
* Minor cleanups

0.4.4 - 2/25/2013

* Added Python 3 support (Martin von Loewis)
* Added NPN client support (Marcelo Fernandez)
* Switched to RC4 as preferred cipher
  * faster in Python, avoids "Lucky 13" timing attacks
* Fixed bug when specifying ciphers for anon ciphersuites
* Made RSA hashAndVerify() tolerant of sigs w/o encoded NULL AlgorithmParam
  * (this function is not used for TLS currently, and this tolerance may
     not even be necessary)

0.4.3 - 9/27/2012

* Minor bugfix (0.4.2 doesn't load tackpy)

0.4.2 - 9/25/2012

* Updated TACK (compatible with tackpy 0.9.9)

0.4.1 - 5/22/2012

* Fixed RSA padding bugs (w/help from John Randolph)
* Updated TACK (compatible with tackpy 0.9.7)
* Added SNI
* Added NPN server support (Sam Rushing/Google)
* Added AnonDH (Dimitris Moraitis)
* Added X509CertChain.parsePemList
* Improved XML-RPC (Kees Bos)

0.4.0 - 2/11/2012

* Fixed pycrypto support
* Fixed python 2.6 problems

0.3.9.x - 2/7/2012

Much code cleanup, in particular decomposing the handshake functions so they
are readable. The main new feature is support for TACK, an experimental
authentication method that provides a new way to pin server certificates (See
[moxie0/Convergance](https://github.com/moxie0/Convergence/wiki/TACK) ).

Also:

* Security Fixes
  * Sends SCSV ciphersuite as per RFC 5746, to signal non-renegotiated
    Client Hello.  Does not support renegotiation (never has).
  * Change from e=3 to e=65537 for generated RSA keys, not strictly
    necessary but mitigates risk of sloppy verifier.
  * 1/(n-1) countermeasure for BEAST.

* Behavior changes:
  * Split cmdline into tls.py and tlstest.py, improved options.
  * Formalized LICENSE.
  * Defaults to closing socket after sending `close_notify`, fixes hanging.
    problem that would occur sometime when waiting for other party's
    close_notify.
  * Update SRP to RFC 5054 compliance.
  * Removed client handshake "callbacks", no longer support the SRP
    re-handshake idiom within a single handshake function.

* Bugfixes
  * Added hashlib support, removes Deprecation Warning due to sha and md5.
  * Handled GeneratorExit exceptions that are a new Python feature, and
    interfere with the async code if not handled.

* Removed:
  * Shared keys (it was based on an ancient I-D, not TLS-PSK).
  * cryptlib support, it wasn't used much, we have enough other options.
  * cryptoIDs (TACK is better).
  * win32prng extension module, as os.urandom is now available.
  * Twisted integration (unused?, slowed down loading).
  * Jython code (ancient, didn't work).
  * Compat support for python versions < 2.7.

* Additions
  * Support for TACK via TACKpy.
  * Support for `CertificateRequest.certificate_authorities` ("reqCAs")
  * Added TLSConnection.shutdown() to better mimic socket.
  * Enabled Session resumption for XMLRPCTransport.

0.3.8 - 2/21/2005

* Added support for poplib, imaplib, and smtplib
* Added python 2.4 windows installer
* Fixed occassional timing problems with test suite

0.3.7 - 10/05/2004

* Added support for Python 2.2
* Cleaned up compatibility code, and docs, a bit

0.3.6 - 9/28/2004

* Fixed script installation on UNIX
* Give better error message on old Python versions

0.3.5 - 9/16/2004

* TLS 1.1 support
* os.urandom() support
* Fixed win32prng on some systems

0.3.4 - 9/12/2004

* Updated for TLS/SRP draft 8
* Bugfix: was setting `_versioncheck` on SRP 1st hello, causing problems
  with GnuTLS (which was offering TLS 1.1)
* Removed `_versioncheck` checking, since it could cause interop problems
* Minor bugfix: when `cryptlib_py` and and cryptoIDlib present, cryptlib
  was complaining about being initialized twice

0.3.3 - 6/10/2004

* Updated for TLS/SRP draft 7
* Updated test cryptoID cert chains for cryptoIDlib 0.3.1

0.3.2 - 5/21/2004

* fixed bug when handling multiple handshake messages per record (e.g. IIS)

0.3.1 - 4/21/2004

* added xmlrpclib integration
* fixed hanging bug in Twisted integration
* fixed win32prng to work on a wider range of win32 sytems
* fixed import problem with cryptoIDlib
* fixed port allocation problem when test scripts are run on some UNIXes
* made tolerant of buggy IE sending wrong version in premaster secret

0.3.0 - 3/20/2004

* added API docs thanks to epydoc
* added X.509 path validation via cryptlib
* much cleaning/tweaking/re-factoring/minor fixes

0.2.7 - 3/12/2004

* changed Twisted error handling to use connectionLost()
* added ignoreAbruptClose

0.2.6 - 3/11/2004

* added Twisted errorHandler
* added TLSAbruptCloseError
* added 'integration' subdirectory

0.2.5 - 3/10/2004

* improved asynchronous support a bit
* added first-draft of Twisted support

0.2.4 - 3/5/2004

* cleaned up asyncore support
* added proof-of-concept for Twisted

0.2.3 - 3/4/2004

* added pycrypto RSA support
* added asyncore support

0.2.2 - 3/1/2004

* added GMPY support
* added pycrypto support
* added support for PEM-encoded private keys, in pure python

0.2.1 - 2/23/2004

* improved PRNG use (cryptlib, or /dev/random, or CryptoAPI)
* added RSA blinding, to avoid timing attacks
* don't install local copy of M2Crypto, too problematic

0.2.0 - 2/19/2004

* changed VerifierDB to take per-user parameters
* renamed `tls_lite` -> tlslite

0.1.9 - 2/16/2004

* added post-handshake 'Checker'
* made compatible with Python 2.2
* made more forgiving of abrupt closure, since everyone does it:
  if the socket is closed while sending/recv'ing `close_notify`,
  just ignore it.

0.1.8 - 2/12/2004

* TLSConnections now emulate sockets, including makefile()
* HTTPTLSConnection and TLSMixIn simplified as a result

0.1.7 - 2/11/2004

* fixed httplib.HTTPTLSConnection with multiple requests
* fixed SocketServer to handle `close_notify`
* changed handshakeClientNoAuth() to ignore CertificateRequests
* changed handshakeClient() to ignore non-resumable session arguments

0.1.6 - 2/10/2004

* fixed httplib support

0.1.5 - 2/09/2004

* added support for httplib and SocketServer
* added support for SSLv3
* added support for 3DES
* cleaned up read()/write() behavior
* improved HMAC speed

0.1.4 - 2/06/2004

* fixed dumb bug in tls.py

0.1.3 - 2/05/2004

* change read() to only return requested number of bytes
* added support for shared-key and in-memory databases
* added support for PEM-encoded X.509 certificates
* added support for SSLv2 ClientHello
* fixed shutdown/re-handshaking behavior
* cleaned up handling of `missing_srp_username`
* renamed readString()/writeString() -> read()/write()
* added documentation

0.1.2 - 2/04/2004

* added clienttest/servertest functions
* improved OpenSSL cipher wrappers speed
* fixed server when it has a key, but client selects plain SRP
* fixed server to postpone errors until it has read client's messages
* fixed ServerHello to only include extension data if necessary

0.1.1 - 2/02/2004

* fixed `close_notify` behavior
* fixed handling of empty application data packets
* fixed socket reads to not consume extra bytes
* added testing functions to tls.py

0.1.0 - 2/01/2004

* first release
