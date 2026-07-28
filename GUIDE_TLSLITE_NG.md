# Guide d'utilisation de tlslite-ng

## 1. Qu'est-ce que tlslite-ng ?

**tlslite-ng** est une bibliothèque TLS écrite entièrement en Python. Elle permet de :
- Créer des connexions TLS sécurisées (client et serveur)
- Supporter SSL 3.0, TLS 1.0, 1.1, 1.2 et **TLS 1.3**
- Utiliser différents types d'authentification (certificats X.509, SRP, anonyme)

C'est un fork maintenu de la bibliothèque originale "TLS Lite".

---

## 2. Installation

### 2.1 Créer un environnement virtuel

```bash
# Créer l'environnement
python3 -m venv venv

# Activer l'environnement
source venv/bin/activate   # Linux/Mac
# ou
venv\Scripts\activate      # Windows
```

### 2.2 Installer tlslite-ng

```bash
# Installation en mode développement (éditable)
pip install -e .

# Ou installation normale
pip install tlslite-ng
```

### 2.3 Dépendances

- **Obligatoire** : `ecdsa` (installé automatiquement)
- **Optionnel** (pour de meilleures performances) :
  - `m2crypto` : Accélération RSA via OpenSSL
  - `pycryptodome` : Accélération des chiffrements
  - `gmpy2` : Accélération des calculs mathématiques

---

## 3. Utilisation en ligne de commande

tlslite-ng fournit deux scripts CLI :
- `tls.py` : Client/serveur TLS de test
- `tlsdb.py` : Gestion des bases de données SRP

### 3.1 Lancer un serveur HTTPS

```bash
# Serveur basique avec certificat X.509
python scripts/tls.py server \
    -k tests/serverX509Key.pem \
    -c tests/serverX509Cert.pem \
    localhost:4433

# Options utiles :
#   -k, --key     : Chemin vers la clé privée (PEM)
#   -c, --cert    : Chemin vers le certificat (PEM)
#   --reqcert     : Demander un certificat client
```

Le serveur sert les fichiers du répertoire courant via HTTPS.

### 3.2 Lancer un client TLS

```bash
# Client basique
python scripts/tls.py client localhost:4433

# Client avec certificat (authentification mutuelle)
python scripts/tls.py client \
    -k tests/clientX509Key.pem \
    -c tests/clientX509Cert.pem \
    localhost:4433
```

### 3.3 Exemple de session complète

**Terminal 1 - Serveur :**
```bash
source venv/bin/activate
python scripts/tls.py server -k tests/serverX509Key.pem -c tests/serverX509Cert.pem localhost:4433
```

**Terminal 2 - Client :**
```bash
source venv/bin/activate
python scripts/tls.py client localhost:4433
```

**Sortie attendue du client :**
```
Handshake success
  Version: TLS 1.3
  Cipher: aes256gcm python
  Ciphersuite: TLS_AES_256_GCM_SHA384
  Key exchange signature: rsa_pss_rsae_sha512
  Group used for key exchange: secp256r1
  ...
```

---

## 4. Utilisation comme bibliothèque Python

### 4.1 Client TLS simple

```python
from socket import socket, AF_INET, SOCK_STREAM
from tlslite import TLSConnection

# 1. Créer et connecter un socket
sock = socket(AF_INET, SOCK_STREAM)
sock.connect(("www.example.com", 443))

# 2. Envelopper avec TLS
tls = TLSConnection(sock)

# 3. Effectuer le handshake
tls.handshakeClientCert()

# 4. Vérifier la connexion
print(f"Version: {tls.version}")
print(f"Cipher: {tls.session.cipherSuite}")

# 5. Envoyer/recevoir des données
tls.send(b"GET / HTTP/1.1\r\nHost: www.example.com\r\n\r\n")
response = tls.recv(4096)
print(response.decode())

# 6. Fermer
tls.close()
```

### 4.2 Serveur TLS simple

```python
from socket import socket, AF_INET, SOCK_STREAM
from tlslite import TLSConnection, X509, X509CertChain, parsePEMKey

# Charger le certificat et la clé
with open("server.crt") as f:
    cert = X509().parse(f.read())
cert_chain = X509CertChain([cert])

with open("server.key") as f:
    private_key = parsePEMKey(f.read(), private=True)

# Créer le socket serveur
server_sock = socket(AF_INET, SOCK_STREAM)
server_sock.bind(("localhost", 4433))
server_sock.listen(5)

print("Serveur en écoute sur localhost:4433")

while True:
    # Accepter une connexion
    client_sock, addr = server_sock.accept()
    print(f"Connexion de {addr}")
    
    # Envelopper avec TLS
    tls = TLSConnection(client_sock)
    
    # Handshake serveur
    tls.handshakeServer(certChain=cert_chain, privateKey=private_key)
    
    # Échanger des données
    data = tls.recv(4096)
    tls.send(b"HTTP/1.1 200 OK\r\n\r\nHello TLS!")
    
    tls.close()
```

### 4.3 Configuration avancée avec HandshakeSettings

```python
from tlslite import HandshakeSettings

settings = HandshakeSettings()

# Versions TLS autorisées
settings.minVersion = (3, 3)  # TLS 1.2 minimum
settings.maxVersion = (3, 4)  # TLS 1.3 maximum

# Algorithmes de chiffrement
settings.cipherNames = ["aes256gcm", "aes128gcm", "chacha20-poly1305"]

# Courbes elliptiques
settings.eccCurves = ["secp256r1", "secp384r1", "x25519"]

# Algorithmes de signature
settings.rsaSigHashes = ["sha256", "sha384", "sha512"]

# Appliquer les settings
tls.handshakeClientCert(settings=settings)
```

---

## 5. Structure du code source

```
tlslite-ng/
├── tlslite/                      # Code source principal
│   ├── tlsconnection.py          # Classe principale TLSConnection
│   ├── tlsrecordlayer.py         # Couche record (fragmentation, chiffrement)
│   ├── messages.py               # Messages du handshake (ClientHello, etc.)
│   ├── constants.py              # Constantes (types de messages, extensions)
│   ├── keyexchange.py            # Échange de clés (RSA, DHE, ECDHE)
│   ├── handshakesettings.py      # Configuration du handshake
│   ├── handshakehashes.py        # Calcul du transcript hash
│   ├── extensions.py             # Extensions TLS
│   ├── x509.py                   # Parsing des certificats X.509
│   └── utils/                    # Utilitaires cryptographiques
│       ├── rsakey.py             # Opérations RSA
│       ├── ecdsakey.py           # Opérations ECDSA
│       ├── cryptomath.py         # Fonctions mathématiques
│       └── ...
├── scripts/                      # Scripts CLI
│   ├── tls.py                    # Client/serveur de test
│   └── tlsdb.py                  # Gestion base SRP
├── tests/                        # Certificats et clés de test
│   ├── serverX509Cert.pem        # Certificat serveur RSA
│   ├── serverX509Key.pem         # Clé privée serveur RSA
│   ├── clientX509Cert.pem        # Certificat client RSA
│   └── ...
└── unit_tests/                   # Tests unitaires
```

---

## 6. Flux du handshake TLS 1.3

Voici ce qui se passe lors d'un handshake TLS 1.3 dans tlslite-ng :

```
Client                                              Serveur
   |                                                   |
   |  1. ClientHello                                   |
   |      - Version supportées                         |
   |      - Cipher suites                              |
   |      - Extensions (key_share, etc.)               |
   |  ------------------------------------------------>|
   |                                                   |
   |                          2. ServerHello           |
   |                              - Version choisie    |
   |                              - Cipher suite       |
   |                              - key_share          |
   |  <------------------------------------------------|
   |                                                   |
   |        [Chiffrement activé avec clés handshake]   |
   |                                                   |
   |                          3. EncryptedExtensions   |
   |  <------------------------------------------------|
   |                                                   |
   |                          4. Certificate           |
   |                              - Chaîne X.509       |
   |  <------------------------------------------------|
   |                                                   |
   |                          5. CertificateVerify  ←──┼── C'EST ICI !
   |                              - Signature du       |    On veut remplacer
   |                                transcript         |    par Guillou-Quisquater
   |  <------------------------------------------------|
   |                                                   |
   |                          6. Finished              |
   |                              - MAC du transcript  |
   |  <------------------------------------------------|
   |                                                   |
   |  7. Finished                                      |
   |  ------------------------------------------------>|
   |                                                   |
   |        [Chiffrement avec clés application]        |
   |                                                   |
   |  <============= Données applicatives ============>|
```

### Fichiers impliqués dans le handshake :

| Étape | Message | Fichier |
|-------|---------|---------|
| 1 | ClientHello | `messages.py` → classe `ClientHello` |
| 2 | ServerHello | `messages.py` → classe `ServerHello` |
| 3 | EncryptedExtensions | `messages.py` → classe `EncryptedExtensions` |
| 4 | Certificate | `messages.py` → classe `Certificate` |
| 5 | **CertificateVerify** | `messages.py` → classe `CertificateVerify` |
| 6-7 | Finished | `messages.py` → classe `Finished` |

Le handshake est orchestré par :
- `tlsconnection.py` → `_clientTLS13Handshake()` (côté client)
- `tlsconnection.py` → `_serverTLS13Handshake()` (côté serveur)

---

## 7. Le message CertificateVerify (notre cible)

### 7.1 Rôle

Le message `CertificateVerify` prouve que le serveur (ou client) possède la clé privée correspondant au certificat présenté. Il contient une **signature** du transcript hash.

### 7.2 Code actuel

```python
# Dans messages.py
class CertificateVerify(HandshakeMsg):
    def __init__(self, version):
        self.signatureAlgorithm = None  # Ex: rsa_pss_rsae_sha256
        self.signature = bytearray(0)   # La signature

    def create(self, signature, signatureAlgorithm):
        self.signature = signature
        self.signatureAlgorithm = signatureAlgorithm
```

### 7.3 Création de la signature

```python
# Dans keyexchange.py
class KeyExchange:
    @staticmethod
    def makeCertificateVerify(version, handshakeHashes, ...):
        # 1. Calculer les bytes à signer
        verifyBytes = bytearray(b'\x20' * 64 +          # Padding
                                b'TLS 1.3, server CertificateVerify\x00') + 
                      handshakeHashes.digest()
        
        # 2. Signer avec la clé privée RSA
        signature = privateKey.sign(verifyBytes, padding='pss', ...)
        
        # 3. Créer le message
        certVerify = CertificateVerify(version)
        certVerify.create(signature, signatureAlgorithm)
        return certVerify
```

### 7.4 Notre modification

On va remplacer cette signature par un échange ZKP Guillou-Quisquater :

```
Actuel (1 message):
    CertificateVerify { signature }

Proposé (3 messages):
    ZKP_Commitment { T = r^e mod n }
    ZKP_Challenge  { c = random }
    ZKP_Response   { t = r·s^c mod n }
```

---

## 8. Certificats de test disponibles

| Fichier | Type | Usage |
|---------|------|-------|
| `serverX509Cert.pem` | RSA | Certificat serveur |
| `serverX509Key.pem` | RSA | Clé privée serveur |
| `clientX509Cert.pem` | RSA | Certificat client |
| `clientX509Key.pem` | RSA | Clé privée client |
| `serverECCert.pem` | ECDSA | Certificat serveur EC |
| `serverECKey.pem` | ECDSA | Clé privée serveur EC |

Pour notre implémentation GQ, on utilisera les certificats **RSA** (serverX509*).

---

## 9. Lancer les tests

```bash
# Activer l'environnement
source venv/bin/activate

# Tests unitaires
python -m pytest unit_tests/

# Test d'intégration client/serveur
python tests/tlstest.py
```

---

## 10. Ressources

- **Code source** : https://github.com/tlsfuzzer/tlslite-ng
- **Documentation** : https://tlslite-ng.readthedocs.io/
- **RFC 8446** (TLS 1.3) : https://tools.ietf.org/html/rfc8446
