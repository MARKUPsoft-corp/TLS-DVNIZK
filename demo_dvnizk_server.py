#!/usr/bin/env python3
"""
Démonstration DVNIZK-ECC : Serveur TLS 1.3
============================================
Lance un serveur TLS 1.3 qui utilise DVNIZK-ECC
pour prouver la possession de sa clé privée Ed25519.

Usage :
    python demo_dvnizk_server.py [port]

Test :
    openssl s_client -connect localhost:8443 -tls1_3
        (ne fonctionnera PAS — le client doit comprendre DVNIZK)
    → Utiliser demo_dvnizk_client.py
"""
import os, sys, socket, threading, time

# Ajouter le répertoire courant au path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from tlslite.tlsconnection import TLSConnection
from tlslite.handshakesettings import HandshakeSettings
from tlslite.x509 import X509
from tlslite.x509certchain import X509CertChain
from tlslite.utils.keyfactory import parsePEMKey
from tlslite.constants import SignatureScheme

# Chemins des certificats (relatifs à la racine du projet)
CERT_PATH = os.path.join(os.path.dirname(__file__), 'dvnizk_ecc', 'certs', 'server.crt')
KEY_PATH  = os.path.join(os.path.dirname(__file__), 'dvnizk_ecc', 'certs', 'server.key')

SEP = "─" * 60

def main(port: int = 8443):
    print(f"\n  {SEP}", flush=True)
    print(f"  🖥  SERVEUR DVNIZK-ECC — TLS 1.3", flush=True)
    print(f"  {SEP}\n", flush=True)

    # 1. Charger certificat et clé
    print(f"  [1] Chargement du certificat Ed25519...")
    with open(KEY_PATH, 'r') as f:
        key_pem = f.read()
    private_key = parsePEMKey(key_pem, private=True)
    print(f"      ✓ Clé privée chargée   ({type(private_key).__name__})")

    with open(CERT_PATH, 'r') as f:
        cert_pem = f.read()
    x509 = X509()
    x509.parse(cert_pem)
    cert_chain = X509CertChain([x509])
    print(f"      ✓ Certificat chargé    ({len(cert_pem)} octets PEM)")

    # 2. Socket serveur
    srv_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv_sock.bind(('', port))
    srv_sock.listen(5)
    print(f"\n  [2] Serveur à l'écoute sur http://localhost:{port}")
    print(f"      (Ctrl+C pour arrêter)\n")
    print(f"  {SEP}\n")

    try:
        while True:
            conn, addr = srv_sock.accept()
            print(f"  📡 Connexion reçue de {addr[0]}:{addr[1]}")
            t = threading.Thread(target=handle_client,
                                 args=(conn, private_key, cert_chain),
                                 daemon=True)
            t.start()
    except KeyboardInterrupt:
        print("\n  Arrêt du serveur.")
    finally:
        srv_sock.close()

def handle_client(sock, private_key, cert_chain):
    settings = HandshakeSettings()
    settings.minVersion = (3, 4)
    settings.maxVersion = (3, 4)
    settings.keyShares = ['x25519']

    tls_conn = TLSConnection(sock)
    try:
        handshaker = tls_conn.handshakeServerAsync(
            certChain=cert_chain,
            privateKey=private_key,
            settings=settings,
            reqCert=False
        )
        for _ in handshaker:
            pass

        sig_alg = SignatureScheme.toStr(tls_conn.serverSigAlg)
        print(f"  ✅ Handshake TLS 1.3 réussi !")
        print(f"      Algorithme : {sig_alg}")
        print(f"      Version    : {'.'.join(str(v) for v in tls_conn.version)}")
        print(f"      Chiffrement: {tls_conn.session.cipherSuite}")

        tls_conn.write("Bienvenue ! Connexion DVNIZK-ECC etablie.\n".encode())
        data = tls_conn.read(4096)
        print(f"      Reçu client: {data.decode(errors='replace').strip()}")
        tls_conn.write("Message recu. Fin de la connexion.\n".encode())
    except Exception as e:
        print(f"  ❌ Erreur : {e}")
    finally:
        tls_conn.close()

if __name__ == '__main__':
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8443
    main(port)
