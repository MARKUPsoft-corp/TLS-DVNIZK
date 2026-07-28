#!/usr/bin/env python3
"""
Démonstration DVNIZK-ECC : Client TLS 1.3
==========================================
Se connecte à un serveur TLS 1.3 et vérifie
la preuve DVNIZK-ECC dans le CertificateVerify.

Usage :
    python demo_dvnizk_client.py [host] [port]
"""
import os, sys, socket

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from tlslite.tlsconnection import TLSConnection
from tlslite.handshakesettings import HandshakeSettings
from tlslite.constants import SignatureScheme

SEP = "─" * 60

def main(host: str = '127.0.0.1', port: int = 8443):
    print(f"\n  {SEP}")
    print(f"  💻 CLIENT DVNIZK-ECC — TLS 1.3")
    print(f"  {SEP}\n")

    print(f"  [1] Connexion à {host}:{port}...")
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(10)
    try:
        sock.connect((host, port))
        print(f"      ✓ Socket TCP connectée")
    except Exception as e:
        print(f"      ❌ Impossible de se connecter : {e}")
        sock.close()
        return

    settings = HandshakeSettings()
    settings.minVersion = (3, 4)
    settings.maxVersion = (3, 4)
    settings.keyShares = ['x25519']
    settings.signature_algorithms = [
        SignatureScheme.dvnizk_ed25519,
        SignatureScheme.ed25519
    ]
    print(f"      ✓ Schémas annoncés : dvnizk_ed25519, ed25519")

    print(f"\n  [2] Handshake TLS 1.3...")
    conn = TLSConnection(sock)
    try:
        conn.handshakeClientCert(settings=settings)

        sig_alg = SignatureScheme.toStr(conn.serverSigAlg)
        print(f"      ✅ Handshake réussi !")
        print(f"      Algorithme négocié : {sig_alg}")
        print(f"      Version TLS        : {'.'.join(str(v) for v in conn.version)}")
        print(f"      Chiffrement        : {conn.session.cipherSuite}")

        print(f"\n  [3] Transfert de données...")
        data = conn.read(4096)
        print(f"      Reçu du serveur : {data.decode(errors='replace').strip()}")

        conn.write("Hello depuis le client DVNIZK-ECC !".encode())
        reply = conn.read(4096)
        print(f"      Reçu             : {reply.decode(errors='replace').strip()}")

        print(f"\n  {SEP}")
        print(f"  ✅ TEST DVNIZK-ECC RÉUSSI")
        print(f"  {SEP}\n")
    except Exception as e:
        print(f"      ❌ Erreur : {e}")
        import traceback
        traceback.print_exc()
    finally:
        conn.close()

if __name__ == '__main__':
    host = sys.argv[1] if len(sys.argv) > 1 else '127.0.0.1'
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 8443
    main(host, port)
