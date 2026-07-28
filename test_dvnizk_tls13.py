import unittest
import socket
import os
import sys

# Add the tlslite-ng directory to the path to allow imports from tlslite
# This allows running the test from the project root directory
sys.path.insert(0, os.path.abspath('implementation/tlslite-ng'))

from tlslite.tlsconnection import TLSConnection
from tlslite.handshakesettings import HandshakeSettings
from tlslite.x509 import X509
from tlslite.x509certchain import X509CertChain
from tlslite.utils.keyfactory import parsePEMKey  # Correction: keyfactory au lieu de rsakey
from tlslite.constants import SignatureScheme, AlertDescription
from tlslite.errors import TLSError  # Correction: TLSError au lieu de TLSHandshakeError

# Paths are now relative to the project root directory
CERT_PATH = 'dvnizk_ecc/certs/server.crt'
KEY_PATH = 'dvnizk_ecc/certs/server.key'

# Helper pour exécuter le handshake asynchrone
def _perform_handshake(client, server):
    """Effectue un handshake asynchrone entre deux TLSConnection."""
    c_gen = client
    s_gen = server
    c_wants_write = s_wants_write = False
    c_data = b''
    s_data = b''

    while not (c_gen is None and s_gen is None):
        try:
            if c_gen and not c_wants_write:
                c_wants_write = next(c_gen)
            if s_gen and not s_wants_write:
                s_wants_write = next(s_gen)
        except StopIteration:
            # Handshake terminé pour l'un des deux
            if c_gen: c_gen = None
            if s_gen: s_gen = None
            continue

        if c_wants_write:
            c_data += client.sock.get_write_buffer()
            client.sock.flush_write_buffer()
            c_wants_write = False
        
        if s_wants_write:
            s_data += server.sock.get_write_buffer()
            server.sock.flush_write_buffer()
            s_wants_write = False

        if c_data:
            server.sock.queue_read_data(c_data)
            c_data = b''

        if s_data:
            client.sock.queue_read_data(s_data)
            s_data = b''

class TestDVNIZK(unittest.TestCase):
    def test_dvnizk_handshake(self):
        """
        Teste un handshake TLS 1.3 complet en utilisant DVNIZK-ECC.
        """
        # 1. Charger le certificat et la clé du serveur
        with open(KEY_PATH, 'r') as f:  # 'r' au lieu de 'rb' pour avoir une string
            key_pem = f.read()
        private_key = parsePEMKey(key_pem, private=True)

        with open(CERT_PATH, 'r') as f:  # 'r' au lieu de 'rb'
            cert_pem = f.read()
        x509 = X509()
        x509.parse(cert_pem)
        cert_chain = X509CertChain([x509])

        # 2. Utiliser une paire de sockets "en mémoire" pour la communication
        client_sock, server_sock = socket.socketpair()

        # 3. Configurer le serveur
        server_settings = HandshakeSettings()
        server_settings.minVersion = (3, 4)
        server_settings.maxVersion = (3, 4)
        
        # 4. Configurer le client pour qu'il annonce DVNIZK
        client_settings = HandshakeSettings()
        client_settings.minVersion = (3, 4)
        client_settings.maxVersion = (3, 4)
        # Le client annonce sa préférence pour DVNIZK
        client_settings.signature_algorithms = [SignatureScheme.dvnizk_ed25519,
                                                SignatureScheme.ed25519]

        # 5. Initialiser les connexions
        server_conn = TLSConnection(server_sock)
        client_conn = TLSConnection(client_sock)

        try:
            # 6. Lancer les générateurs de handshake
            server_handshake = server_conn.handshakeServerAsync(
                certChain=cert_chain, 
                privateKey=private_key, 
                settings=server_settings)
            
            client_handshake = client_conn.handshakeClientCert(
                settings=client_settings)

            # 7. Exécuter le handshake
            _perform_handshake(client_handshake, server_handshake)

            # 8. Vérifier que le handshake a réussi et que DVNIZK a été utilisé
            self.assertTrue(client_conn.handshake_completed)
            self.assertTrue(server_conn.handshake_completed)
            self.assertEqual(server_conn.serverSigAlg, SignatureScheme.dvnizk_ed25519)
            
            print("\n\nHandshake DVNIZK-ECC réussi !")
            print(f"Algorithme négocié : {SignatureScheme.toStr(server_conn.serverSigAlg)}")

        except TLSError as e:
            self.fail(f"Le handshake DVNIZK a échoué avec l'erreur : {e}")
        finally:
            client_sock.close()
            server_sock.close()

if __name__ == '__main__':
    # Ce test doit être exécuté depuis la racine du projet
    unittest.main()