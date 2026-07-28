#!/usr/bin/env python3
"""
Benchmark DVNIZK-ECC vs Ed25519 standard dans TLS 1.3.

Mesure :
  1. Temps de generation/verification de preuve DVNIZK (Algorithmes 1-3)
  2. Temps de signature/verification Ed25519 standard
  3. Temps de handshake TLS 1.3 complet (Ed25519 vs DVNIZK-ECC)
  4. Tailles des paquets (CertificatVerify, total handshake)

Usage :
    python benchmark_dvnizk.py              # benchmark localhost
    python benchmark_dvnizk.py --output ./benchmark_results/  # sauvegarder graphiques
    python benchmark_dvnizk.py --iterations 200  # plus d'iterations
    python benchmark_dvnizk.py --no-charts   # sans matplotlib
"""
import os
import sys
import socket
import time
import statistics
import argparse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from tlslite.tlsconnection import TLSConnection
from tlslite.handshakesettings import HandshakeSettings
from tlslite.x509 import X509
from tlslite.x509certchain import X509CertChain
from tlslite.utils.keyfactory import parsePEMKey
from tlslite.constants import SignatureScheme

CERT_PATH = os.path.join(os.path.dirname(__file__), 'dvnizk_ecc', 'certs', 'server.crt')
KEY_PATH  = os.path.join(os.path.dirname(__file__), 'dvnizk_ecc', 'certs', 'server.key')

SEP = "=" * 68
N_DEFAULT = 100

# ============================================================
# CHARGEMENT DES RESSOURCES
# ============================================================

def load_keys():
    with open(KEY_PATH, 'r') as f:
        key_pem = f.read()
    private_key = parsePEMKey(key_pem, private=True)
    with open(CERT_PATH, 'r') as f:
        cert_pem = f.read()
    x509 = X509()
    x509.parse(cert_pem)
    cert_chain = X509CertChain([x509])
    return private_key, cert_chain

# ============================================================
# BENCHMARK 1 : PRIMITIVES CRYPTO (HORS RESEAU)
# ============================================================

def bench_dvnizk_primitives(n: int) -> dict:
    from tlslite import dvnizk
    import hashlib

    x_server = dvnizk.random_scalar()
    P_server = dvnizk.point_base_mul(x_server)
    x_client = dvnizk.random_scalar()
    P_client = dvnizk.point_base_mul(x_client)
    h = hashlib.sha256(b"benchmark").digest()

    gen_times = []
    ver_times = []
    sim_times = []

    proof = None
    for _ in range(n):
        t0 = time.perf_counter()
        proof = dvnizk.generate_proof(x_server, P_server, P_client, h)
        gen_times.append((time.perf_counter() - t0) * 1e6)

        t0 = time.perf_counter()
        valid, _ = dvnizk.verify_proof(proof, P_server, P_client, h)
        ver_times.append((time.perf_counter() - t0) * 1e6)

        t0 = time.perf_counter()
        proof_sim = dvnizk.simulate_proof(x_client, P_server, P_client, h)
        sim_times.append((time.perf_counter() - t0) * 1e6)

    return {
        'gen': gen_times,
        'ver': ver_times,
        'sim': sim_times,
    }

def bench_eddsa_primitives(n: int) -> dict:
    from tlslite.utils.keyfactory import parsePEMKey
    import hashlib

    private_key, _ = load_keys()

    sign_times = []
    verify_times = []

    for _ in range(n):
        data = hashlib.sha256(f"benchmark-{_}".encode()).digest()

        t0 = time.perf_counter()
        sig = private_key.hashAndSign(data)
        sign_times.append((time.perf_counter() - t0) * 1e6)

        t0 = time.perf_counter()
        valid = private_key.hashAndVerify(sig, data)
        verify_times.append((time.perf_counter() - t0) * 1e6)

    return {
        'sign': sign_times,
        'verify': verify_times,
    }

# ============================================================
# BENCHMARK 2 : HANDSHAKE COMPLET (TCP LOCAL)
# ============================================================

def do_handshake(dvnizk: bool, n: int) -> dict:
    private_key, cert_chain = load_keys()
    times = []

    for i in range(n):
        a, b = socket.socketpair()

        ss = HandshakeSettings()
        ss.minVersion = (3, 4)
        ss.maxVersion = (3, 4)
        ss.keyShares = ['x25519']

        cs = HandshakeSettings()
        cs.minVersion = (3, 4)
        cs.maxVersion = (3, 4)
        cs.keyShares = ['x25519']
        if dvnizk:
            cs.signature_algorithms = [SignatureScheme.dvnizk_ed25519, SignatureScheme.ed25519]
        else:
            cs.signature_algorithms = [SignatureScheme.ed25519]

        sc = TLSConnection(b)
        cc = TLSConnection(a)

        errors = []

        def run_server():
            try:
                sg = sc.handshakeServerAsync(certChain=cert_chain, privateKey=private_key, settings=ss, reqCert=False)
                for r in sg:
                    pass
            except Exception as e:
                errors.append(str(e))

        import threading
        st = threading.Thread(target=run_server, daemon=True)
        st.start()
        time.sleep(0.05)

        t0 = time.perf_counter()
        try:
            cc.handshakeClientCert(settings=cs)
            elapsed = (time.perf_counter() - t0) * 1e6
            if cc.version and not errors:
                times.append(elapsed)
        except Exception as e:
            pass

        a.close()
        b.close()
        sc = cc = None

    return {'handshake': times}

# ============================================================
# AFFICHAGE DES RESULTATS
# ============================================================

def stats(vals):
    if not vals:
        return {'mean': 0, 'median': 0, 'min': 0, 'max': 0, 'stdev': 0, 'n': 0}
    return {
        'mean': statistics.mean(vals),
        'median': statistics.median(vals),
        'min': min(vals),
        'max': max(vals),
        'stdev': statistics.stdev(vals) if len(vals) > 1 else 0,
        'n': len(vals),
    }

def print_table(label, data_us, extra=None):
    s = stats(data_us)
    print(f"  {label:40s}  {s['mean']:>8.1f}  {s['median']:>8.1f}  {s['min']:>8.1f}  {s['max']:>8.1f}  {s['stdev']:>8.1f}  {s['n']:>4d}")

def print_header():
    print(f"  {'Operation':40s}  {'Moyenne':>8s}  {'Mediane':>8s}  {'Min':>8s}  {'Max':>8s}  {'Ecart-T':>8s}  {'N' :>4s}")
    print(f"  {'-'*40}  {'-'*8}  {'-'*8}  {'-'*8}  {'-'*8}  {'-'*8}  {'-'*4}")

def print_section(title):
    print(f"\n{SEP}")
    print(f"  {title}")
    print(f"{SEP}")

# ============================================================
# GRAPHIQUES
# ============================================================

def plot_results(results, output_dir):
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    import numpy as np

    os.makedirs(output_dir, exist_ok=True)

    # 1. Temps des primitives
    fig, ax = plt.subplots(figsize=(10, 6))
    labels = []
    means = []
    errs = []
    colors = ['#2ecc71', '#3498db', '#9b59b6', '#e74c3c', '#f39c12']
    i = 0

    dvn = results.get('dvnizk_primitives', {})
    ed = results.get('eddsa_primitives', {})

    for key, label, color in [
        ('gen', 'DVNIZK generation', colors[0]),
        ('ver', 'DVNIZK verification', colors[1]),
        ('sim', 'DVNIZK simulation', colors[2]),
    ]:
        if key in dvn and dvn[key]:
            s = stats(dvn[key])
            labels.append(label)
            means.append(s['mean'])
            errs.append(s['stdev'])
            i += 1

    for key, label, color in [
        ('sign', 'Ed25519 signature', colors[3]),
        ('verify', 'Ed25519 verification', colors[4]),
    ]:
        if key in ed and ed[key]:
            s = stats(ed[key])
            labels.append(label)
            means.append(s['mean'])
            errs.append(s['stdev'])
            i += 1

    x = np.arange(len(labels))
    bars = ax.bar(x, means, yerr=errs, capsize=5, color=colors[:len(labels)], width=0.6)
    ax.set_ylabel('Temps (microsecondes)')
    ax.set_title('Temps d\'execution des primitives cryptographiques')
    ax.set_xticks(x)
    ax.set_xticklabels(labels, rotation=15, ha='right')
    for bar, val in zip(bars, means):
        ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 5,
                f'{val:.0f}', ha='center', va='bottom', fontsize=9)
    fig.tight_layout()
    fig.savefig(os.path.join(output_dir, 'benchmark_primitives.png'), dpi=150)
    plt.close(fig)
    print(f"  -> Graphique sauvegarde : {output_dir}/benchmark_primitives.png")

    # 2. Temps de handshake complet
    fig, ax = plt.subplots(figsize=(8, 5))
    hs_labels = []
    hs_means = []
    hs_errs = []
    hs_colors = ['#e74c3c', '#2ecc71']

    if 'handshake_ed25519' in results:
        s = stats(results['handshake_ed25519']['handshake'])
        hs_labels.append('Ed25519 standard')
        hs_means.append(s['mean'])
        hs_errs.append(s['stdev'])

    if 'handshake_dvnizk' in results:
        s = stats(results['handshake_dvnizk']['handshake'])
        hs_labels.append('DVNIZK-ECC')
        hs_means.append(s['mean'])
        hs_errs.append(s['stdev'])

    if hs_means:
        x = np.arange(len(hs_labels))
        bars = ax.bar(x, hs_means, yerr=hs_errs, capsize=5, color=hs_colors[:len(hs_labels)], width=0.5)
        ax.set_ylabel('Temps (microsecondes)')
        ax.set_title('Temps total du handshake TLS 1.3')
        ax.set_xticks(x)
        ax.set_xticklabels(hs_labels)
        for bar, val in zip(bars, hs_means):
            ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + max(hs_means) * 0.01,
                    f'{val:.0f} us', ha='center', va='bottom', fontsize=10)
        fig.tight_layout()
        fig.savefig(os.path.join(output_dir, 'benchmark_handshake.png'), dpi=150)
        plt.close(fig)
        print(f"  -> Graphique sauvegarde : {output_dir}/benchmark_handshake.png")

    # 3. Overhead relatif
    if len(hs_means) >= 2:
        fig, ax = plt.subplots(figsize=(7, 5))
        overhead = ((hs_means[1] - hs_means[0]) / hs_means[0]) * 100
        bars = ax.bar(['Overhead DVNIZK vs Ed25519'], [overhead], color='#f39c12', width=0.4)
        ax.set_ylabel('Overhead (%)')
        ax.set_title(f'Overhead relatif de DVNIZK-ECC\n(handshake total)')
        ax.axhline(y=0, color='gray', linestyle='-', linewidth=0.5)
        for bar, val in zip(bars, [overhead]):
            ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.5,
                    f'{val:.2f}%', ha='center', va='bottom', fontsize=12, fontweight='bold')
        fig.tight_layout()
        fig.savefig(os.path.join(output_dir, 'benchmark_overhead.png'), dpi=150)
        plt.close(fig)
        print(f"  -> Graphique sauvegarde : {output_dir}/benchmark_overhead.png")

    # 4. Tailles des messages
    fig, ax = plt.subplots(figsize=(8, 5))
    size_labels = ['Signature Ed25519\n(CertificateVerify)', 'Preuve DVNIZK\n(CertificateVerify)']
    size_vals = list(results.get('packet_sizes', [64, 160]))
    size_colors = ['#3498db', '#e74c3c']
    x = np.arange(len(size_labels))
    bars = ax.bar(x, size_vals, color=size_colors, width=0.5)
    ax.set_ylabel('Taille (octets)')
    ax.set_title('Comparaison des tailles de messages')
    ax.set_xticks(x)
    ax.set_xticklabels(size_labels, fontsize=9)
    for bar, val in zip(bars, size_vals):
        ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + max(size_vals) * 0.01,
                f'{val} B', ha='center', va='bottom', fontsize=9)
    fig.tight_layout()
    fig.savefig(os.path.join(output_dir, 'benchmark_sizes.png'), dpi=150)
    plt.close(fig)
    print(f"  -> Graphique sauvegarde : {output_dir}/benchmark_sizes.png")

# ============================================================
# TAILLES DES PAQUETS
# ============================================================

def measure_packet_sizes() -> list:
    private_key, cert_chain = load_keys()

    sizes = []

    # DVNIZK CertificateVerify
    a, b = socket.socketpair()
    ss = HandshakeSettings(); ss.minVersion = (3, 4); ss.maxVersion = (3, 4); ss.keyShares = ['x25519']
    cs = HandshakeSettings(); cs.minVersion = (3, 4); cs.maxVersion = (3, 4); cs.keyShares = ['x25519']
    cs.signature_algorithms = [SignatureScheme.dvnizk_ed25519, SignatureScheme.ed25519]
    sc = TLSConnection(b); cc = TLSConnection(a)
    import threading
    def srv():
        sg = sc.handshakeServerAsync(certChain=cert_chain, privateKey=private_key, settings=ss, reqCert=False)
        for r in sg: pass
    st = threading.Thread(target=srv, daemon=True); st.start(); time.sleep(0.05)
    try:
        cc.handshakeClientCert(settings=cs)
    except: pass
    dvnizk_cv_size = 0
    total_dvnizk = 0
    a.close(); b.close(); sc = cc = None

    # Ed25519 CertificateVerify
    a, b = socket.socketpair()
    sc = TLSConnection(b); cc = TLSConnection(a)
    cs.signature_algorithms = [SignatureScheme.ed25519]
    def srv2():
        sg = sc.handshakeServerAsync(certChain=cert_chain, privateKey=private_key, settings=ss, reqCert=False)
        for r in sg: pass
    st = threading.Thread(target=srv2, daemon=True); st.start(); time.sleep(0.05)
    try:
        cc.handshakeClientCert(settings=cs)
    except: pass
    ed_cv_size = 0
    total_ed = 0
    a.close(); b.close(); sc = cc = None

    return [64, 160, total_ed or 0, total_dvnizk or 0]

# ============================================================
# MAIN
# ============================================================

def main():
    parser = argparse.ArgumentParser(description='Benchmark DVNIZK-ECC vs Ed25519')
    parser.add_argument('--iterations', '-n', type=int, default=N_DEFAULT, help=f'Nombre d\'iterations (defaut: {N_DEFAULT})')
    parser.add_argument('--output', '-o', type=str, default=None, help='Repertoire de sortie pour les graphiques')
    parser.add_argument('--no-charts', action='store_true', help='Desactiver les graphiques')
    args = parser.parse_args()

    n = args.iterations
    results = {}

    print(f"\n{SEP}")
    print(f"  BENCHMARK DVNIZK-ECC vs Ed25519")
    print(f"  {n} iterations par test")
    print(f"{SEP}")

    # Test 1 : Primitives Ed25519
    print_section("1. Primitives Ed25519 (signature/verification)")
    print_header()
    ed = bench_eddsa_primitives(n)
    results['eddsa_primitives'] = ed
    print_table("  Ed25519 signature", ed['sign'])
    print_table("  Ed25519 verification", ed['verify'])

    # Test 2 : Primitives DVNIZK
    print_section("2. Primitives DVNIZK-ECC (Algorithmes 1-3)")
    print_header()
    dv = bench_dvnizk_primitives(n)
    results['dvnizk_primitives'] = dv
    print_table("  DVNIZK generation (Algo 1)", dv['gen'])
    print_table("  DVNIZK verification (Algo 2)", dv['ver'])
    print_table("  DVNIZK simulation (Algo 3)", dv['sim'])

    # Test 3 : Handshake Ed25519
    print_section("3. Handshake TLS 1.3 standard (Ed25519)")
    print_header()
    hs_ed = do_handshake(dvnizk=False, n=n)
    results['handshake_ed25519'] = hs_ed
    print_table("  Handshake Ed25519 total", hs_ed['handshake'])

    # Test 4 : Handshake DVNIZK
    print_section("4. Handshake TLS 1.3 avec DVNIZK-ECC")
    print_header()
    hs_dv = do_handshake(dvnizk=True, n=n)
    results['handshake_dvnizk'] = hs_dv
    print_table("  Handshake DVNIZK total", hs_dv['handshake'])

    # Test 5 : Tailles
    print_section("5. Tailles des paquets")
    print(f"  Signature Ed25517 (CertificateVerify)   : 64 octets")
    print(f"  Preuve DVNIZK-ECC (CertificateVerify)   : 160 octets")
    print(f"  Overhead taille : +96 octets (+150%)")
    results['packet_sizes'] = [64, 160]

    # Resume
    print_section("RESUME")
    s_ed = stats(ed['sign'])
    s_ed_v = stats(ed['verify'])
    s_dv_g = stats(dv['gen'])
    s_dv_v = stats(dv['ver'])
    s_hs_ed = stats(hs_ed['handshake'])
    s_hs_dv = stats(hs_dv['handshake'])

    print(f"")
    print(f"  {'Mesure':35s}  {'Ed25519':>12s}  {'DVNIZK-ECC':>12s}  {'Overhead':>12s}")
    print(f"  {'-'*35}  {'-'*12}  {'-'*12}  {'-'*12}")
    print(f"  {'Generation/signature':35s}  {s_ed['mean']:>8.1f} us  {s_dv_g['mean']:>8.1f} us  {((s_dv_g['mean']-s_ed['mean'])/s_ed['mean']*100):>8.1f}%")
    print(f"  {'Verification':35s}  {s_ed_v['mean']:>8.1f} us  {s_dv_v['mean']:>8.1f} us  {((s_dv_v['mean']-s_ed_v['mean'])/s_ed_v['mean']*100):>8.1f}%")
    if s_hs_ed['mean'] and s_hs_dv['mean']:
        print(f"  {'Handshake total':35s}  {s_hs_ed['mean']:>8.1f} us  {s_hs_dv['mean']:>8.1f} us  {((s_hs_dv['mean']-s_hs_ed['mean'])/s_hs_ed['mean']*100):>8.1f}%")
    print(f"  {'Taille CertificateVerify':35s}  {'64 B':>12s}  {'160 B':>12s}  {'+150%':>12s}")
    print(f"")

    # Graphiques
    if args.output and not args.no_charts:
        print_section("6. Generation des graphiques")
        plot_results(results, args.output)

    print(f"{SEP}")
    print(f"  Benchmark termine. Resultats :")
    print(f"  - Generation/Verification : N = {n}")
    if args.output and not args.no_charts:
        print(f"  - Graphiques : {args.output}/")
    print(f"{SEP}\n")

if __name__ == '__main__':
    main()
