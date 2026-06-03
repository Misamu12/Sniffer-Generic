#!/usr/bin/env python3
import argparse
import signal
import sys
from datetime import datetime

from scapy.all import sniff, wrpcap, conf

# Dictionnaire global pour le comptage par protocole
packet_counts = {"TCP": 0, "UDP": 0, "ICMP": 0, "OTHER": 0}
global_captured_packets = []
log_entries = []
capture_active = True  # ← AJOUTÉ : flag pour contrôler la capture


def packet_info(packet):
    """Callback appelée pour chaque paquet capturé."""
    global global_captured_packets
    
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]

    if packet.haslayer("IP"):
        ip_src = packet["IP"].src
        ip_dst = packet["IP"].dst
    else:
        ip_src = ip_dst = "N/A"

    if packet.haslayer("TCP"):
        proto = "TCP"
        sport = packet["TCP"].sport
        dport = packet["TCP"].dport
    elif packet.haslayer("UDP"):
        proto = "UDP"
        sport = packet["UDP"].sport
        dport = packet["UDP"].dport
    elif packet.haslayer("ICMP"):
        proto = "ICMP"
        sport = dport = "N/A"
    else:
        proto = "OTHER"
        sport = dport = "N/A"

    packet_counts[proto] = packet_counts.get(proto, 0) + 1
    global_captured_packets.append(packet)

    log_line = (
        f"[{timestamp}] {proto:5s} | "
        f"{ip_src:15s}:{str(sport):5s} -> "
        f"{ip_dst:15s}:{str(dport):5s}"
    )
    print(log_line)
    log_entries.append(log_line)
    
    # Optionnel : arrêt après N paquets pour test
    # if len(global_captured_packets) >= 10:
    #     return False  # Arrête la capture


def signal_handler(sig, frame):
    """Gestionnaire d'interruption Ctrl+C - ne quitte pas immédiatement"""
    global capture_active
    print("\n\n[!] Interruption clavier détectée. Arrêt en cours...")
    capture_active = False  # ← Drapeau pour arrêter la capture
    # Ne pas appeler sys.exit() ici !


def final_report():
    """Affiche le bilan final du nombre de paquets capturés par protocole."""
    print("\n" + "=" * 50)
    print("         BILAN FINAL DE LA CAPTURE")
    print("=" * 50)
    total = sum(packet_counts.values())
    print(f"  TCP   : {packet_counts.get('TCP', 0):6d} paquets")
    print(f"  UDP   : {packet_counts.get('UDP', 0):6d} paquets")
    print(f"  ICMP  : {packet_counts.get('ICMP', 0):6d} paquets")
    print(f"  OTHER : {packet_counts.get('OTHER', 0):6d} paquets")
    print("-" * 50)
    print(f"  TOTAL : {total:6d} paquets")
    print("=" * 50)


def save_files(interface, bpf_filter):
    """Sauvegarde les fichiers après la capture"""
    if global_captured_packets:
        wrpcap("capture.pcap", global_captured_packets)
        print(f"\n[*] Fichier capture.pcap généré ({len(global_captured_packets)} paquets).")
    else:
        print("\n[!] Aucun paquet capturé.")

    with open("capture.log", "w") as f:
        f.write(f"=== Sniffer Log - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} ===\n")
        f.write(f"Interface: {interface} | Filtre: {bpf_filter or 'aucun'}\n\n")
        f.write("\n".join(log_entries))
    print(f"[*] Fichier capture.log généré ({len(log_entries)} lignes).")


def main():
    global capture_active, global_captured_packets
    
    parser = argparse.ArgumentParser(
        description="Renifleur de paquets réseau générique avec Scapy"
    )
    parser.add_argument(
        "interface",
        type=str,
        help="Nom de l'interface réseau à écouter (ex: eth0, wlan0)"
    )
    parser.add_argument(
        "bpf_filter",
        type=str,
        nargs="?",
        default="",
        help='Filtre BPF optionnel entre guillemets (ex: "tcp port 21 or tcp port 80")'
    )
    args = parser.parse_args()

    # Enregistrement du handler pour Ctrl+C
    signal.signal(signal.SIGINT, signal_handler)

    print(f"[*] Démarrage de la capture sur l'interface : {args.interface}")
    if args.bpf_filter:
        print(f"[*] Filtre BPF appliqué : {args.bpf_filter}")
    else:
        print("[*] Aucun filtre BPF — capture de tout le trafic")
    print("[*] Appuyez sur Ctrl+C pour arrêter la capture.\n")

    try:
        # Lancement du sniffing
        sniff(
            iface=args.interface,
            filter=args.bpf_filter if args.bpf_filter else None,
            prn=packet_info,
            store=False,
            stop_filter=lambda x: not capture_active  # ← Arrête quand capture_active devient False
        )
    except PermissionError:
        print("[!] ERREUR : Privilèges insuffisants. Exécutez avec sudo.")
        sys.exit(1)
    except OSError as e:
        print(f"[!] ERREUR réseau : {e}")
        sys.exit(1)
    except Exception as e:
        print(f"[!] ERREUR inattendue : {e}")
        sys.exit(1)
    
    # Sauvegarde après la capture (MAINTENANT ACCESSIBLE)
    save_files(args.interface, args.bpf_filter)
    final_report()


if __name__ == "__main__":
    main()