#!/usr/bin/env python3
"""
app.py — Interface Web Flask pour le Sniffer Réseau TP1
Permet de lancer/arrêter la capture et de voir les résultats en temps réel
"""

import json
import threading
import time
from datetime import datetime
from pathlib import Path

from flask import Flask, jsonify, render_template, request, Response, stream_with_context

from sniffer_core import SnifferEngine

app = Flask(__name__)

# Instance unique du moteur de capture
sniffer = SnifferEngine()

# File d'attente pour les événements SSE
sse_clients = []


# ──────────────────────────────────────────────
# ROUTES PRINCIPALES
# ──────────────────────────────────────────────

@app.route("/")
def index():
    """Page d'accueil avec l'interface de contrôle."""
    # Récupérer la liste des interfaces réseau disponibles
    interfaces = get_interfaces()
    return render_template("index.html", interfaces=interfaces)


@app.route("/api/status")
def api_status():
    """Retourne l'état actuel du sniffer."""
    return jsonify({
        "is_running": sniffer.is_running,
        "interface": sniffer.interface,
        "bpf_filter": sniffer.bpf_filter,
        "packet_count": len(sniffer.log_entries),
        "bilan": sniffer.get_bilan(),
    })


@app.route("/api/start", methods=["POST"])
def api_start():
    """Lance la capture réseau dans un thread séparé."""
    if sniffer.is_running:
        return jsonify({"success": False, "error": "Capture déjà en cours"}), 400

    data = request.get_json()
    interface = data.get("interface", "")
    bpf_filter = data.get("bpf_filter", "")

    if not interface:
        return jsonify({"success": False, "error": "Interface requise"}), 400

    def sse_callback(packet_data):
        """Callback appelée pour chaque paquet → informer les clients SSE."""
        msg = json.dumps({"type": "packet", "data": packet_data})
        for queue in sse_clients:
            queue.append(msg)
        # Limiter la taille des files
        while len(sse_clients) > 0 and len(sse_clients[0]) > 100:
            sse_clients[0].pop(0)

    def run_capture():
        sniffer.start_capture(interface, bpf_filter, callback=sse_callback)
        # Fin de capture → sauvegarde
        sniffer.save_files()
        # Notifier les clients SSE
        msg = json.dumps({
            "type": "stop",
            "bilan": sniffer.get_bilan(),
            "ftp_count": len(sniffer.credentials_ftp),
            "http_count": len(sniffer.credentials_http),
            "telnet_count": len(sniffer.credentials_telnet),
        })
        for queue in sse_clients:
            queue.append(msg)

    thread = threading.Thread(target=run_capture, daemon=True)
    thread.start()

    return jsonify({"success": True})


@app.route("/api/stop", methods=["POST"])
def api_stop():
    """Arrête la capture."""
    if not sniffer.is_running:
        return jsonify({"success": False, "error": "Aucune capture en cours"}), 400

    sniffer.stop_capture()
    return jsonify({"success": True})


# ──────────────────────────────────────────────
# SERVER-SENT EVENTS (flux temps réel)
# ──────────────────────────────────────────────

@app.route("/api/stream")
def api_stream():
    """Endpoint SSE pour le flux temps réel des paquets."""
    queue = []

    # Ajouter ce client à la liste
    sse_clients.append(queue)

    def generate():
        try:
            while True:
                while queue:
                    yield f"data: {queue.pop(0)}\n\n"
                time.sleep(0.05)
        except GeneratorExit:
            pass
        finally:
            if queue in sse_clients:
                sse_clients.remove(queue)

    return Response(
        stream_with_context(generate()),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


# ──────────────────────────────────────────────
# ROUTES POUR LES RÉSULTATS
# ──────────────────────────────────────────────

@app.route("/api/credentials")
def api_credentials():
    """Retourne tous les credentials détectés."""
    return jsonify({
        "ftp": sniffer.credentials_ftp,
        "http": sniffer.credentials_http,
        "telnet": sniffer.credentials_telnet,
    })


@app.route("/api/logs")
def api_logs():
    """Retourne les entrées du log."""
    page = request.args.get("page", 1, type=int)
    per_page = 50
    start = (page - 1) * per_page
    end = start + per_page
    entries = sniffer.log_entries[start:end]
    return jsonify({
        "entries": entries,
        "total": len(sniffer.log_entries),
        "page": page,
        "per_page": per_page,
    })


@app.route("/api/bilan")
def api_bilan():
    """Retourne le bilan détaillé."""
    return jsonify({
        "bilan": sniffer.get_bilan(),
        "credentials": {
            "ftp": len(sniffer.credentials_ftp),
            "http": len(sniffer.credentials_http),
            "telnet": len(sniffer.credentials_telnet),
        },
        "interface": sniffer.interface,
        "filter": sniffer.bpf_filter or "aucun",
    })


@app.route("/api/download/<filetype>")
def api_download(filetype):
    """Télécharge les fichiers générés."""
    from flask import send_file

    if filetype == "pcap":
        path = "captures/capture.pcap"
        mimetype = "application/vnd.tcpdump.pcap"
    elif filetype == "log":
        path = "captures/capture.log"
        mimetype = "text/plain"
    else:
        return jsonify({"error": "Type inconnu"}), 400

    try:
        return send_file(path, mimetype=mimetype, as_attachment=True)
    except FileNotFoundError:
        return jsonify({"error": "Fichier non trouvé. Lancez d'abord une capture."}), 404


# ──────────────────────────────────────────────
# UTILITAIRES
# ──────────────────────────────────────────────

def get_interfaces():
    """Récupère la liste des interfaces réseau disponibles."""
    try:
        from scapy.all import get_if_list
        return get_if_list()
    except Exception:
        return ["eth0", "wlan0", "lo" , "wlo1"]


# ──────────────────────────────────────────────
# LANCEMENT
# ──────────────────────────────────────────────

if __name__ == "__main__":
    # Créer le dossier captures s'il n'existe pas
    Path("captures").mkdir(exist_ok=True)
    Path("captures/screenshots").mkdir(exist_ok=True)

    print("[*] Interface Flask démarrée sur http://127.0.0.1:5001")
    print("[*] Arrêter avec Ctrl+C")
    app.run(host="127.0.0.1", port=5001, debug=True, threaded=True)