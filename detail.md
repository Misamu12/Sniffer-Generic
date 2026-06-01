Voici l'architecture complète du projet et les explications détaillées.

---

## Architecture du Projet

```
TP1-Sniffer-Credentials/
│
├── sniffer.py                  # Script principal unifié (toutes les parties)
├── README.md                   # Documentation du projet
├── capture.pcap                # Fichier de capture généré (Wireshark)
├── capture.log                 # Journal textuel des paquets
│
├── docs/
│   ├── questions_comprehension_A.md   # Réponses Partie A
│   ├── questions_comprehension_B.md   # Réponses Partie B
│   └── conclusion.md                  # Conclusion finale (15-20 lignes)
│
├── captures/
│   ├── ecran_credentials_ftp.png      # Capture d'écran FTP
│   ├── ecran_credentials_http.png     # Capture d'écran HTTP
│   └── ecran_credentials_telnet.png   # Capture d'écran Telnet
│
└── tests/
    └── test_sniffer.py               # Scripts de test unitaires
```

---

## Structure du code — `sniffer.py` (architecture interne)

```
sniffer.py
│
├── [ENTÊTE]          # Shebang, docstring, imports
│
├── PARTIE A
│   ├── packet_counts         # dict: compteur par protocole
│   ├── captured_packets      # list: paquets bruts stockés
│   ├── log_entries           # list: lignes du journal
│   ├── packet_info()         # Callback principale
│   ├── signal_handler()      # Gestion Ctrl+C
│   └── final_report()        # Bilan final
│
├── PARTIE B (Personne B)
│   ├── FTP
│   │   ├── ftp_sessions      # dict: sessions FTP actives
│   │   └── extract_ftp_credentials()
│   │
│   └── HTTP
│       ├── extract_http_credentials()
│       └── (keywords, parsing POST)
│
├── PARTIE B (Personne C)
│   └── Telnet
│       ├── IAC, DO, DONT, WILL, WONT, SB, SE  # Constantes
│       ├── TELNET_OPTIONS                      # Dictionnaire options
│       ├── telnet_sessions                     # Buffer sessions
│       ├── strip_telnet_negotiation()          # Filtre IAC
│       ├── extract_telnet_credentials()        # En temps réel
│       └── extract_telnet_final_credentials()  # Bilan final
│
└── MAIN
    ├── main()                 # Point d'entrée
    └── argparse               # Parsing arguments CLI
```

---

## Explications détaillées du fonctionnement

### 1. Ligne de commande et arguments

```
sudo python3 sniffer.py <interface> [filtre_bpf]
```

| Argument | Obligatoire | Rôle | Exemple |
|----------|:-----------:|------|---------|
| `interface` | Oui | Interface réseau à écouter | `eth0`, `wlan0`, `ens33` |
| `bpf_filter` | Non | Filtre BPF optionnel entre guillemets | `"tcp port 21 or tcp port 80"` |

**Cas d'utilisation concrets :**

```bash
# Sniffer complet (tout le trafic)
sudo python3 sniffer.py eth0

# Sniffer ciblé FTP + HTTP + Telnet
sudo python3 sniffer.py eth0 "tcp port 21 or tcp port 80 or tcp port 23"

# Sniffer uniquement Telnet
sudo python3 sniffer.py wlan0 "tcp port 23"
```

---

### 2. Partie A — Sniffer générique (Personne A)

#### Principe de fonctionnement

```
                    Mode Promiscuité
  Machine A              |               Machine B (attaquant)
  (client FTP)           |               (sniffer.py)
       |                 |                     |
       |--- USER toto -->|-----#------------->|  Scapy sniff()
       |                 |     |              |  capture le paquet
       |                 |     |              |       |
       |                 |     |              |  packet_info(packet)
       |                 |     |              |       |
       |                 |     |              |  +---> Affichage console
       |                 |     |              |  +---> Ajout à log_entries
       |                 |     |              |  +---> Stockage dans captured_packets
       |                 |     |              |  +---> extract_ftp_credentials()
       |                 |     |              |  +---> extract_http_credentials()
       |                 |     |              |  +---> extract_telnet_credentials()
       |                 |     |              |
       |                 |     |         [Ctrl+C]
       |                 |     |              |
       |                 |     |         signal_handler()
       |                 |     |              |
       |                 |     |         +---> wrpcap("capture.pcap")
       |                 |     |         +---> write("capture.log")
       |                 |     |         +---> extract_telnet_final_credentials()
       |                 |     |         +---> final_report()
```

#### Détail de `packet_info()`

```python
def packet_info(packet):
    # 1. Récupérer l'horodatage
    timestamp = datetime.now()

    # 2. Extraire les adresses IP
    ip_src = packet["IP"].src    # Ex: 192.168.1.10
    ip_dst = packet["IP"].dst    # Ex: 192.168.1.20

    # 3. Déterminer le protocole et les ports
    if packet.haslayer("TCP"):
        proto = "TCP"
        sport = packet["TCP"].sport   # Ex: 34567
        dport = packet["TCP"].dport   # Ex: 21
    elif packet.haslayer("UDP"):
        proto = "UDP"
        ...
    elif packet.haslayer("ICMP"):
        proto = "ICMP"
        sport = dport = "N/A"
    else:
        proto = "OTHER"

    # 4. Incrémenter le compteur
    packet_counts[proto] += 1

    # 5. Afficher et logger
    # [2026-05-31 14:23:45.123] TCP   | 192.168.1.10:34567 -> 192.168.1.20:21
```

#### Sauvegarde des fichiers

| Fichier | Format | Utilisation |
|---------|--------|-------------|
| `capture.pcap` | Binaire (pcap) | Ouvrir dans Wireshark pour analyse approfondie |
| `capture.log` | Texte | Consultation rapide, partage, scripts d'analyse |

---

### 3. Partie B — FTP (Personne B)

#### Détection des credentials FTP

Le protocole FTP échange les commandes en clair sur le port TCP 21 :

```
Client (192.168.1.10)          Serveur FTP (192.168.1.20)
       |                              |
       |---- TCP SYN (port 21) ------>|
       |<--- TCP SYN-ACK -------------|
       |---- TCP ACK ---------------->|
       |                              |
       |---- "USER toto\r\n" -------->|   <<< Capturé par le sniffer
       |<--- "331 Password required" -|
       |                              |
       |---- "PASS secret123\r\n" --->|   <<< Capturé par le sniffer
       |<--- "230 Login successful" --|
```

**Algorithme d'extraction :**

```
extract_ftp_credentials(packet)
│
├── Vérifier : TCP + Raw payload + port 21
│
├── Extraire la charge utile brute
│   └── payload = packet["Raw"].load.decode("utf-8")
│
├── Déterminer la direction (client vs serveur)
│   └── client_ip = ip.src if sport != 21 else ip.dst
│
├── Chercher "USER <username>" (regex insensible à la casse)
│   └── Si trouvé → stocker dans ftp_sessions[session_key]["user"]
│
├── Chercher "PASS <password>" (regex insensible à la casse)
│   └── Si trouvé → stocker dans ftp_sessions[session_key]["password"]
│
└── Si USER ET PASS présents dans la même session
    └── Afficher le rapport complet
```

**Exemple de sortie console :**
```
[FTP] USER détecté — toto

============================================================
  [CREDENTIALS FTP CAPTURÉS]  @ 2026-05-31 14:23:45.123
  Victime      : 192.168.1.10:45678
  Serveur FTP  : 192.168.1.20:21
  Protocole    : FTP
  Username     : toto
  Password     : secret123
============================================================
```

#### Gestion de la session FTP

Le dictionnaire `ftp_sessions` utilise une clé composite :
```python
session_key = (client_ip, serveur_ip, client_port)
# Ex: ("192.168.1.10", "192.168.1.20", 45678)
```

Cette clé permet de suivre plusieurs sessions FTP simultanées entre différentes machines.

---

### 4. Partie B — HTTP (Personne B)

#### Détection des credentials HTTP

Le protocole HTTP POST envoie les données de formulaire en clair sur le port TCP 80 :

```
Client (192.168.1.10)          Serveur Web (192.168.1.20)
       |                              |
       |---- POST /login.php -------->|   <<< Requête HTTP POST
       |    Host: example.com         |
       |    Content-Type: appl...     |
       |                              |
       |    username=toto&            |
       |    password=secret123        |   <<< Corps POST en clair
       |                              |
       |<--- HTTP 200 OK -------------|   <<< Réponse (contient la page)
```

**Algorithme d'extraction :**

```
extract_http_credentials(packet)
│
├── Vérifier : TCP + Raw payload + port 80
│
├── Charger le payload en UTF-8
│
├── Vérifier que la requête commence par "POST"
│   └── Sinon → ignorer (GET, PUT, etc.)
│
├── Extraire l'URL ciblée
│   └── url = regex sur "POST <url> HTTP"
│
├── Extraire le Host
│   └── host = regex header "Host: <host>"
│
├── Extraire le corps (body) après "\r\n\r\n"
│
├── Découper le body en paramètres (&)
│   └── Pour chaque paramètre "key=value"
│       ├── Décoder l'URL-encoding (%20 → espace, etc.)
│       └── Vérifier si key contient un mot-clé :
│           password, passwd, pwd, pass,
│           login, username, user, email
│           └── Si oui → ajouter aux credentials_found
│
└── Si credentials_found non vide
    └── Afficher le rapport complet
```

**Exemple de sortie console :**
```
============================================================
  [CREDENTIALS HTTP CAPTURÉS]  @ 2026-05-31 14:25:10.456
  Victime      : 192.168.1.10
  Serveur HTTP : 192.168.1.20:80
  Protocole    : HTTP
  URL ciblée   : http://example.com/login.php
  Données      :
    username         = toto
    password         = secret123
============================================================
```

---

### 5. Partie B — Telnet (Personne C)

#### Le problème de la négociation Telnet

Telnet utilise des séquences de contrôle IAC (Interpret As Command) mélangées aux données utilisateur. Ces séquences sont des **octets de commande** qui ne doivent pas être affichés.

**Structure d'une négociation Telnet :**

| Séquences | Octets | Signification |
|-----------|--------|---------------|
| `IAC DO x` | `FF FD xx` | Demande à l'autre d'activer l'option x |
| `IAC DONT x` | `FF FE xx` | Demande à l'autre de désactiver l'option x |
| `IAC WILL x` | `FF FB xx` | Annonce qu'on va activer l'option x |
| `IAC WONT x` | `FF FC xx` | Annonce qu'on va désactiver l'option x |
| `IAC SB ... IAC SE` | `FF FA ... FF F0` | Subnégociation (ex: type de terminal) |
| `IAC IAC` | `FF FF` | Un seul octet 0xFF littéral |

**Exemple concret d'une session Telnet brute :**

```
Flux brut reçu par le sniffer :
FF FB 1F FF FB 20 FF FB 18 FF FB 27 FF FD 05 FF FB 21 FF FB 22 FF FB 1B
FF FB 23 FF FB 03 FF FD 01 FF FA 18 00 58 54 45 52 4D FF F0
            t  o  t  o  \r  \n
FF FC 01 FF FD 03 FF FB 1F FF FB 20 FF FB 18 FF FB 27 FF FD 05
FF FB 21 FF FB 22 FF FB 1B FF FB 23 FF FB 03
            P  a  s  s  w  o  r  d  :  \r  \n
                        s  e  c  r  e  t  1  2  3  \r  \n
```

**Après filtrage IAC (ce que voit l'utilisateur — et ce que notre script extrait) :**
```
toto\r\nPassword:\r\nsecret123\r\n
```

#### Algorithme de filtrage IAC

```
strip_telnet_negotiation(data_bytes)
│
├── Parcourir octet par octet
│
├── Si octet == IAC (0xFF) :
│   ├── Regarder l'octet suivant :
│   │   ├── DO/DONT/WILL/WONT → sauter 3 octets (IAC + cmd + option)
│   │   ├── SB → chercher IAC SE, sauter tout le bloc
│   │   ├── IAC (double) → ajouter un IAC littéral
│   │   └── autre → sauter 2 octets
│   │
│   └── Continuer la boucle
│
└── Si octet normal → ajouter au résultat
```

#### Reconstitution de session Telnet

```
extract_telnet_credentials(packet)
│
├── Vérifier : TCP + Raw + port 23
│
├── Appliquer strip_telnet_negotiation() sur le payload brut
│
├── Déterminer direction
│   ├── client → serveur : stocker dans telnet_sessions
│   └── serveur → client : afficher les messages (prompts, etc.)
│
└── Afficher en temps réel les caractères saisis
```

À l'arrêt (`extract_telnet_final_credentials`), on analyse le buffer complet :

```
extract_telnet_final_credentials()
│
├── Pour chaque session Telnet
│   ├── Nettoyer les \r
│   ├── Découper par \n → obtenir des lignes
│   │   ├── Ligne 1 → Username probable
│   │   └── Ligne 2 → Password probable
│   └── Afficher le rapport
```

**Exemple de sortie console :**
```
  [TELNET Keystrokes] (192.168.1.10:54321) -> toto\n
  [TELNET Server] (192.168.1.20) -> Password:
  [TELNET Keystrokes] (192.168.1.10:54321) -> secret123\n

============================================================
  [RAPPORT CREDENTIALS TELNET]
============================================================

  Session Telnet : 192.168.1.10 -> 192.168.1.20
  Séquences reconstituées :
    >> toto
    >> Password:
    >> secret123

  [+] Username probable : toto
  [+] Password probable : secret123
============================================================
```

---

### 6. Schéma de flux global (data flow)

```
┌──────────────────────────────────────────────────────────────┐
│                    RÉSEAU LOCAL (192.168.1.0/24)              │
│                                                              │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐   │
│  │ Client FTP   │    │ Serveur FTP  │    │ ATTAQUANT    │   │
│  │ 192.168.1.10 │    │ 192.168.1.20 │    │ 192.168.1.30 │   │
│  │              │    │              │    │              │   │
│  │ USER toto    │───▶│ port 21      │    │ sniffer.py   │   │
│  │ PASS secret  │───▶│              │───▶│ (promisc)    │   │
│  └──────────────┘    └──────────────┘    └──────┬───────┘   │
│                                                  │           │
│  ┌──────────────┐    ┌──────────────┐            │           │
│  │ Client HTTP  │    │ Serveur Web  │            │           │
│  │ 192.168.1.11 │    │ 192.168.1.20 │            │           │
│  │              │    │              │            │           │
│  │ POST /login  │───▶│ port 80      │────────────┤           │
│  │ user=admin   │───▶│              │            │           │
│  │ pass=1234    │───▶│              │            │           │
│  └──────────────┘    └──────────────┘            │           │
│                                                  │           │
│  ┌──────────────┐    ┌──────────────┐            │           │
│  │ Client Telnet│    │ Serveur Teln │            │           │
│  │ 192.168.1.12 │    │ 192.168.1.20 │            │           │
│  │              │    │              │            │           │
│  │ toto\n       │───▶│ port 23      │────────────┤           │
│  │ secret123\n  │───▶│              │            │           │
│  └──────────────┘    └──────────────┘            │           │
│                                                  │           │
│                                    ┌─────────────▼──────────┐│
│                                    │   SORTIES sniffer.py   ││
│                                    │                        ││
│                                    │  ┌──────────────────┐  ││
│                                    │  │  Console (stdout) │  ││
│                                    │  │  Affichage temps │  ││
│                                    │  │  réel des infos  │  ││
│                                    │  └──────────────────┘  ││
│                                    │  ┌──────────────────┐  ││
│                                    │  │  capture.pcap    │  ││
│                                    │  │  (Wireshark)     │  ││
│                                    │  └──────────────────┘  ││
│                                    │  ┌──────────────────┐  ││
│                                    │  │  capture.log     │  ││
│                                    │  │  (texte lisible) │  ││
│                                    │  └──────────────────┘  ││
│                                    └────────────────────────┘│
└──────────────────────────────────────────────────────────────┘
```

---

### 7. Fichiers de sortie détaillés

#### `capture.log` — Exemple de contenu

```
=== Sniffer Log - 2026-05-31 14:23:00 ===
Interface: eth0 | Filtre: tcp port 21 or tcp port 80 or tcp port 23

[2026-05-31 14:23:45.123] TCP   | 192.168.1.10:45678    -> 192.168.1.20:21
[2026-05-31 14:23:45.124] TCP   | 192.168.1.20:21       -> 192.168.1.10:45678
[2026-05-31 14:23:45.125] TCP   | 192.168.1.10:45678    -> 192.168.1.20:21
...
```

#### `capture.pcap` — Utilisation dans Wireshark

```bash
wireshark capture.pcap
```

Dans Wireshark, vous pouvez :
- Appliquer des filtres d'affichage : `ftp`, `http`, `telnet`
- Suivre les flux TCP : clic droit → Follow → TCP Stream
- Voir les credentials en clair dans les flux

---

### 8. Tableau récapitulatif des signatures de détection

| Protocole | Port | Méthode de détection | Regex / Logique |
|-----------|:----:|----------------------|-----------------|
| **FTP** | 21 | Commande USER puis PASS | `USER\s+(.+)` + `PASS\s+(.+)` |
| **HTTP** | 80 | Requête POST + parsing du body | `password\|passwd\|pwd\|pass\|login\|username\|user\|email` dans les noms de champs |
| **Telnet** | 23 | Filtrage IAC + reconstitution séquentielle | Stripping des séquences `FF xx yy` |

---

### 9. Environnement de test (à préparer côté "victime")

```bash
# --- Sur la machine serveur/victime ---

# 1. Installation des services
sudo apt update
sudo apt install -y vsftpd telnetd apache2 python3

# 2. Configuration FTP (vsftpd)
sudo sed -i 's/anonymous_enable=YES/anonymous_enable=NO/' /etc/vsftpd.conf
sudo sed -i 's/#local_enable=YES/local_enable=YES/' /etc/vsftpd.conf
sudo sed -i 's/#write_enable=YES/write_enable=YES/' /etc/vsftpd.conf
sudo systemctl restart vsftpd

# 3. Création des utilisateurs de test
sudo useradd -m testuser
echo "testuser:password123" | sudo chpasswd

# 4. Configuration HTTP avec formulaire de login
sudo mkdir -p /var/www/html/login
cat << 'EOF' | sudo tee /var/www/html/login/index.html
<html><body>
<form method="POST" action="/login/authenticate.php">
  Username: <input type="text" name="username"><br>
  Password: <input type="password" name="password"><br>
  <input type="submit" value="Login">
</form>
</body></html>
EOF

# 5. Activation Telnet
sudo systemctl enable telnetd
sudo systemctl start telnetd
```

---

### 10. Commandes de test (depuis la machine cliente)

```bash
# Test FTP
ftp 192.168.1.20
# Nom: testuser
# Mot de passe: password123

# Test HTTP
curl -X POST http://192.168.1.20/login/authenticate.php \
  -d "username=admin&password=secret456"

# Test Telnet
telnet 192.168.1.20
# login: testuser
# Password: password123
```

Pendant ces tests, le sniffer sur la machine attaquante capture et affiche les credentials en temps réel.
