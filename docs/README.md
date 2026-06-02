# Sniffer-Generic

# Installation préalable
sudo apt install python3-scapy

# Capture de tout le trafic sur eth0
sudo python3 sniffer.py eth0

# Capture filtrée FTP + HTTP sur wlan0
sudo python3 sniffer.py wlan0 "tcp port 21 or tcp port 80"

Fichier	Format	Utilisation
capture.pcap	Binaire (pcap)	Ouvrir dans Wireshark pour analyse approfondie
capture.log	Texte	Consultation rapide, partage, scripts d'analyse


FTP (Personne B)
Détection des credentials FTP

Le protocole FTP échange les commandes en clair sur le port TCP 21 :


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



# Environnement de test (à préparer côté "victime")
## --- Sur la machine serveur/victime ---

### 1. Installation des services
sudo apt update
sudo apt install -y vsftpd telnetd apache2 python3

### 2. Configuration FTP (vsftpd)
sudo sed -i 's/anonymous_enable=YES/anonymous_enable=NO/' /etc/vsftpd.conf
sudo sed -i 's/#local_enable=YES/local_enable=YES/' /etc/vsftpd.conf
sudo sed -i 's/#write_enable=YES/write_enable=YES/' /etc/vsftpd.conf
sudo systemctl restart vsftpd

### 3. Création des utilisateurs de test
sudo useradd -m testuser
echo "testuser:password123" | sudo chpasswd

### 4. Configuration HTTP avec formulaire de login
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

### 5. Activation Telnet

sudo systemctl enable telnetd
sudo systemctl start telnetd