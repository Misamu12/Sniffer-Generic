# === 1. Installer les services ===
sudo apt update
sudo apt install -y vsftpd telnetd apache2 net-tools

# === 2. Créer les utilisateurs de test ===
sudo useradd -m alice
echo "alice:P@ssw0rd123!" | sudo chpasswd

sudo useradd -m bob
echo "bob:SecretPass456!" | sudo chpasswd

# === 3. Configurer FTP ===
sudo sed -i 's/anonymous_enable=YES/anonymous_enable=NO/' /etc/vsftpd.conf
sudo sed -i 's/#local_enable=YES/local_enable=YES/' /etc/vsftpd.conf
sudo sed -i 's/#write_enable=YES/write_enable=YES/' /etc/vsftpd.conf

# Optionnel : décommenter pour voir les logs FTP
echo "log_ftp_protocol=YES" | sudo tee -a /etc/vsftpd.conf

sudo systemctl restart vsftpd
sudo systemctl enable vsftpd

# === 4. Configurer le serveur HTTP avec formulaire ===
sudo mkdir -p /var/www/html/app

# Page de login HTML
cat << 'EOF' | sudo tee /var/www/html/app/index.html
<!DOCTYPE html>
<html>
<head><title>Login</title></head>
<body>
  <h2>Connexion</h2>
  <form method="POST" action="/app/login.php">
    <label>Utilisateur:</label>
    <input type="text" name="username"><br><br>
    <label>Mot de passe:</label>
    <input type="password" name="password"><br><br>
    <input type="submit" value="Se connecter">
  </form>
</body>
</html>
EOF

# Script PHP qui simule la réception (les credentials transitent en clair)
cat << 'EOF' | sudo tee /var/www/html/app/login.php
<?php
// Simuler une tentative de connexion
$log = fopen("/tmp/http_credentials.log", "a");
fwrite($log, date("Y-m-d H:i:s") . " - " . $_POST['username'] . ":" . $_POST['password'] . "\n");
fclose($log);

echo "Tentative de connexion pour " . htmlspecialchars($_POST['username']) . "...<br>";
echo "Authentification... (simulation)";
sleep(2);
echo "<br>Échec de connexion.";
?>
EOF

sudo chmod 755 /var/www/html/app/login.php
sudo systemctl restart apache2

# === 5. Vérifier Telnet ===
sudo systemctl enable telnetd
sudo systemctl restart telnetd

# === 6. Vérifier que tout tourne ===
sudo systemctl status vsftpd --no-pager
sudo systemctl status apache2 --no-pager
sudo systemctl status telnetd --no-pager

# === 7. Obtenir l'IP ===
ip addr show | grep inet | grep -v 127.0.0.1
# Notez l'IP : 192.168.1.20 (ou autre selon votre réseau)
