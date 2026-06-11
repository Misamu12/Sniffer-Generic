# 1.3.1 Question de comprehension --Partie A
Répondez par écrit aux questions suivantes avant de passer à la partie B.
## 1. Définissez le concept de filtre BPF. Donnez la syntaxe exacte permettant de capturer
simultanément le trafic FTP (port 21) et HTTP (port 80).
```
R) Berkeley Packet Filter (BPF) : mécanisme de filtrage de paquets au niveau du noyau (ou via libpcap) permettant de ne remonter à l'utilisateur que les paquets correspondant à une expression logique. Le filtre est compilé dans un pseudo-code exécuté par une machine virtuelle dans le noyau Linux, ce qui évite de copier inutilement des paquets indésirables depuis l'espace noyau vers l'espace utilisateur. C'est le même mécanisme qu'utilise tcpdump.
```


## 2. Expliquez la différence entre une capture en mode promiscuité et une capture standard.
Dans quel scénario le mode promiscuité est-il indispensable pour capturer le trafic
d’une machine tierce sur un segment commuté ?
```
 Capture standard (mode non-promiscuous) : l'interface réseau ne capture que les paquets qui lui sont destinés :

    Paquets dont l'adresse MAC destination correspond à celle de l'interface
    Paquets de broadcast (FF:FF:FF:FF:FF:FF)
    Paquets de multicast auxquels l'interface s'est abonnée

Capture en mode promiscuité : l'interface capture tous les paquets qui traversent le segment physique, quelle que soit leur adresse MAC destination. Le pilote de l'interface est configuré pour ne pas filtrer les trames.

Scénario où le mode promiscuité est indispensable :

Sur un réseau commuté (avec switch), le switch segmente le trafic : chaque port ne reçoit que les trames destinées à la machine qui y est connectée. Cependant, dans les cas suivants, le mode promiscuité devient nécessaire :

    Attaque par ARP spoofing : l'attaquant empoisonne la table ARP de la victime et du switch pour devenir un man-in-the-middle.
    Span port / port mirroring : l'administrateur configure le switch pour copier tout le trafic d'un port vers le port de l'attaquant.
    Hub (concentrateur) : contrairement au switch, le hub répète toutes les trames sur tous ses ports — le mode promiscuité suffit alors.

Dans tous ces cas, sans mode promiscuité, les paquets arrivent physiquement à l'interface mais sont ignorés par le pilote réseau car l'adresse MAC ne correspond pas.
```

## 3. Pourquoi votre script nécessite-t-il les privilèges superutilisateur pour s’exécuter ?
Répondez en vous appuyant sur le fonctionnement des sockets réseau au niveau du
système d’exploitation Linux.
```
Pourquoi votre script nécessite-t-il les privilèges superutilisateur pour s'exécuter ?

Sous Linux, la création de sockets brutes (raw sockets) est une opération privilégiée réservée à l'utilisateur root (ou aux processus avec la capacité CAP_NET_RAW). Voici pourquoi :

    Scapy utilise une socket AF_PACKET (SOCK_RAW) au niveau couche 2 (Ethernet). Ce type de socket permet de lire des trames Ethernet complètes, y compris celles qui ne sont pas destinées à la machine. C'est la seule façon de capturer en mode promiscuité.

    Les sockets brutes violent l'isolation normale du réseau : un processus normal ne peut recevoir que les données qui lui sont adressées via une socket TCP/UDP standard. Une socket brute casse cette isolation en donnant accès à tout le trafic.

    socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL)) nécessite les privilèges root. Le noyau vérifie que l'UID effectif du processus est 0 (ou que la capacité CAP_NET_RAW est présente dans son allowed set).

    Sans privilèges, sniff() échoue avec PermissionError car Scapy ne peut pas ouvrir la socket de capture.
```

# 1.4.1 Question de comprehension --Partie B

