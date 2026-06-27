# 1. Créer l'environnement virtuel
python3 -m venv venv

# 2. Activer l'environnement virtuel
source venv/bin/activate

# 3. Vérifier que pip est bien celui du venv
which pip  # Doit afficher .../venv/bin/pip

# 4. Installer les dépendances (sans sudo !)
pip install -r requirements.txt

# 5. Lancer l'application (toujours dans le venv)
sudo venv/bin/python app.py

# Lancer sur le port 5001
sudo python3 app.py --port=5001

# OU modifier directement dans app.py

-------------------------------------------------
## Avertissement légal et éthique
```
Les manipulations décrites dans ce document sont réservées à un cadre pédagogique
strict. Elles doivent impérativement être effectuées dans un environnement de
laboratoire entièrement isolé, sur des machines virtuelles appartenant à l’étudiant.
Toute reproduction de ces techniques sur un réseau tiers, sans autorisation explicite
et écrite du propriétaire du système, est constitutive d’une infraction pénale dans la
majorité des juridictions : accès frauduleux à un système de traitement automatisé
de données, interception de communications électroniques, usurpation d’identité
numérique.
L’objectif de ces travaux est de comprendre les mécanismes d’attaque afin de
concevoir des architectures défensives robustes et de justifier les bonnes pratiques
de sécurité auprès des utilisateurs et des décideurs.
```
