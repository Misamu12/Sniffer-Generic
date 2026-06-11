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