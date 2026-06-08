# Guide de Déploiement SOC-AI sur VM OpenStack

Ce guide vous explique pas à pas comment déployer l'application **SOC-AI** (Interface d'analyse et de classification d'alertes Wazuh assistée par IA) depuis votre poste local Windows vers votre machine virtuelle dans votre cloud d'entreprise OpenStack.

---

## 📋 Prérequis et Préparation

### 1. Configuration du Groupe de Sécurité dans OpenStack
Avant de vous connecter, allez dans votre tableau de bord OpenStack Horizon (**Projet > Réseau > Groupes de sécurité**) et assurez-vous que les règles suivantes sont actives pour votre VM :
* **Ingress (Entrant) - TCP Port 22** : Permet de vous connecter à la VM en SSH.
* **Ingress (Entrant) - TCP Port 80** : Permet d'accéder à l'interface web de l'application depuis votre navigateur.

### 2. Identifier votre VM cible
D'après votre tableau de bord, vous avez le choix entre deux machines principales :
* **Option A (Recommandé - Sizing Idéal)** : VM **`soc-srv`** (IP : `192.168.1.13`, Gabarit `4G-80go`)
* **Option B** : VM **`agent-vm 1`** (IP : `192.168.1.15`, Gabarit `flavor`)

> [!TIP]
> Nous utiliserons **`192.168.1.13`** (`soc-srv`) dans les exemples ci-dessous, mais vous pouvez remplacer cette IP par `192.168.1.15` si vous déployez sur l'autre VM.

---

## 🚀 Étape 1 : Transférer le code de Windows vers la VM

Si la connexion SSH directe (et donc SCP) ne fonctionne pas de votre Windows vers la VM (souvent dû à des restrictions de réseau d'entreprise), vous devez utiliser la **Méthode B (Git)**. Sinon, utilisez la **Méthode A (SCP)**.

---

### 🟢 Méthode A : Transfert direct par SCP (Si SSH fonctionne)

Si la connexion SSH directe fonctionne de votre poste Windows vers la VM, exécutez ceci dans **PowerShell** sur votre Windows local à la racine du projet :

```powershell
# Commande pour transférer le projet vers la VM (ex: 192.168.1.13)
scp -i "C:\Chemin\Vers\Votre\ssh-key" -r `
  (Get-ChildItem -Exclude "node_modules", ".venv", ".git", "__pycache__", "dist") `
  ubuntu@192.168.1.13:/home/ubuntu/ProjectSOC_AI_1/
```

Ensuite, connectez-vous en SSH et passez à l'**Étape 2**.

---

### 🔵 Méthode B : Déploiement via Git (Si SSH direct est bloqué)

Si le SSH est bloqué et que vous devez utiliser la **console Web VNC d'OpenStack Horizon** pour exécuter des commandes sur la VM, suivez ces étapes.

#### 1. Publier le projet local sur un serveur Git (depuis votre poste Windows)
Ouvrez un terminal **PowerShell** dans le dossier de votre projet sur Windows :

```powershell
# Initialiser Git localement (si ce n'est pas déjà fait)
git init

# Ajouter les fichiers au commit (les dépendances lourdes sont ignorées par .gitignore)
git add .
git commit -m "Initial commit for OpenStack deployment"

# Connecter à votre dépôt distant (GitHub, GitLab interne de l'entreprise, etc.)
# (Créez un dépôt vide sur votre GitHub/GitLab, puis remplacez l'URL ci-dessous)
git remote add origin https://github.com/VOTRE_COMPTE/VOTRE_DEPOT.git
git branch -M main

# Envoyer le code
git push -u origin main
```

#### 2. Récupérer le code sur la VM OpenStack (depuis la console Horizon)
1. Ouvrez le tableau de bord OpenStack Horizon et ouvrez la **Console Web VNC** de votre VM.
2. Connectez-vous avec vos identifiants Linux sur le terminal.
3. Installez Git sur la VM si ce n'est pas déjà fait :
   ```bash
   sudo apt-get update
   sudo apt-get install -y git
   ```
4. Récupérez le projet :
   ```bash
   git clone https://github.com/VOTRE_COMPTE/VOTRE_DEPOT.git ~/ProjectSOC_AI_1
   ```

---

## 🛠️ Étape 2 : Lancer le déploiement sur la VM

Que vous ayez utilisé la Méthode A (SCP) ou la Méthode B (Git), effectuez les actions suivantes **sur la VM** (soit via SSH, soit via la console Horizon) :

1. Déplacez-vous dans le dossier du projet :
   ```bash
   cd ~/ProjectSOC_AI_1/
   ```

2. Rendez le script de déploiement exécutable et lancez-le :
   ```bash
   chmod +x deploy.sh
   sudo ./deploy.sh
   ```

Ce script va automatiquement :
- Mettre à jour la VM Linux.
- Installer Docker et Docker Compose si nécessaire.
- Initialiser la base de données SQLite `logs.db` et le fichier de configuration `config.json`.
- Construire les conteneurs et les démarrer en arrière-plan.

---

## 🔍 Étape 3 : Vérifier le Déploiement

1. Sur la VM, vérifiez que les deux conteneurs tournent correctement :
   ```bash
   sudo docker ps
   ```
   Vous devriez voir :
   - `soc-ai-frontend` sur le port `80`
   - `soc-ai-backend` sur le port `5000`

2. Ouvrez votre navigateur internet sur votre poste local et connectez-vous à l'adresse de votre VM :
   * URL : **`http://192.168.1.13`** (ou `http://192.168.1.15`)
   * Vous devriez voir s'afficher l'interface d'administration moderne du SOC-AI.

---

## 🦅 Étape 4 : Configurer l'intégration avec Wazuh Manager

Pour que Wazuh envoie automatiquement ses alertes de sécurité à votre application SOC-AI, configurez l'intégration sur le serveur où tourne **Wazuh Manager** (votre serveur de sécurité).

### 1. Télécharger le script d'intégration personnalisé
Sur la VM ou le serveur hébergeant votre **Wazuh Manager**, téléchargez le script d'intégration généré par le backend SOC-AI :
```bash
sudo curl -o /var/ossec/active-response/bin/custom-soc-ai http://192.168.1.13/api/download/custom-soc-ai
sudo chmod 750 /var/ossec/active-response/bin/custom-soc-ai
sudo chown root:wazuh /var/ossec/active-response/bin/custom-soc-ai
```

### 2. Activer l'intégration dans Wazuh
Ouvrez le fichier de configuration principal de Wazuh Manager :
```bash
sudo nano /var/ossec/etc/ossec.conf
```

Ajoutez le bloc `<integration>` suivant à la fin du fichier, à l'intérieur du bloc principal `<ossec_config>` :
```xml
<ossec_config>
  <!-- ... autres configurations ... -->

  <!-- Intégration personnalisée vers SOC-AI -->
  <integration>
    <name>custom-soc-ai</name>
    <hook_url>http://192.168.1.13/api/alerts</hook_url>
    <alert_format>json</alert_format>
  </integration>
</ossec_config>
```

> [!IMPORTANT]
> Si vous souhaitez n'envoyer que les alertes critiques (par exemple, de niveau égal ou supérieur à 7), vous pouvez ajouter une balise de filtre :
> `<level>7</level>` dans le bloc d'intégration ci-dessus.

### 3. Redémarrer Wazuh Manager
Pour appliquer les modifications :
```bash
sudo systemctl restart wazuh-manager
```

Désormais, chaque alerte Wazuh correspondante sera envoyée en temps réel au classifieur XGBoost de votre application SOC-AI.

---

## 🔑 Étape 5 : Configurer l'API de l'IA (Groq / Gemini)

Une fois l'application lancée, l'analyse détaillée par LLM nécessitera une clé API. Vous pouvez l'ajouter de deux manières :

* **Option A (Depuis l'Interface Graphique - Recommandé)** :
  1. Allez sur l'application Web à l'adresse `http://192.168.1.13`.
  2. Cliquez sur l'onglet **Paramètres** ou l'icône d'engrenage.
  3. Saisissez votre clé API Groq (commençant par `gsk_`) ou Gemini dans le champ prévu et validez.

* **Option B (En modifiant le fichier de configuration sur la VM)** :
  1. Sur la VM, éditez le fichier `config.json` :
     ```bash
     sudo nano ~/ProjectSOC_AI_1/backend/config.json
     ```
  2. Ajoutez votre clé API :
     ```json
     {
         "attack_threshold": 0.15,
         "simulation_active": false,
         "simulation_speed": 1.5,
         "groq_api_key": "VOTRE_CLE_API_GROQ_ICI"
     }
     ```
  3. Enregistrez et redémarrez les conteneurs : `sudo docker compose restart`
