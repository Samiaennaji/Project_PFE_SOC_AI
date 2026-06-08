#!/usr/bin/env bash

# ==============================================================================
# Script de déploiement automatique pour SOC-AI sur VM OpenStack (Debian/Ubuntu)
# ==============================================================================

# Arrêter le script en cas d'erreur
set -e

# Couleurs pour l'affichage
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # Pas de couleur

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# 1. Vérification des droits root
if [ "$EUID" -ne 0 ]; then
    log_error "Veuillez exécuter ce script en tant que root ou avec sudo."
    exit 1
fi

log_info "Début de l'installation et du déploiement de SOC-AI..."

# 2. Vérification et installation de Docker
if ! command -v docker &> /dev/null; then
    log_warn "Docker n'est pas installé. Installation en cours..."
    
    # Mise à jour des paquets et installation des prérequis
    apt-get update -y
    apt-get install -y ca-certificates curl gnupg lsb-release

    # Ajout de la clé GPG officielle de Docker
    mkdir -p /etc/apt/keyrings
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg || \
    curl -fsSL https://download.docker.com/linux/debian/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg

    # Configuration du dépôt Docker
    echo \
      "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
      $(lsb_release -cs) stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null || \
    echo \
      "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/debian \
      $(lsb_release -cs) stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null

    apt-get update -y
    apt-get install -y docker-ce docker-ce-cli containerd.io
    log_info "Docker installé avec succès."
else
    log_info "Docker est déjà installé : $(docker --version)"
fi

# 3. Vérification de Docker Compose (plugin ou standalone)
if ! docker compose version &> /dev/null && ! command -v docker-compose &> /dev/null; then
    log_warn "Docker Compose n'est pas détecté. Installation du plugin Docker Compose..."
    apt-get update -y
    apt-get install -y docker-compose-plugin
    log_info "Docker Compose installé."
else
    log_info "Docker Compose est déjà installé."
fi

# Démarrage et activation du service Docker
systemctl enable docker
systemctl start docker

# 4. Préparation de la base de données et des fichiers de config locaux
log_info "Vérification des volumes et fichiers locaux..."
mkdir -p backend

# Initialiser le fichier logs.db vide s'il n'existe pas pour éviter que Docker ne crée un dossier
if [ ! -f backend/logs.db ]; then
    touch backend/logs.db
    chmod 666 backend/logs.db
    log_info "Fichier backend/logs.db créé et configuré."
fi

# Initialiser config.json s'il n'existe pas
if [ ! -f backend/config.json ]; then
    cat <<EOT > backend/config.json
{
    "attack_threshold": 0.15,
    "simulation_active": false,
    "simulation_speed": 1.5,
    "groq_api_key": ""
}
EOT
    chmod 666 backend/config.json
    log_info "Fichier de configuration par défaut backend/config.json créé."
fi

# 5. Lancement des conteneurs via Docker Compose
log_info "Lancement des conteneurs de l'application..."
if docker compose version &> /dev/null; then
    docker compose down --remove-orphans
    docker compose up -d --build
else
    docker-compose down --remove-orphans
    docker-compose up -d --build
fi

log_info "=============================================================="
log_info " SOC-AI a été déployé avec succès sur la VM !"
log_info " - Interface Web (Frontend) : http://localhost:80 (ou IP de la VM)"
log_info " - API (Backend)            : http://localhost:5000"
log_info "=============================================================="
log_info "Pour voir les logs en temps réel, lancez: docker compose logs -f"
