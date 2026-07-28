#!/usr/bin/env bash
# ─── ComplianceFlow AI: Azure VM Automated Setup Script ───
# Installs Docker, Docker Compose, configures ufw firewall, and launches stack

set -e

echo "=== [1/4] Updating Ubuntu/Debian system packages ==="
sudo apt-get update -y
sudo apt-get install -y ca-certificates curl gnupg lsb-release ufw

echo "=== [2/4] Installing Docker Engine & Docker Compose Plugin ==="
sudo install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg --yes
sudo chmod a+r /etc/apt/keyrings/docker.gpg

echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
  $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

sudo apt-get update -y
sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

sudo usermod -aG docker $USER || true

echo "=== [3/4] Configuring UFW Firewall ==="
sudo ufw allow 22/tcp || true
sudo ufw allow 80/tcp || true
sudo ufw allow 443/tcp || true
sudo ufw allow 3000/tcp || true
sudo ufw --force enable || true

echo "=== [4/4] Launching ComplianceFlow AI Docker Containers ==="
if [ -f "docker-compose.yml" ]; then
    sudo docker compose up --build -d
    echo "=== SUCCESS! ComplianceFlow AI stack is running in Docker. ==="
    sudo docker ps
else
    echo "Warning: docker-compose.yml not found in current directory. Please navigate to the project directory and run 'docker compose up -d'."
fi
