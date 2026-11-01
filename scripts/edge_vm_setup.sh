#!/bin/bash
# Sentinel edge-VM setup (Debian/Ubuntu, e.g. a GCP spot VM).
#
# Provisions ONE machine as the "edge node": the whole demo stack runs on
# it over localhost, so the P2-12 story stays intact (local inference, no
# API calls, no network dependency at demo time).
#
# Usage (on the VM, after `gcloud compute ssh`):
#   chmod +x edge_vm_setup.sh
#   ./edge_vm_setup.sh [git-repo-url]   # default: github ajayka009/sentinel
#
# What it does:
#   1. apt: python3-venv, mosquitto (MQTT broker, localhost:1883), curl, git
#   2. installs Ollama + pulls muse-glimmer:30b (~18GB, takes a while)
#   3. clones the repo to ~/sentinel (if missing), venv + requirements
#   4. runs the P2-12 hardware gate (must PASS on this machine)
#
# Afterwards, on the VM (one terminal each, or tmux):
#   python3 sim/plc.py
#   python3 sim/sensors.py
#   python3 sim/yard.py --jitter 1 --drop 0.1
#   python3 sim/glimmer_operator.py --backend ollama --cycles 12
#   streamlit run console/app.py --server.address 127.0.0.1
# On your laptop, view the console through an SSH tunnel (no firewall rule):
#   gcloud compute ssh sentinel-edge --zone=Z -- -L 8501:localhost:8501
#   # then open http://localhost:8501
set -euo pipefail

REPO_URL="${1:-https://github.com/ajayka009/sentinel.git}"
DEST="$HOME/sentinel"
OLLAMA_MODEL="${OLLAMA_MODEL:-muse-glimmer:30b}"

echo "==> apt packages (python, mosquitto, curl, git)"
sudo apt-get update -y
sudo apt-get install -y python3 python3-venv python3-pip \
    mosquitto mosquitto-clients curl git

echo "==> mosquitto: localhost-only listener, anonymous (sim use only)"
printf 'listener 1883 127.0.0.1\nallow_anonymous true\n' \
    | sudo tee /etc/mosquitto/conf.d/sentinel.conf >/dev/null
sudo systemctl enable mosquitto
sudo systemctl restart mosquitto

if ! command -v ollama >/dev/null 2>&1; then
    echo "==> installing ollama"
    curl -fsSL https://ollama.com/install.sh | sh
fi
echo "==> ensuring ollama daemon is up"
sudo systemctl enable ollama 2>/dev/null || true
sudo systemctl start ollama 2>/dev/null || true
if ! ollama list >/dev/null 2>&1; then
    echo "    systemd unit unavailable; starting 'ollama serve' in background"
    nohup ollama serve >/tmp/ollama.log 2>&1 &
    sleep 5
fi

echo "==> pulling ${OLLAMA_MODEL} (~18GB — this takes a while)"
ollama pull "${OLLAMA_MODEL}"
ollama list

if [ ! -d "${DEST}/.git" ]; then
    echo "==> cloning ${REPO_URL} to ${DEST}"
    git clone "${REPO_URL}" "${DEST}"
else
    echo "==> repo already present at ${DEST} (leaving untouched)"
fi

echo "==> python venv + requirements"
cd "${DEST}"
[ -d .venv ] || python3 -m venv .venv
.venv/bin/pip install --upgrade pip
.venv/bin/pip install -r requirements.txt

echo "==> P2-12 hardware gate (must PASS here)"
.venv/bin/python sim/glimmer_operator.py --hardware-gate

echo
echo "Setup complete. Next, on this VM (one terminal each):"
echo "  cd ${DEST} && .venv/bin/python sim/plc.py"
echo "  cd ${DEST} && .venv/bin/python sim/sensors.py"
echo "  cd ${DEST} && .venv/bin/python sim/yard.py --jitter 1 --drop 0.1"
echo "  cd ${DEST} && .venv/bin/python sim/glimmer_operator.py --backend ollama --cycles 12"
echo "  cd ${DEST} && .venv/bin/streamlit run console/app.py --server.address 127.0.0.1"
