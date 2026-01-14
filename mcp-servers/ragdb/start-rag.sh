#!/usr/bin/env bash
set -euo pipefail

# Ensure sudo is available (prompts once if needed)
sudo -v

sudo docker compose -f /home/kali/Desktop/mcp/ragdb/docker-compose.yml up -d --build
