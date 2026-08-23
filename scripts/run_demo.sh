#!/bin/bash
set -e

# ANSI Color Codes
CLR_RESET="\033[0m"
CLR_BOLD="\033[1m"
CLR_RED="\033[91m"
CLR_GREEN="\033[92m"
CLR_YELLOW="\033[93m"
CLR_CYAN="\033[96m"

echo -e "${CLR_CYAN}${CLR_BOLD}========================================================================${CLR_RESET}"
echo -e "${CLR_CYAN}${CLR_BOLD}      ATTACKTRACE Automated Multi-Service Demo Launcher                 ${CLR_RESET}"
echo -e "${CLR_CYAN}${CLR_BOLD}========================================================================${CLR_RESET}"

# 1. Verify Docker & Docker Compose installation
if ! command -v docker &> /dev/null; then
    echo -e "${CLR_RED}${CLR_BOLD}[ERROR] Docker is not installed on this system.${CLR_RESET}"
    exit 1
fi

# Detect if docker compose or docker-compose is available
DOCKER_COMPOSE="docker compose"
if ! docker compose version &> /dev/null; then
    if command -v docker-compose &> /dev/null; then
        DOCKER_COMPOSE="docker-compose"
    else
        echo -e "${CLR_RED}${CLR_BOLD}[ERROR] Docker Compose is not installed on this system.${CLR_RESET}"
        exit 1
    fi
fi

echo -e "${CLR_GREEN}[+] Docker and Compose verified successfully.${CLR_RESET}"

# 2. Build and launch containers in detached mode
echo -e "${CLR_YELLOW}[*] Building and starting services in detached mode...${CLR_RESET}"
$DOCKER_COMPOSE up --build -d

# 3. Wait for the engine healthcheck to turn green
echo -e "${CLR_YELLOW}[*] Waiting for attacktrace-engine health check to turn green...${CLR_RESET}"
MAX_RETRIES=30
RETRY_COUNT=0
HEALTHY=false

while [ $RETRY_COUNT -lt $MAX_RETRIES ]; do
    STATUS=$(docker inspect --format='{{json .State.Health.Status}}' attacktrace-engine 2>/dev/null || echo '"unknown"')
    if [ "$STATUS" == '"healthy"' ]; then
        HEALTHY=true
        break
    fi
    echo -n "."
    sleep 2
    RETRY_COUNT=$((RETRY_COUNT + 1))
done
echo ""

if [ "$HEALTHY" = true ]; then
    echo -e "${CLR_GREEN}[+] ATTACKTRACE Engine is healthy and accepting logs!${CLR_RESET}"
else
    echo -e "${CLR_RED}[-] Health check timed out or failed. Check container logs using '$DOCKER_COMPOSE logs'.${CLR_RESET}"
fi

# 4. Display ASCII Banner and Service Access URLs
echo -e "${CLR_CYAN}${CLR_BOLD}"
echo -e "  ▲  A T T A C K T R A C E   |   Production Container Demo Launch  "
echo -e "========================================================================${CLR_RESET}"
echo -e "  ${CLR_BOLD}Interactive Web SOC Console:${CLR_RESET}   ${CLR_GREEN}http://localhost:8000/dashboard${CLR_RESET}"
echo -e "  ${CLR_BOLD}Swagger REST API Documentation:${CLR_RESET} ${CLR_GREEN}http://localhost:8000/docs${CLR_RESET}"
echo -e "  ${CLR_BOLD}Live WebSocket Alerts Channel:${CLR_RESET}  ${CLR_GREEN}ws://localhost:8000/ws/alerts${CLR_RESET}"
echo -e "${CLR_CYAN}========================================================================${CLR_RESET}"
echo -e "Following container logs in real time... (Press Ctrl+C to exit launcher, containers will remain running)"
echo ""

# 5. Automatically follow logs
$DOCKER_COMPOSE logs -f
