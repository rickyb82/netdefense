#!/usr/bin/env bash
# netdefense — avvio su macOS.
# Lancialo dalla cartella dei sorgenti:  ./start.sh
# Builda l'immagine Docker (binario + tool Kali) e avvia la console su :8088.
set -euo pipefail

cd "$(dirname "$0")"

PORT="${NETDEFENSE_PORT:-8088}"
URL="http://127.0.0.1:${PORT}/"

info() { printf "\033[1;36m›\033[0m %s\n" "$*"; }
err()  { printf "\033[1;31m✗\033[0m %s\n" "$*" >&2; }

# 1) Cartella giusta?
if [ ! -f Dockerfile ] || [ ! -f docker-compose.yml ]; then
  err "Esegui lo script dalla cartella dei sorgenti di netdefense (dove ci sono Dockerfile e docker-compose.yml)."
  exit 1
fi

# 2) Docker presente e daemon attivo?
if ! command -v docker >/dev/null 2>&1; then
  err "Docker non trovato. Installa Docker Desktop: https://www.docker.com/products/docker-desktop/"
  exit 1
fi
if ! docker info >/dev/null 2>&1; then
  err "Il daemon Docker non risponde: avvia Docker Desktop e riprova."
  exit 1
fi

# 3) compose v2 (docker compose) o v1 (docker-compose)
if docker compose version >/dev/null 2>&1; then
  COMPOSE="docker compose"
elif command -v docker-compose >/dev/null 2>&1; then
  COMPOSE="docker-compose"
else
  err "Docker Compose non disponibile. Aggiorna Docker Desktop."
  exit 1
fi

info "Build + avvio in corso…"
info "(il primo build scarica Rust+Kali e installa i tool: alcuni GB, qualche minuto; i successivi sono immediati)"
# shellcheck disable=SC2086
$COMPOSE up --build -d

info "Attendo che il servizio risponda…"
for _ in $(seq 1 150); do
  if curl -fsS "http://127.0.0.1:${PORT}/health" >/dev/null 2>&1; then
    info "Pronto ✅"
    command -v open >/dev/null 2>&1 && open "$URL" || true
    echo
    info "Console:  ${URL}"
    info "Log:      ${COMPOSE} logs -f"
    info "MCP:      ${COMPOSE} run --rm -i netdefense netdefense mcp"
    info "Stop:     ${COMPOSE} down   (i dati restano nel volume nd-data)"
    exit 0
  fi
  sleep 2
done

err "Il servizio non ha risposto entro il tempo previsto. Controlla i log:  ${COMPOSE} logs"
exit 1
