#!/usr/bin/env bash
# netdefense — installazione/aggiornamento e avvio via Docker (macOS/Linux).
#
#   ./install.sh                 dentro la cartella dei sorgenti: aggiorna e avvia
#   ./install.sh ~/netdefense    clona lì se manca, poi avvia
#
# Richiede solo Docker (Desktop su Mac). Builda l'immagine (binario + tool Kali)
# e avvia la console su http://127.0.0.1:8088/.
set -euo pipefail

REPO="${NETDEFENSE_REPO:-https://github.com/rickyb82/netdefense}"
PORT="${NETDEFENSE_PORT:-8088}"
DIR="${1:-}"

info() { printf "\033[1;36m›\033[0m %s\n" "$*"; }
err()  { printf "\033[1;31m✗\033[0m %s\n" "$*" >&2; }

# 1) Docker presente e daemon attivo
if ! command -v docker >/dev/null 2>&1; then
  err "Docker non trovato. Installa Docker Desktop: https://www.docker.com/products/docker-desktop/"
  exit 1
fi
if ! docker info >/dev/null 2>&1; then
  err "Il daemon Docker non risponde: avvia Docker Desktop e riprova."
  exit 1
fi

# 2) Docker Compose v2 (docker compose) o v1 (docker-compose)
if docker compose version >/dev/null 2>&1; then
  COMPOSE="docker compose"
elif command -v docker-compose >/dev/null 2>&1; then
  COMPOSE="docker-compose"
else
  err "Docker Compose non disponibile. Aggiorna Docker Desktop."
  exit 1
fi

# 3) Individua/prepara la cartella dei sorgenti
if [ -z "$DIR" ] && [ -f Dockerfile ] && [ -f docker-compose.yml ]; then
  DIR="$(pwd)"
fi
DIR="${DIR:-$HOME/netdefense}"

if [ -d "$DIR/.git" ]; then
  info "Aggiorno i sorgenti in $DIR"
  git -C "$DIR" pull --ff-only || info "git pull non riuscito: proseguo con i sorgenti presenti"
elif [ -f "$DIR/Dockerfile" ]; then
  info "Uso i sorgenti in $DIR"
else
  if ! command -v git >/dev/null 2>&1; then
    err "git non trovato: installalo, oppure lancia lo script dentro la cartella dei sorgenti."
    exit 1
  fi
  info "Clono $REPO in $DIR"
  git clone "$REPO" "$DIR"
fi
cd "$DIR"

info "Build + avvio in corso…"
info "(il primo build scarica Rust+Kali e installa i tool: alcuni GB, qualche minuto)"
# shellcheck disable=SC2086
$COMPOSE up --build -d

URL="http://127.0.0.1:${PORT}/"
info "Attendo che il servizio risponda…"
for _ in $(seq 1 150); do
  if curl -fsS "http://127.0.0.1:${PORT}/health" >/dev/null 2>&1; then
    info "Pronto ✅"
    command -v open >/dev/null 2>&1 && open "$URL" || true
    echo
    info "Console:  ${URL}"
    info "Sorgenti: ${DIR}"
    info "Log:      ${COMPOSE} logs -f"
    info "Stop:     ${COMPOSE} down   (i dati restano nel volume nd-data)"
    exit 0
  fi
  sleep 2
done

err "Il servizio non ha risposto entro il tempo previsto. Controlla i log:  cd ${DIR} && ${COMPOSE} logs"
exit 1
