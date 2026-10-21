# netdefense

Piattaforma di **monitoraggio proattivo gestito** della sicurezza (EASM) per
clienti MSSP: inventario della superficie esterna, rilevamento dei cambiamenti
nel tempo, con **scope autorizzato per asset** al centro del sistema.

Vedi [`ARCHITECTURE.md`](ARCHITECTURE.md) per il disegno completo e la roadmap.

> ⚠️ **Solo uso autorizzato.** Questo servizio scansiona reti. Ogni asset deve
> essere autorizzato da una rules-of-engagement / contratto firmato prima di
> poter essere scansionato — il gate di autorizzazione lo impone a livello di
> codice. Scansionare senza autorizzazione è reato.

## Stato: Milestone 1

Fondamenta funzionanti end-to-end:
- gate di autorizzazione (testato) — rifiuta asset non `Active`, scaduti, fuori
  finestra oraria o senza riferimento RoE;
- modello dati + persistenza SQLite;
- API HTTP (axum);
- scan della superficie esterna (nmap) con diff vs baseline.

## Build & run

```sh
cargo build --release
NETDEFENSE_ADDR=127.0.0.1:8088 NETDEFENSE_DB=netdefense.db ./target/release/netdefense
```

Variabili d'ambiente: `NETDEFENSE_ADDR` (default `127.0.0.1:8088`),
`NETDEFENSE_DB` (default `netdefense.db`). Richiede `nmap` installato
sull'host per lo scan della superficie esterna.

## Docker — pronto all'avvio sul Mac (con i tool Kali inclusi)

Richiede solo **Docker Desktop**. Dalla cartella dei sorgenti:

```sh
git clone https://github.com/rickyb82/netdefense && cd netdefense
./start.sh          # controlla Docker, builda, avvia e apre la console
```

`start.sh` fa tutto: verifica che Docker Desktop sia attivo, builda l'immagine,
avvia il container, attende che il servizio risponda e apre
`http://127.0.0.1:8088/`. In alternativa, a mano:

```sh
docker compose up --build
# poi apri: http://127.0.0.1:8088/
```

L'immagine è **multi-stage**: builda il binario netdefense (Rust) e lo mette su
una base **Kali** con installati i binari dei tool (nmap, sqlmap, nuclei, …), così
i wrapper funzionano davvero. Il DB SQLite persiste nel volume `nd-data`; la
console è esposta **solo su 127.0.0.1**.

- Primo build: scarica le immagini Rust+Kali e installa i tool (alcuni GB, qualche
  minuto). Gli avvii successivi (`docker compose up`) sono immediati.
- Apple Silicon: gira in **arm64** nativo; se un tool Kali manca per arm64,
  scommenta `platform: linux/amd64` in `docker-compose.yml` (più lento, via
  emulazione, ma massima copertura tool).
- Modalità MCP nel container: `docker compose run --rm -i netdefense netdefense mcp`.
- Un tool il cui binario non è nell'immagine risponde "not installed"; il resto
  funziona (la lista pacchetti è modificabile nel `Dockerfile`).

## Prova in locale su macOS (sviluppo, senza Docker)

Prerequisiti (una volta sola):

```sh
xcode-select --install                 # compilatore C (serve a SQLite bundled / rustls)
curl https://sh.rustup.rs -sSf | sh    # toolchain Rust (rustup)
brew install nmap                       # opzionale: per lo scan superficie (la SQLi nativa non serve tool esterni)
```

Clona, builda e avvia:

```sh
git clone https://github.com/rickyb82/netdefense && cd netdefense
cargo run --release                     # avvia il servizio HTTP + gestionale
# poi apri nel browser:
open http://127.0.0.1:8088/
```

Il binario è **autocontenuto**: crea `netdefense.db` nella cartella corrente,
la UI del gestionale è servita su `/`, nessun servizio esterno richiesto.

Loop di sviluppo (iterare prima del deploy):

```sh
cargo run                # build debug + avvio, rapido per le modifiche
cargo test               # tutti i test
cargo clippy && cargo fmt
```

Modalità MCP (server dei tool, per collegarlo a Emily o a un client MCP):

```sh
cargo run --release -- mcp     # parla JSON-RPC su stdin/stdout
```

I tool Kali (nmap, sqlmap, nuclei, …) sono opzionali: se un binario non è
installato il tool risponde "not installed", il resto funziona. Su macOS molti
si installano con Homebrew (`brew install nmap sqlmap nuclei ffuf …`); alcuni
sono solo Linux/Kali — per quelli conviene l'host di deploy.

> Prova subito, senza installare nulla d'altro: la **SQL injection** (`kind:
> sql_injection`) e la gestione asset/clienti dal gestionale girano con il solo
> binario.

## Esempio di flusso

```sh
B=http://127.0.0.1:8088

# 1. crea cliente
CID=$(curl -s -X POST $B/clients -H 'content-type: application/json' \
  -d '{"name":"ACME Spa","contact_email":"it@acme.example"}' | jq -r .id)

# 2. aggiungi asset (parte in stato "pending" → non scansionabile)
AID=$(curl -s -X POST $B/clients/$CID/assets -H 'content-type: application/json' \
  -d '{"kind":"host","value":"198.51.100.20"}' | jq -r .id)

# 3. autorizza (serve il riferimento RoE; opzionale scadenza + finestra oraria)
curl -s -X POST $B/assets/$AID/authorize -H 'content-type: application/json' \
  -d '{"status":"active","roe_reference":"RoE-2026-ACME-001",
       "window_start":"02:00:00","window_end":"06:00:00"}'

# 4. lancia lo scan (passa dal gate; se non autorizzato → HTTP 403 "refused")
curl -s -X POST $B/assets/$AID/scan -H 'content-type: application/json' \
  -d '{"kind":"external_surface"}'

# 5. findings
curl -s $B/assets/$AID/findings
```

## Test

```sh
cargo test     # gate, parsing nmap, diff baseline
```

## Relazione con kali-mcp

`netdefense` è il layer di servizio (clienti, autorizzazioni, scheduling,
findings); condivide con `kali-mcp` lo stesso schema di esecuzione dei tool
(subprocess + timeout). `kali-mcp` resta il motore interattivo via MCP; qui
l'esecuzione è sempre mediata dal gate di autorizzazione.
