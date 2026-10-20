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
