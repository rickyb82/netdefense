# netdefense — architettura

Piattaforma di **monitoraggio proattivo gestito** della sicurezza (External
Attack Surface Management + monitoraggio disponibilità) per clienti MSSP.

> **Principio cardine — scope autorizzato.** Nessuno scan parte se l'asset non
> è esplicitamente autorizzato nel database. È un servizio che tocca reti di
> terzi: l'autorizzazione firmata (rules-of-engagement / contratto) è il
> fondamento legale e operativo, non un optional.

## Il gate di autorizzazione (`src/authz.rs`)

Punto di decisione unico. `authorize(asset, now)` consente lo scan **solo se**:
1. `auth_status == Active` (non Pending/Suspended/Revoked);
2. è presente un `roe_reference` (riferimento alla RoE/contratto firmato);
3. l'autorizzazione non è scaduta (`authorized_until`);
4. l'ora corrente è dentro la finestra giornaliera consentita (se impostata,
   anche a cavallo della mezzanotte);
5. il target non è vuoto.

Restituisce un `AuthorizedTarget` (non una stringa qualsiasi): un target può
raggiungere uno scanner **solo** dopo essere passato dal gate. Una richiesta
rifiutata viene **registrata** come scan `Refused` (audit trail), non scartata
in silenzio. Il gate è coperto da test unitari esaustivi.

## Modello dati (`src/domain.rs`, `src/store.rs`)

```
Client 1──* Asset 1──* Scan 1──* Finding
```

- **Client** — cliente dell'MSSP.
- **Asset** — unità autorizzata di scansione (host/dominio/URL/CIDR) con stato
  di autorizzazione, scadenza, finestra oraria, riferimento RoE.
- **Scan** — esecuzione (kind + status: queued/running/completed/failed/refused).
- **Finding** — risultato con `key` stabile (es. `tcp/443`) usata per il diff.

Persistenza: SQLite (`rusqlite`, bundled — nessun DB esterno). Le righe sono
lette come tuple primitive e poi "idratate" in tipi di dominio, così il
parsing fallibile (UUID/date/enum) sta fuori dalla closure di rusqlite.

## Motore di scansione (`src/scan/`)

- `runner.rs` — esecuzione subprocess con timeout rigido (stesso schema di
  kali-mcp), stdin chiuso, kill on drop.
- `external.rs` — **scan superficie esterna**: nmap top-ports, output
  greppable parsato in un finding per porta aperta. *Implementato.*
- `diff.rs` — confronto col baseline (scan completato precedente dello stesso
  tipo): `added` / `removed` / `unchanged`. Le porte nuove (`added`) sono ciò
  su cui il monitoraggio proattivo allerta. Il primo scan fa solo da baseline.
- `mod.rs` — orchestratore: gate → registra scan → scanner → findings → diff.

## API HTTP (`src/api.rs`, axum)

| Metodo | Route | Azione |
|---|---|---|
| POST | `/clients` | crea cliente |
| GET  | `/clients` | lista clienti |
| POST | `/clients/:id/assets` | aggiunge asset (parte `Pending`) |
| GET  | `/clients/:id/assets` | lista asset del cliente |
| GET  | `/assets/:id` | dettaglio asset |
| POST | `/assets/:id/authorize` | imposta stato/RoE/scadenza/finestra |
| POST | `/assets/:id/scan` | lancia scan (passa dal gate; refuse → 403) |
| GET  | `/assets/:id/findings` | findings dell'asset |
| GET  | `/scans/:id` | scan + findings |

## Modello ibrido (esterno + interno)

- **Esterno (implementato come fondamenta):** il servizio centrale scansiona
  gli asset pubblici autorizzati del cliente.
- **Interno (previsto):** una sonda/agente nella rete del cliente invia
  telemetria al centrale tramite la stessa API/modello dati. L'agente erediterà
  lo stesso vincolo di scope autorizzato.

## Roadmap

| Milestone | Contenuto | Stato |
|---|---|---|
| **M1** | Gate autorizzazione, modello dati, store SQLite, API, scan superficie esterna + diff | ✅ fatto |
| M2 | Scheduler periodico per asset + storicizzazione baseline | da fare |
| M3 | Alerting (webhook/email/Slack) su diff `is_noteworthy` | da fare |
| M4 | Scanner **Vuln/CVE** (fingerprint versioni → feed CVE) | stub gated |
| M5 | Scanner **Disponibilità/DoS** (uptime, latenza, anomalie) | stub gated |
| M6 | Scanner **igiene web/WordPress** (nikto/wpscan periodici) | stub gated |
| M7 | Agente interno (modello ibrido) + mTLS | da fare |
| M8 | Report periodici per cliente + dashboard | da fare |
| M9 | Autenticazione/RBAC sull'API, multi-tenant hardening | da fare |

I tipi di scan non ancora implementati (`Vuln`, `Availability`, `WebHygiene`)
passano comunque dal gate e restituiscono `failed` con nota "scanner not yet
implemented" — il wiring è onesto su cosa gira davvero.
