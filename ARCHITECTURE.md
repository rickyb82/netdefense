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

## Flotta multi-vendor e CVE (`src/fleet.rs`, `src/cve.rs`)

Pensato per un parco **multi-vendor di ~20.000 dispositivi**: MikroTik (anche
CHR), Keenetic, Huawei, Juniper, AVM, antenne Cambium (ePMP/Medusa), Ubiquiti,
e il VoIP (3CX, softswitch Cirpack).

- **Catalogo prodotti** (`fleet::catalog`): per ogni vendor il token CPE usato
  per matchare le CVE. Esteso man mano che cresce il parco.
- **Device facts** (`device_facts`): vendor, prodotto, **versione** e servizi di
  management/VoIP esposti per ciascun asset. La versione è ciò che serve alla
  correlazione CVE; si popola via `POST /assets/:id/facts` (in prospettiva da
  RouterOS API/The Dude, SNMP, API vendor, import PRTG).
- **Motore CVE** (`cve.rs`): parsing feed **NVD 2.0**, confronto versioni
  RouterOS-style, `Cve::affects(versione)`. Tutto puro e testato.
- **Correlazione** (`fleet::run_correlation`): per ogni CVE × device con
  prodotto e versione colpiti → **un alert** (dedup via `cve_matches`). Quando
  esce una CVE si sa subito **quali** apparati sono colpiti; l'alert esce dalle
  notifiche di Emily.
- **Classificatore esposizione** (`fleet::classify`): porte management/VoIP
  (Winbox 8291, RouterOS API 8728/9, Telnet, RDP, SNMP, TR-069, **SIP 5060/5061**,
  **Asterisk AMI 5038**, **3CX 5000/5001/5090**) con severità; usato dallo scan
  superficie per alzare la gravità dei finding.

API aggiunte: `POST /cve`, `GET /cve`, `POST /cve/import-nvd?product=<token>`,
`POST /cve/correlate`, `POST /assets/:id/facts`, `GET /fleet/catalog`.

## Roadmap

| Milestone | Contenuto | Stato |
|---|---|---|
| **M1** | Gate autorizzazione, modello dati, store SQLite, API, scan superficie esterna + diff | ✅ fatto |
| **M2** | Scheduler periodico per asset (`schedules`) + API | ✅ fatto |
| **M3** | Alerting su diff: alert persistiti + log + API | ✅ fatto |
| **M4** | Flotta multi-vendor + motore/correlazione **CVE** + classificatore esposizione VoIP/mgmt | ✅ fatto (logica pura, testata) |
| **M4b** | Poller **NVD 2.0** schedulato (reqwest, incrementale per prodotto, cursori `cve_sync_state`) → insert_cve + correlazione automatica | ✅ fatto (abilita con `NETDEFENSE_NVD_ENABLE=1`; advisory vendor: prossimo) |
| M5 | **Collettori inventario**: **SNMP live** ✅ — codec SNMPv2c BER puro+testato, trasporto UDP (tokio, no deps esterne), poller che legge `sysDescr`/`sysObjectID` dai device → `device_facts` → correlazione CVE (`NETDEFENSE_SNMP_ENABLE=1`); classificatore+API `snmp-classify` ✅; **import PRTG** ✅. WALK interfacce (NMS live), RouterOS API/The Dude, NETCONF: da fare | in corso |
| M6 | **NMS**: matematica banda da contatori (wrap 32/64 bit) + utilizzo + soglie/verdetto ✅ core+API; collector SNMP interfacce live + storicizzazione campioni: da fare | in corso |
| **M7** | Consegna alert: flag `delivered` + `notify::deliver_pending` (webhook → endpoint Emily, at-least-once, retry) | ✅ fatto lato netdefense (manca il piccolo endpoint `POST /api/integrations/netdefense/alert` lato Emily che chiama `events.notify`) |
| M8 | **VoIP** (SIP OPTIONS + fingerprint PBX) ✅ core+API; **estate web 200 siti** (scadenza TLS, voto header, change/defacement) ✅ core+API; invio UDP SIP live + fetch HTTPS/TLS-peek live + nikto/wpscan: da fare | in corso |
| M9 | **Lab/disclosure**: macchina a stati **coordinated disclosure** + candidati vuln ✅ core+API; lab-gate su authz + harness fuzzing: da fare | in corso |
| M10 | **NetFlow × BGP**: RPKI route-origin validation + validazione FlowSpec (cap anti-blackhole) + macchina stati mitigazione **approval-gated** (annuncio solo dopo approvazione) ✅ core+API; integrazione Akvorado/ClickHouse (flussi) + GoBGP (annuncio) + NTA/ML: da fare | in corso |
| M11 | Agente interno (modello ibrido) + mTLS; report per cliente; RBAC/multi-tenant | da fare |

### Nota disclosure
Per le vulnerabilità nuove trovate nel lab: disclosure **coordinata** (vendor →
CVE riservata → patch → pubblicazione). Pubblicare un 0-day prima della patch
esporrebbe per primo il parco di ~20.000 dispositivi.

## Scheduler (`src/scheduler.rs`) e Alerting (`src/alert.rs`)

- **Scheduler:** un task in background si sveglia a cadenza fissa
  (`NETDEFENSE_TICK_SECS`, default 30s), seleziona gli `schedules` scaduti e
  abilitati, esegue lo scan (sempre tramite il gate) e li ripianifica a
  `now + interval_secs`. Un fallimento transitorio non blocca i run futuri.
- **Alerting:** quando il diff è `is_noteworthy` (porte nuove o rimosse, mai
  sul primo scan-baseline) viene creato un `Alert` persistito, con severità
  derivata (nuova esposizione = Medium, sola rimozione = Low), e loggato. La
  consegna su canali esterni (webhook/email/Slack) si innesta dopo
  `alert::from_diff` — il seam è già pronto in `src/alert.rs`.

## Crate `kali-mcp/` (motore tool, personalizzabile)

Il repo è un **workspace Cargo**: oltre al servizio (`src/`) include il crate
`kali-mcp/` — il server MCP che espone i tool Kali (nmap, masscan, nikto,
sqlmap, hydra, …). Il registro dei tool è in
[`kali-mcp/src/tools.rs`](kali-mcp/src/tools.rs): ogni tool è un `ToolDef`
(nome, binario, descrizione, JSON-Schema dei parametri, funzione che costruisce
gli argomenti CLI). Si personalizza aggiungendo/modificando i `ToolDef` lì,
senza toccare il codice di protocollo. `netdefense` e `kali-mcp` condividono lo
stesso schema di esecuzione subprocess+timeout ma restano crate separati:
`kali-mcp` è il motore interattivo via MCP, `netdefense` è il servizio gestito
in cui ogni esecuzione passa dal gate di autorizzazione.

I tipi di scan non ancora implementati (`Vuln`, `Availability`, `WebHygiene`)
passano comunque dal gate e restituiscono `failed` con nota "scanner not yet
implemented" — il wiring è onesto su cosa gira davvero.
