# NEXUM/97 — Telegram Intelligence Monitor

Ideazione e progettazione: Giuseppe LISI

[![Licenza: Apache 2.0](https://img.shields.io/badge/licenza-Apache%202.0-blue.svg)](LICENSE)
[![CI Windows](https://github.com/nackbydefault/nexum97-telegram-monitor/actions/workflows/ci.yml/badge.svg)](https://github.com/nackbydefault/nexum97-telegram-monitor/actions/workflows/ci.yml)
[![Catena di fornitura](https://github.com/nackbydefault/nexum97-telegram-monitor/actions/workflows/catena-di-fornitura.yml/badge.svg)](https://github.com/nackbydefault/nexum97-telegram-monitor/actions/workflows/catena-di-fornitura.yml)

NEXUM/97 è un programma per Windows 10 e 11 (x64), scritto in Rust con l'interfaccia Slint, per
il **monitoraggio autorizzato** di fonti Telegram accessibili a un account d'ufficio. Usa
soltanto le API ufficiali di Telegram, attraverso TDLib.

È **software libero**, con la [Apache License 2.0](LICENSE): si può usare, studiare, modificare e
ridistribuire alle condizioni della licenza. Questa repository contiene il codice sorgente della
versione 0.2.2, con le correzioni del collaudo.

## Che cosa fa, e che cosa non fa

- Segue fonti autorizzate, applica dizionari versionati con regole deterministiche e mostra
  all'operatore perché un contenuto è stato segnalato.
- Tiene separati il dato originale, l'analisi del programma e la valutazione dell'operatore.
- **Non usa intelligenza artificiale** di alcun tipo: nessun modello, nessun servizio di
  inferenza, nessun punteggio appreso ([ADR-0048](docs/adr/ADR-0048-NESSUNA-INTELLIGENZA-ARTIFICIALE.md)).
- Non entra da sé in gruppi, non scrive, non reagisce, non spende Telegram Stars.
- Non attribuisce responsabilità e non classifica persone: ogni valutazione è di una persona,
  con il motivo e l'istante.

Per che cosa è pensato, e che cosa resta a chi lo usa: [USO_LEGITTIMO.md](USO_LEGITTIMO.md). È
un'informativa, non una condizione della licenza.

## Che cosa c'è in questa repository

- `crates/` — il codice: interfaccia (`lisi-app`), servizi applicativi, modello del dominio,
  archivio SQLite con le migrazioni, connettore Telegram, sicurezza, piattaforma Windows,
  trasporto dell'Hub fra postazioni.
- `assets/brand/` — il marchio e l'icona del programma.
- `assets/dizionari-esempio/` — due **dizionari d'esempio** neutri, installati al primo avvio.
- I file che fissano per impronta le versioni di ciò che si scarica (`*.lock.json`) e lo script
  che scarica i caratteri (`scripts/fetch-fonts.ps1`).
- `docs/` — alcune decisioni del progetto (la licenza del prodotto, la licenza di Slint, nessuna
  intelligenza artificiale) e il lessico comune che le prove dell'italiano semplice usano.

## Che cosa non c'è

- La storia di sviluppo, che sta in un archivio privato: questa repository ha una storia sua.
- I dizionari operativi, sostituiti dagli esempi; la documentazione interna; le schermate.
- Le prove automatiche che leggono la documentazione interna: il codice pubblicato porta tutte
  le altre.
- L'installer, la libreria TDLib, i caratteri e ogni binario. Nessuna credenziale: quelle con cui
  il programma si presenta a Telegram non sono qui.

## Compilare

Servono Windows 10 o 11 x64, Microsoft C++ Build Tools con il Windows SDK, e Rust nella versione
fissata da `rust-toolchain.toml`.

```powershell
cargo build                                # il programma, in modalità di sviluppo
cargo test --workspace --all-features      # le prove
.\scripts\fetch-fonts.ps1                  # i caratteri, verificati per impronta
cargo build --release                      # una build di rilascio: richiede i caratteri
```

Compilato senza la funzione `tdlib-runtime`, come fa `cargo build`, il programma lo dichiara e non
offre la modalità reale; l'Esercitazione (`--esercitazione`) funziona con dati sintetici. Con
`--features tdlib-runtime` la libreria TDLib, che non è inclusa, va costruita a parte nella
versione fissata da `tdlib.lock.json`. Per collegarsi a Telegram servono le credenziali di
un'applicazione registrata su https://my.telegram.org, che non sono in questa repository.

## Controlli automatici

Su ogni richiesta di modifica: compilazione, Clippy e prove su Windows; licenze e avvisi di
sicurezza delle dipendenze con `cargo deny`; CodeQL; scansione dei segreti e Dependabot.

Il controllo degli avvisi è **rosso** per RUSTSEC-2026-0543 su `chrono`, una dipendenza
dell'interfaccia Slint senza ancora una soluzione a monte: resta rosso finché l'avviso c'è.

## Componenti di terze parti

Le dipendenze si scaricano da crates.io con le loro licenze; l'elenco è in [NOTICE](NOTICE).
L'interfaccia usa [Slint](https://slint.dev), con tre licenze a scelta: **chi compila e
distribuisce il programma** sceglie la GPL-3.0, oppure la licenza royalty-free per applicazioni
desktop, che chiede un'attribuzione: il programma la mostra nella schermata «Informazioni e
licenze». I caratteri (SIL Open Font License 1.1) e TDLib (Boost Software License 1.0) non sono
inclusi: si scaricano e si verificano per impronta.

## Contribuire

Le istruzioni sono in [CONTRIBUTING.md](CONTRIBUTING.md), le regole di comportamento in
[CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md), chi decide in [GOVERNANCE.md](GOVERNANCE.md). Le
vulnerabilità si segnalano in privato: [SECURITY.md](SECURITY.md).

## Licenza

[Apache License 2.0](LICENSE). Copyright (c) 2026 Giuseppe LISI. Il nome «NEXUM/97» e il segno
dell'occhio non sono concessi come marchio: vedi [NOTICE](NOTICE).

---

*English.* NEXUM/97 is a Windows desktop application, written in Rust with Slint, for the
**authorized** monitoring of Telegram sources reachable by an office account, through the
official API only. It uses **no artificial intelligence**. It is **free software** under the
[Apache License 2.0](LICENSE). This repository holds the source code of version 0.2.2 with the
fixes from its acceptance test. Operational dictionaries, internal documentation, development
history, installer and binaries are not included; two neutral example dictionaries replace the
operational ones. Slint is used under one of its licences, chosen by whoever builds and
distributes the program (GPL-3.0 or the royalty-free desktop licence, which requires the
attribution shown in the About screen). The supply-chain advisory check stays red for
RUSTSEC-2026-0543 (`chrono`) until an upstream fix exists. See CONTRIBUTING.md, GOVERNANCE.md,
SECURITY.md and USO_LEGITTIMO.md (a lawful-use notice, not a licence condition).
