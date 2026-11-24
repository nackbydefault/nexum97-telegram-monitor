# NEXUM/97 — Telegram Intelligence Monitor

Ideazione e progettazione: Giuseppe LISI

NEXUM/97 è un programma per Windows 10 e 11 (x64), scritto in Rust con l'interfaccia Slint, per
il **monitoraggio autorizzato** di fonti Telegram accessibili a un account d'ufficio. Usa
soltanto le API ufficiali di Telegram, attraverso TDLib.

Questa repository contiene il **codice sorgente pubblicabile** del programma, alla versione
0.2.2, con le correzioni già fatte. È pubblicato **per consultazione**: il progetto è
**proprietario** e non è open source (vedi [Licenza](#licenza)).

## Che cosa fa, e che cosa non fa

- Segue fonti autorizzate, applica dizionari versionati con regole deterministiche e mostra
  all'operatore perché un contenuto è stato segnalato.
- Tiene separati il dato originale, l'analisi del programma e la valutazione dell'operatore.
- **Non usa intelligenza artificiale** di alcun tipo: nessun modello, nessun servizio di
  inferenza, nessun punteggio appreso ([ADR-0048](docs/adr/ADR-0048-NESSUNA-INTELLIGENZA-ARTIFICIALE.md)).
- Non entra da sé in gruppi, non scrive, non reagisce, non spende Telegram Stars.
- Non attribuisce responsabilità e non classifica persone: ogni valutazione è di una persona,
  con il motivo e l'istante.

## Che cosa c'è in questa repository

- `crates/` — il codice: interfaccia (`lisi-app`), servizi applicativi, modello del dominio,
  archivio SQLite con le migrazioni, connettore Telegram, sicurezza, piattaforma Windows,
  trasporto dell'Hub fra postazioni.
- `assets/brand/` — il marchio e l'icona del programma.
- `assets/dizionari-esempio/` — due **dizionari d'esempio** neutri, installati al primo avvio.
- I file che fissano per impronta le versioni di ciò che si scarica (`*.lock.json`) e lo script
  che scarica i caratteri (`scripts/fetch-fonts.ps1`).
- `docs/` — tre decisioni del progetto (la licenza del prodotto, la licenza di Slint, nessuna
  intelligenza artificiale) e il lessico comune che le prove dell'italiano semplice usano.

## Che cosa non c'è

- La storia di sviluppo: questa repository ha una storia sua, nuova.
- I **dizionari operativi**, sostituiti dagli esempi.
- La documentazione interna del progetto (decisioni, procedure, revisioni, manuali), le
  schermate e i materiali degli strumenti di sviluppo.
- Le prove automatiche che leggono quella documentazione: il codice pubblicato porta tutte le
  altre.
- L'installer, la libreria TDLib, i caratteri e ogni binario. Nessuna credenziale: quelle con cui
  il programma si presenta a Telegram arrivano con la distribuzione privata.

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
versione fissata da `tdlib.lock.json`.

`cargo deny check` segnala oggi RUSTSEC-2026-0543 su `chrono`, una dipendenza dell'interfaccia
Slint senza ancora una soluzione a monte.

## Componenti di terze parti

Le dipendenze si scaricano da crates.io con le loro licenze. L'interfaccia usa
[Slint](https://slint.dev) con la licenza royalty-free per applicazioni desktop, che chiede
un'attribuzione: il programma la mostra nella schermata «Informazioni e licenze». I caratteri
(SIL Open Font License 1.1) e TDLib (Boost Software License 1.0) non sono inclusi: si scaricano
e si verificano per impronta.

## Sicurezza

Le vulnerabilità si segnalano in privato: vedi [SECURITY.md](SECURITY.md).

## Licenza

**Proprietaria, tutti i diritti riservati.** Vedi [LICENSE](LICENSE) e [NOTICE](NOTICE). La
pubblicazione del codice in questa repository **non concede** il diritto di usare, copiare,
modificare o ridistribuire il programma, in tutto o in parte, senza l'autorizzazione scritta del
titolare.

---

*English.* NEXUM/97 is a Windows desktop application, written in Rust with Slint, for the
**authorized** monitoring of Telegram sources reachable by an office account, through the
official API only. It uses **no artificial intelligence**. This repository publishes its source
code, version 0.2.2, **for reference only**: the project is **proprietary**, all rights
reserved, and is not open source. Publishing the code grants no right to use, copy, modify or
redistribute it. Operational dictionaries, internal documentation, development history,
installer and binaries are not included; two neutral example dictionaries replace the
operational ones. Report security issues privately (see SECURITY.md).
