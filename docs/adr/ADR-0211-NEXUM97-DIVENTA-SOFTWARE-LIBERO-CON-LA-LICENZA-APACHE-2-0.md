# ADR-0211 — NEXUM/97 diventa software libero, con la licenza Apache 2.0

Ideazione e progettazione: Giuseppe LISI

**Stato:** accettato (decisione del committente del 2026-11-25) · **Data:** 2026-11-25 ·
**Milestone:** OSS-LICENSING-01 · **Decisione:** DEC-524 · **Sostituisce:** ADR-0007 (la licenza
proprietaria del prodotto) · **Modifica:** ADR-0210 §3 (il codice pubblicato «per consultazione»)
· **Non modifica:** ADR-0005 (Slint), ADR-0048 (nessuna intelligenza artificiale), ADR-0210 per il
resto (che cosa si pubblica e come)

## Il fatto

Dal 2026-11-24 il codice sorgente della 0.2.2 è nella repository pubblica con la licenza
proprietaria di ADR-0007, «per consultazione» (ADR-0210, DEC-522). Il 2026-11-25 il committente,
titolare dei diritti, ha deciso di farne un progetto **effettivamente open source**, con la
licenza raccomandata Apache-2.0, dopo una verifica di titolarità, dipendenze, Slint, TDLib,
risorse grafiche, caratteri, obblighi di attribuzione, materiali non redistribuibili, segreti e
contributi di terzi.

## La verifica

| Punto | Che cosa si è guardato | Esito |
|---|---|---|
| Titolarità | Gli autori dei commit dell'archivio: tutti del titolare; gli altri nomi sono le righe `Co-Authored-By` dello strumento di sviluppo assistito, che non è un contributore umano | Il titolare ha i diritti sul codice originale |
| Contributi di terzi | Nessuna richiesta di modifica esterna, nessun codice copiato da altri progetti, nessuna intestazione di licenza altrui nei sorgenti | Nessun diritto di terzi da chiedere |
| Dipendenze Rust | L'elenco ammesso di `deny.toml`: MIT, Apache-2.0, Apache-2.0 WITH LLVM-exception, BSD-2-Clause, BSD-3-Clause, BSL-1.0, ISC, Unicode-3.0, Zlib; `cargo deny check licenses` verde | Tutte compatibili con Apache-2.0; nessuna è inclusa nella repository |
| Slint | Il testo della Royalty-free Desktop, Mobile, and Web Applications License 2.0 incluso nel pacchetto 1.17.1, e la GPL-3.0 | Le condizioni di Slint valgono per chi **distribuisce il programma compilato**, non per il nostro codice sorgente. Chi distribuisce sceglie: la royalty-free, con l'attribuzione (il riquadro `AboutSlint` è già in «Informazioni e licenze»), per un'applicazione desktop e non per sistemi incorporati; oppure la GPL-3.0, con cui il codice Apache-2.0 si combina |
| TDLib | Boost Software License 1.0 | Compatibile; non inclusa, caricata a runtime |
| Caratteri | Sora e IBM Plex Mono, SIL Open Font License 1.1 | Non inclusi; scaricati e verificati per impronta |
| Marchio e icone | `assets/brand/`: generati da uno script del progetto, nessuna opera di terzi | Il titolare ne ha i diritti; il nome e il segno restano esclusi come marchio (licenza, sezione 6) |
| Materiali non redistribuibili | L'esportazione di ADR-0210 lascia fuori dizionari operativi, documenti interni, installer, binari, configurazioni reali | Nulla di non redistribuibile entra |
| Segreti e dati riservati | La ricerca dei segreti e delle parole operative dell'esportazione; la scansione dei segreti di GitHub sulla repository pubblica | Nessun segreto, nessun avviso aperto |

## Le decisioni

### 1. La licenza

Il prodotto passa alla **Apache License 2.0** (SPDX `Apache-2.0`). Il file `LICENSE` porta il testo
ufficiale, senza modifiche. Il `NOTICE` porta il copyright, la formula di attribuzione, l'esclusione
del marchio e l'elenco dei componenti di terze parti. I manifest dichiarano `license = "Apache-2.0"`;
la schermata «Informazioni e licenze», la riga di copyright dell'eseguibile e la distinta dei
componenti dicono la stessa licenza.

### 2. Nessuna restrizione nella licenza

La licenza non limita chi usa il programma né per che cosa: una clausola del genere la renderebbe
incompatibile con la definizione di open source. **L'uso legittimo si dice in un'informativa a
parte** (`USO_LEGITTIMO.md` nella repository pubblica), che non è una condizione della licenza. Le
regole di disegno — nessuna intelligenza artificiale, solo API ufficiali, nessun ingresso o
invio automatico, la decisione umana — restano nel codice e nelle sue prove, e il progetto non
accetta contributi che le tolgano (`CONTRIBUTING.md`).

### 3. Il marchio

Il nome «NEXUM/97» e il segno dell'occhio identificano il progetto del titolare: la licenza non li
concede come marchio (sezione 6). I file del marchio si possono copiare e modificare come il resto
della repository.

### 4. I contributi

I contributi entrano con la stessa licenza (sezione 5), con la firma del Developer Certificate of
Origin su ogni commit (`git commit -s`). La formula «Ideazione e progettazione: Giuseppe LISI» non
cambia e non si aggiunge ai file dei contributori.

### 5. Il governo del progetto

Un titolare unico decide (`GOVERNANCE.md`). Lo sviluppo resta nell'archivio privato; il codice
arriva nella repository pubblica con l'esportazione di ADR-0210, a una milestone chiusa, in una
richiesta di modifica unita con lo squash.

### 6. I controlli automatici della repository pubblica

Senza materiali privati e senza costi: compilazione, Clippy e prove su un runner Windows; licenze e
avvisi con `cargo deny`; CodeQL; scansione dei segreti con il blocco al push; Dependabot. Il
controllo degli avvisi resta **rosso** finché RUSTSEC-2026-0543 (`chrono`) non ha una soluzione a
monte: non si nasconde e non si dichiara superato.

## Le conseguenze

- **Irrevocabile per le copie già fatte.** Chi riceve il codice con la Apache-2.0 lo conserva con
  quella licenza anche se un giorno il progetto ne cambiasse.
- **Chiunque può usare, modificare e ridistribuire il programma**, anche togliendo le regole di
  disegno nella propria copia. La licenza non lo impedisce; l'informativa e il rifiuto dei
  contributi che le tolgono sono ciò che resta al progetto.
- **Nessuna garanzia** (sezioni 7 e 8).
- **Brevetti**: chi contribuisce concede la licenza sui propri brevetti che il contributo usa
  (sezione 3).
- La versione distribuita in privato, con l'installer, porta la stessa licenza: il Setup mostra il
  file `LICENSE`.

## Che cosa non si fa

Nessuna licenza diversa per parti del codice. Nessuna clausola d'uso aggiunta alla licenza. Nessun
binario pubblicato. Nessuna storia privata importata. Nessun cambio della formula di attribuzione.
