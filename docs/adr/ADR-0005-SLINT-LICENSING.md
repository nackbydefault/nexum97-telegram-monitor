# ADR-0005 — Licenza d'uso di Slint

- **Stato:** **accettato** — decisione confermata da Giuseppe LISI il 2026-07-21
- **Data:** 2026-07-20, aggiornato il 2026-07-21 con la decisione presa
- **Riguarda:** `deny.toml`, requisiti di prodotto, schermata "Informazioni"
- **Fonte primaria:** `LICENSES/LicenseRef-Slint-Royalty-free-2.0.md` incluso nel crate `slint 1.17.1`

## Fatto rilevato

Alla prima risoluzione reale delle dipendenze, `slint 1.17.1` e tutti i crate `i-slint-*` dichiarano:

```text
license = "GPL-3.0-only OR LicenseRef-Slint-Royalty-free-2.0 OR LicenseRef-Slint-Software-3.0"
```

L'allow-list di `deny.toml` contiene soltanto Apache-2.0, BSD-2/3-Clause, ISC, MIT, Unicode-3.0 e Zlib. **Nessuna delle tre licenze di Slint è ammessa**: `cargo deny check licenses` fallirebbe. DEC-014 aveva correttamente rinviato la verifica; ora è dovuta.

## Analisi delle tre opzioni

**GPL-3.0-only.** Imporrebbe la distribuzione dell'intera applicazione sotto GPL-3.0, codice sorgente incluso. Incompatibile con un prodotto proprietario destinato a un contesto operativo riservato.

**LicenseRef-Slint-Royalty-free-2.0.** Concede diritti d'uso, modifica e distribuzione a titolo gratuito quando il Software è integrato in una *Desktop Application*, definita come programma progettato per girare su un computer general-purpose, tipicamente installato ed eseguito localmente. LISI Telegram Monitor rientra esattamente in questa definizione. Le limitazioni dichiarate non risultano applicabili al prodotto:

- non si distribuisce Slint da solo;
- non si tratta di un Embedded System;
- l'applicazione non espone le API di Slint.

**LicenseRef-Slint-Software-3.0.** Licenza commerciale a pagamento. Necessaria solo se una delle condizioni precedenti non fosse soddisfacibile.

## Proposta

Adottare **LicenseRef-Slint-Royalty-free-2.0**, che è gratuita e copre il caso d'uso, subordinatamente alla conferma di Giuseppe LISI e, se il contesto lo richiede, a una verifica legale.

## Obbligo operativo derivante — non rinviabile

La sezione 2 della licenza subordina la distribuzione a una condizione di attribuzione. Occorre soddisfare **una** delle due:

- **(a)** mostrare il widget `AboutSlint` in una schermata o finestra "Informazioni" raggiungibile dal menu di primo livello dell'applicazione; in assenza di tale schermata, mostrarlo nella splash screen;
- **(b)** mostrare il badge di attribuzione Slint su una pagina web pubblica, preferibilmente quella da cui si scaricano i binari.

Per un applicativo distribuito internamente e privo di pagina di download pubblica, l'opzione **(a)** è l'unica realisticamente praticabile.

**Conseguenza sui requisiti:** la schermata "Informazioni" cessa di essere un elemento facoltativo di rifinitura e diventa un requisito vincolante di conformità alla licenza, da consegnare non oltre la milestone che introduce la guida integrata. La sua assenza renderebbe la distribuzione non conforme.

## Effetto su `deny.toml`

L'allow-list va estesa con `LicenseRef-Slint-Royalty-free-2.0`. L'estensione è stata scritta con un commento che rimanda a questo ADR: l'allow-list non va mai ampliata in modo tacito per far passare il controllo.

Se Giuseppe LISI respingesse la proposta, le alternative sono acquistare la licenza commerciale oppure riconsiderare il toolkit grafico. La riconsiderazione ha un costo che cresce rapidamente con le milestone: va decisa ora, non alla release candidate.

## Rischio residuo

L'analisi è tecnica e si basa sul testo della licenza incluso nel crate. Non sostituisce un parere legale. Le licenze `LicenseRef-*` non sono licenze SPDX standard e il loro testo può cambiare tra versioni di Slint: a ogni aggiornamento della dipendenza il testo va riletto e questo ADR riverificato.

## Decisione presa — 2026-07-21

Giuseppe LISI ha confermato: **Slint viene mantenuto e adottato con la licenza royalty-free per applicazioni desktop**, `LicenseRef-Slint-Royalty-free-2.0`. Non si acquista la licenza commerciale e non si sostituisce il toolkit grafico.

### Come l'obbligo di attribuzione è stato soddisfatto

È stata scelta l'opzione **(a)**, l'unica praticabile per un applicativo privo di pagina di download pubblica.

- La voce **"Informazioni e licenze"** è presente nel menu di navigazione di primo livello ed è selezionabile.
- La schermata corrispondente contiene il widget `AboutSlint`, l'identità del prodotto, la licenza del prodotto e l'elenco dei componenti di terze parti.
- La collocazione **non è più provvisoria**. Il commento che dichiarava la provvisorietà è stato rimosso dal file `.slint` e sostituito con l'avvertenza di non spostare il widget senza rileggere questo ADR.

### Perché l'elenco delle attribuzioni sta nel codice Rust e non nel file di interfaccia

L'attribuzione di Slint è una **condizione di licenza**, non una cortesia. Un obbligo di conformità deve poter essere verificato automaticamente: un testo scritto a mano dentro `app-window.slint` non sarebbe coperto da alcun test, e una modifica dell'interfaccia potrebbe rimuoverlo senza che nulla se ne accorga.

L'elenco vive quindi in `crates/lisi-core/src/attribution.rs`, dove il componente Slint è marcato `attribution_required: true`. I test lo presidiano: uno verifica che Slint sia presente in elenco con l'identificatore di licenza corretto, uno che esista almeno un componente che rende la schermata obbligatoria, uno che nessun componente sia privo di licenza. Se qualcuno rimuovesse Slint dall'elenco, la suite fallirebbe con un messaggio che spiega che si sta violando la licenza.

Gli identificatori di licenza dell'elenco sono stati letti da `cargo metadata --filter-platform x86_64-pc-windows-msvc`, non trascritti a memoria.

### Cosa resta vero

Il rischio residuo dichiarato sopra non cambia: questa resta un'analisi tecnica basata sul testo della licenza incluso nel crate e non sostituisce un parere legale. A ogni aggiornamento di Slint il testo della licenza va riletto e questo ADR riverificato.
