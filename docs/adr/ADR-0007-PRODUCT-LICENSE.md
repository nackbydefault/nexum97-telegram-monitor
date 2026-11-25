# ADR-0007 — Licenza dei crate del prodotto e identità del repository

- **Stato:** **sostituito da ADR-0211** il 2026-11-25: il prodotto passa alla Apache License 2.0. Fino ad allora: adottato come impostazione tecnica
- **Data:** 2026-07-20
- **Riguarda:** `Cargo.toml`, `LICENSE`, `deny.toml`

## Contesto

Alla chiusura della Milestone 0, `cargo deny check licenses` ha segnalato:

```text
error[unlicensed]: lisi-core = 0.1.0 is unlicensed
error[unlicensed]: lisi-telegram-monitor = 0.1.0 is unlicensed
```

I crate del workspace non dichiaravano alcun campo `license`. Il problema era stato temporaneamente aggirato con `[licenses] private = { ignore = true }`, opzione corretta per i crate non pubblicati ma che lascia il prodotto senza una posizione dichiarata su un punto che è legale, non tecnico.

In parallelo, `Cargo.toml` conteneva un URL segnaposto: `https://github.com/OWNER/lisi-telegram-monitor`.

## Decisione

### Licenza

I crate dichiarano `license = "LicenseRef-LISI-Proprietary"` tramite `[workspace.package]`, con il testo in `LICENSE` nella radice del repository.

La forma `LicenseRef-` è il modo previsto da SPDX per riferirsi a una licenza non standard, ed è esattamente il caso di un prodotto proprietario. Tutti i crate mantengono `publish = false`: non finiranno mai su crates.io.

Il testo adottato è una riserva di diritti conservativa, coerente con la natura del prodotto: uso interno autorizzato, nessuna redistribuzione, nessuna concessione implicita. **È una base tecnica, non un parere legale.** Se il prodotto sarà distribuito a enti terzi, il testo va sostituito con quello concordato contrattualmente.

`deny.toml` conserva `private = { ignore = true }`: i crate del workspace restano esclusi dalla valutazione delle licenze delle dipendenze, che è il suo scopo. La dichiarazione esplicita in `Cargo.toml` non serve a far passare il controllo, ma a non lasciare il prodotto privo di una posizione dichiarata.

### URL del repository

Il campo `repository` è stato **rimosso**, non sostituito.

La visibilità del repository è una decisione ancora aperta e nessun URL reale è noto. Rimuovere il campo dice la verità; inventare un URL plausibile creerebbe un riferimento falso in un metadato destinato a sopravvivere, e per un prodotto usato in contesto investigativo l'accuratezza dei metadati non è un dettaglio. Il campo va reintrodotto quando l'URL definitivo esiste.

## Attribuzione Slint

Separata ma collegata: ADR-0005 stabilisce che la licenza royalty-free di Slint subordina la distribuzione a una condizione di attribuzione. Nella Milestone 1 il widget `AboutSlint` è stato inserito nell'interfaccia esistente.

La licenza chiede il widget in una schermata "Informazioni" raggiungibile dal menu di primo livello, oppure, **in assenza di tale schermata**, nella splash screen. L'applicazione non ha ancora né un menu né una schermata Informazioni: la collocazione attuale, nell'unica schermata esistente, ricade nella seconda ipotesi prevista dalla licenza stessa.

Resta vincolante spostare il widget in una vera schermata "Informazioni" quando la guida integrata verrà introdotta. L'obbligo non è soddisfatto in via definitiva: è soddisfatto in via provvisoria nella forma che la licenza ammette allo stato attuale dell'applicazione.

## Conseguenze

- `cargo deny check licenses` continua a passare.
- Il prodotto ha una posizione dichiarata sulla licenza, non un vuoto.
- Un metadato falso in meno.
- Restano due punti da chiudere con Giuseppe LISI: il testo definitivo della licenza e l'URL del repository.
