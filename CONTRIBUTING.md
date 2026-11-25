# Contribuire / Contributing

Ideazione e progettazione: Giuseppe LISI

Grazie dell'interesse. Questa pagina dice come proporre una modifica e che cosa il progetto
accetta. Le regole di comportamento sono nel [codice di condotta](CODE_OF_CONDUCT.md); chi decide e
come è in [GOVERNANCE.md](GOVERNANCE.md).

## Prima di cominciare

- **Le vulnerabilità non si segnalano in una issue**: si usa la segnalazione privata descritta in
  [SECURITY.md](SECURITY.md).
- Per un difetto o una proposta si apre una issue con il modello adatto. Per una modifica grande
  conviene parlarne prima nella issue: risparmia lavoro a tutti.
- **Mai dati veri**: niente credenziali, sessioni, numeri di telefono, nomi di gruppi reali,
  schermate con dati personali o registri non ripuliti. Gli esempi si fanno con dati inventati e
  con l'Esercitazione del programma (`--esercitazione`).

## Che cosa il progetto accetta

Il programma ha alcune regole che fanno parte del suo disegno. Una modifica che le toglie non
viene accolta, anche se la licenza permette a chiunque di farla nella propria copia:

- nessuna intelligenza artificiale nel prodotto: niente modelli, servizi di inferenza o punteggi
  appresi ([ADR-0048](docs/adr/ADR-0048-NESSUNA-INTELLIGENZA-ARTIFICIALE.md));
- soltanto le API ufficiali di Telegram; niente account falsi, proxy a rotazione, aggiramento dei
  CAPTCHA o dei limiti, tecniche contro il blocco degli account;
- niente ingressi automatici nei gruppi, niente messaggi, reazioni o spese in Telegram Stars;
- dato originale, analisi del programma e valutazione dell'operatore restano separati; nessuna
  classificazione automatica delle persone;
- l'interfaccia dipende soltanto dai servizi applicativi, non da TDLib né dall'archivio.

Sono benvenute le correzioni, le prove, l'accessibilità, le traduzioni, la documentazione e la
robustezza.

## Come si propone una modifica

1. Una copia della repository (fork) e un ramo per la modifica.
2. Il codice compila e passa i controlli, da Windows 10 o 11 x64:

   ```powershell
   cargo fmt --all -- --check
   cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
   cargo test --workspace --all-features --locked
   ```

   Per ciò che riguarda la sicurezza o una regola del programma, una prova che fallisce senza la
   modifica e passa con la modifica.
3. Ogni commit porta la firma del **Developer Certificate of Origin** (https://developercertificate.org):
   `git commit -s` aggiunge la riga `Signed-off-by: Nome <indirizzo>`. Con quella riga dichiari
   di avere il diritto di proporre il contributo con la licenza del progetto.
4. Una richiesta di modifica verso `main`, con il modello compilato. Il ramo `main` è protetto:
   si entra soltanto con una richiesta di modifica, unita con lo squash.

## La licenza dei contributi

Ogni contributo è proposto con la [Apache License 2.0](LICENSE), come dice la sezione 5 della
licenza. Non serve un accordo a parte. Nei file non si aggiunge la formula di attribuzione del
progetto né la si cambia: «Ideazione e progettazione: Giuseppe LISI» indica il titolare, e i
contributi restano riconosciuti nella storia dei commit.

## Lingua

Il progetto è scritto in italiano: codice, commenti, documenti e testi dell'interfaccia. Le issue
e le richieste di modifica si possono scrivere anche in inglese.

---

*English.* Report vulnerabilities privately (see SECURITY.md), never in an issue. Never include
real data: use synthetic data and the program's exercise mode. Changes that remove the program's
design rules (no AI, official API only, no automatic joining or posting, no evasion techniques,
separation of data, analysis and human judgement) are not accepted upstream, even though the
licence allows anyone to make them in their own copy. Fixes, tests, accessibility, translations
and documentation are welcome. Before opening a pull request run `cargo fmt`, `cargo clippy` with
`-D warnings` and `cargo test` as above, sign off every commit (`git commit -s`, Developer
Certificate of Origin) and target `main`, which only accepts squash-merged pull requests.
Contributions are licensed under the Apache License 2.0 (section 5); do not add or alter the
project's attribution line.
