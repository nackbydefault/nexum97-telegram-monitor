# ADR-0048 — NEXUM/97 non usa intelligenza artificiale

- **Stato:** **accettato**
- **Data:** 2026-08-25
- **Riguarda:** l'intero prodotto, permanentemente
- **Rapporto con le decisioni precedenti:** **generalizza** la regola «Nessun
  modello, nessun servizio esterno» che ADR-0035 aveva scritto per la sola
  Public Discovery, e la rende un vincolo di prodotto
- **Milestone:** PF-01

**Ideazione e progettazione: Giuseppe LISI**

---

## La decisione

NEXUM/97 **non usa** capacità di intelligenza artificiale, apprendimento
automatico o modelli linguistici. Non ne usa oggi e non deve usarne in futuro
senza un ADR che revochi esplicitamente questo.

Non entrano nel prodotto, in nessuna forma:

- servizi di inferenza remoti, di qualunque fornitore;
- modelli linguistici locali;
- rappresentazioni vettoriali (*embedding*) e ricerca per similarità semantica;
- classificazione appresa da esempi;
- riassunto generativo;
- punteggi di rischio prodotti da un modello;
- valutazione automatica di una persona;
- punteggi di pericolosità appresi.

**L'architettura analitica del prodotto è, e resta:** regole deterministiche,
statistica, correlazione, tassonomie versionate, algoritmi riproducibili,
revisione umana.

**Nessun contenuto monitorato viene inviato a un sistema di inferenza.**

---

## Le quattro ragioni, in ordine di peso

### 1. Un documento che si firma deve essere riproducibile

Il prodotto produce relazioni che escono dall'ufficio e che qualcuno
sottoscrive. Fra sei mesi deve essere possibile dire: *con questi dati, con
questa versione del dizionario e con questa versione del motore, il risultato è
questo* — e riottenerlo.

Un modello non versionato in modo verificabile, o servito da remoto e cambiato
senza preavviso, rende quella frase impossibile da pronunciare. Non è una
preferenza tecnica: è la differenza fra un documento che regge e un documento
che non regge.

Questa è la ragione per cui la milestone ENGINE-01 introduce una **versione del
motore** accanto alla versione del dizionario. Serve perché il motore è
deterministico. Un motore appreso renderebbe quella versione un'etichetta senza
contenuto.

### 2. Il livello 0-4 si spiega a una persona, o non vale niente

Il motore di analisi esiste per dire **perché**: quale regola, quale termine,
quale combinazione, quale dizionario, quale versione. La motivazione leggibile
non è un ornamento dell'interfaccia, è il prodotto.

«Il modello lo ha classificato così» non è una motivazione. È l'assenza di una
motivazione con la forma di una motivazione, ed è peggio del silenzio, perché
si lascia citare.

Lo stesso vale per ogni collegamento del futuro Evidence Graph (GRAPH-01): un
arco senza provenienza non deve essere costruibile. Un'inferenza appresa è
esattamente un arco senza provenienza.

### 3. Il contenuto monitorato non lascia la postazione

L'inferenza in cloud significa spedire a un terzo il contenuto sorvegliato:
messaggi, autori, identificativi, contesto. Su un'attività di monitoraggio
autorizzato questo è inaccettabile a prescindere dal fornitore e dalle sue
promesse contrattuali.

Il divieto era già scritto per la Public Discovery. Qui diventa una proprietà
del prodotto intero.

### 4. Il confine della decisione umana

NEXUM/97 osserva fatti, li aggrega e li correla. **Non** attribuisce
responsabilità, **non** produce probabilità di pericolosità, **non** classifica
una persona come criminale o estremista per la sua affiliazione politica, il suo
dissenso lecito o la sua partecipazione a una manifestazione lecita.

La valutazione di un soggetto (PERS-05) è **un atto di un operatore**, con
motivo obbligatorio e audit. I segnali osservati si mostrano accanto a quella
valutazione, mai al posto suo.

Un punteggio appreso è la cosa che questo prodotto esiste per non produrre.
Averlo dietro un'impostazione spenta non basterebbe: dev'essere **codice che non
c'è**.

---

## Che cosa questo vincolo costa

Un ADR che elenca solo vantaggi sta nascondendo qualcosa. Questo costa tre cose
reali, e vanno scritte perché nessuno le scopra dopo e le usi per riaprire la
decisione senza discuterla.

**I quasi-duplicati sono più deboli.** SIM-01 dovrà riconoscere che due
contenuti sono quasi lo stesso testo usando Jaccard su token normalizzati,
n-grammi, SimHash o MinHash. Nessuno di questi riconosce due frasi che dicono la
stessa cosa con parole diverse. Un embedding lo farebbe. Si accetta il limite, e
si dichiara nell'interfaccia che la somiglianza è **testuale**: «82% di
somiglianza testuale» è una frase vera, «stesso significato» non lo sarebbe.

**Non c'è riassunto automatico.** Una sessione con molte migliaia di contenuti
resta lunga da leggere. Il rimedio sono gli strumenti deterministici — filtri,
livelli, termini emergenti, grappoli, coda di lavoro — non un paragrafo scritto
da una macchina che nessuno può verificare.

**Una formulazione nuova non si riconosce da sola.** Quando cambia il lessico di
un ambiente, il dizionario va aggiornato da una persona. Il prodotto aiuta a
scoprirlo (TREND-01, FEEDBACK-01, LAB-01) ma non lo fa da solo, e **non deve**:
un dizionario che si modifica da sé è un dizionario di cui nessuno risponde.

---

## Le guardie, e che cosa ciascuna dimostra davvero

### La guardia forte: non esiste un modo di parlare con un servizio remoto

Al 2026-08-25 il grafo delle dipendenze risolte del workspace, misurato su
`Cargo.lock`, **non contiene alcun client HTTP, alcuna libreria TLS in Rust,
alcun runtime asincrono e alcun crate di socket**: né `reqwest`, né `hyper`, né
`ureq`, né `curl`, né `rustls`, né `native-tls`, né `tokio`.

Questo non è un elenco di cose vietate: è un'**assenza di capacità**. Nessun
percorso di codice Rust del prodotto può spedire un byte a un servizio di
inferenza, perché nessun percorso di codice Rust del prodotto può spedire un
byte a nessuno. Tutto ciò che esce dalla postazione esce attraverso lo stack di
rete nativo di TDLib, verso Telegram.

**Una prova lo fissa** leggendo `Cargo.lock` e fallendo se uno di quei crate
compare.

### La guardia debole, e si dichiara debole: l'elenco dei nomi

`deny.toml` rifiuta per nome i crate di inferenza più probabili. Serve a fermare
l'aggiunta distratta, ed è tutto ciò che serve **finché** la guardia forte
regge.

Un elenco è una guardia che si dimentica: la lezione è già scritta in
`PROJECT_STATUS.md` e l'ha insegnata UX-02, dove un elenco chiuso lasciava
passare esattamente il difetto che esisteva per fermare. Non si conta su questo
elenco per la sicurezza della decisione. Si conta sull'assenza di capacità.

### Il giorno in cui la guardia forte cade, e va scritto adesso

Due milestone pianificate **introdurranno** un client HTTPS: **UPDATE-02**, il
trasporto degli aggiornamenti, e **HUB-TLS-01**, il trasporto dell'Hub. Quel
giorno la frase «il prodotto non può parlare con nessuno» smette di essere vera,
e la prova che la fissa diventerà rossa.

**Non va calmata: va sostituita**, con la proprietà più debole che resterà vera
e che è ancora verificabile — le sole destinazioni raggiungibili sono l'origine
del manifesto degli aggiornamenti e l'Hub configurato, entrambe da
configurazione e nessuna da contenuto monitorato.

Si scrive qui perché chi incontrerà quella prova rossa fra molte settimane sappia
che era previsto, che cosa deve metterci al posto, e che cancellarla e basta
sarebbe la fine silenziosa di questo ADR.

### È successo il 2026-09-12, con UPDATE-02 — e la prova NON è diventata rossa

**La previsione qui sopra era giusta nella sostanza e sbagliata nel segnale.**
UPDATE-02 ha aperto la porta verso la rete, e la frase «il prodotto non può
parlare con nessuno» ha smesso di essere vera. Ma la porta è **WinHTTP**, la
rete del sistema operativo (ADR-0067): **nessuna dipendenza nuova è arrivata nel
lockfile**, e la prova che legge il lockfile **è rimasta verde**.

Sarebbe rimasta verde per sempre, raccontando ogni giorno una cosa non più vera.
**Una guardia che resta verde mentre la sua affermazione diventa falsa è peggio
di una rossa**: una rossa costringe qualcuno a guardarla; una verde non dà a
nessuno un motivo per aprirla.

La sostituzione è stata fatta **di proposito**, senza aspettare un fallimento.
Al posto di «il prodotto non può parlare con nessuno» ci sono **tre** proprietà,
tutte più deboli e tutte verificate:

1. **Nessuna seconda pila di rete in Rust.** Il lockfile continua a non contenere
   client HTTP, pile TLS o runtime asincroni: una pila TLS in Rust porterebbe un
   **secondo insieme di radici di fiducia**, che nessun amministratore
   dell'ufficio governa.
2. **Una sola porta.** Un solo modulo dell'intero prodotto nomina WinHTTP, ed è
   il modulo `unsafe` autorizzato di `lisi-platform`. Un secondo punto da cui
   uscire sarebbe un punto **senza le regole del primo**.
3. **La destinazione viene dalla configurazione.** Chi apre la porta le passa
   l'origine conservata in archivio, e non conosce i tipi del contenuto
   monitorato: un messaggio, un profilo, un allegato o un fascicolo importato non
   possono diventare l'indirizzo che il prodotto contatta.

La terza è la più debole e la più importante: è ciò che resta della frase
«nessun contenuto monitorato viene inviato a un sistema di inferenza» quando la
capacità di inviare esiste.

**HUB-TLS-01 passerà di qui.** Quando l'Hub avrà il proprio trasporto, la seconda
proprietà avrà due porte e la terza due destinazioni. **Si aggiunge la
destinazione: non si toglie la prova.**

---

## Rischio residuo dichiarato

- **TDLib è codice nativo con la propria rete.** Le guardie riguardano il codice
  Rust del prodotto. Che cosa fa la libreria di Telegram è coperto da ADR-0008 e
  dalla sua provenienza verificata, non da qui.
- **Una dipendenza futura può portarsi dietro un client HTTP in modo
  transitivo.** Si scopre nella revisione di `Cargo.toml`, in `cargo deny` e
  nella distinta dei componenti: la stessa procedura che vale per ogni
  dipendenza nuova (§69 del mandato, `NOTICE.md`, SBOM).
- **Un elenco di nomi non copre ciò che non nomina.** Dichiarato sopra.
- **Questo ADR non impedisce a nessuno di revocarlo.** Impedisce che venga
  revocato **per distrazione**: perché cada servono un ADR nuovo, una prova
  cancellata con cognizione e una riga in `DECISION_LOG.md`.

---

## Che cosa questo ADR **non** vieta

Per non lasciare che il vincolo si allarghi da solo a cose che non sono
intelligenza artificiale:

- **statistica**, comprese medie, mediane, deviazioni robuste e soglie
  documentate (SPIKE-01);
- **algoritmi di somiglianza deterministici** su testo (SIM-01);
- **tassonomie ufficiali versionate**, come ATT&CK, CVE e KEV, usate come dati e
  non come modelli (ATTACK-01, SNAP-*);
- **espressioni regolari, normalizzazione Unicode, tokenizzazione** e ogni altra
  elaborazione linguistica **deterministica e leggibile**;
- **strumenti assistiti nello sviluppo del software.** Questo ADR riguarda il
  prodotto consegnato, non il modo in cui viene scritto. Il vincolo che vale
  sullo sviluppo è un altro, e sta in `CLAUDE.md`: non dichiarare il falso su
  come il codice è stato prodotto.
