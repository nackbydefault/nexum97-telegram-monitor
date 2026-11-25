# Governo del progetto / Governance

Ideazione e progettazione: Giuseppe LISI

## Chi decide

NEXUM/97 è un progetto con un **titolare unico**, Giuseppe LISI (account GitHub
`nackbydefault`), che ne ha ideato e progettato il prodotto. Il titolare decide che cosa entra
nel progetto, quando esce una versione e come cambiano queste regole. Se un giorno ci saranno
altri manutentori, questa pagina dirà chi sono e che cosa possono decidere.

## Come si decide

- Le decisioni che cambiano il prodotto si scrivono in una **decisione d'architettura** (ADR),
  prima del codice. Quelle pubblicate sono in [`docs/adr/`](docs/adr/).
- Una proposta si discute in una issue. Il titolare risponde accettandola, chiedendo modifiche o
  spiegando perché non entra.
- Le regole di disegno elencate in [CONTRIBUTING.md](CONTRIBUTING.md) non si cambiano con una
  richiesta di modifica: si cambiano soltanto con una decisione del titolare, scritta.

## Come cambia il codice

- `main` è protetto: niente push diretti, niente riscritture della storia, niente cancellazioni.
  Ogni modifica entra con una richiesta di modifica e lo squash.
- Lo sviluppo del titolare avviene in un archivio privato. Il codice arriva qui con
  un'esportazione da un elenco di file ammessi, a una milestone chiusa, in una richiesta di
  modifica. La storia dell'archivio privato non si importa.
- I controlli automatici (compilazione, prove, licenze, avvisi di sicurezza, CodeQL) girano su
  ogni richiesta di modifica. Un controllo rosso si spiega: un avviso noto e senza soluzione a
  monte resta rosso e documentato, non si nasconde.

## Versioni

Questa repository pubblica il codice sorgente. Non pubblica eseguibili né installer.

## Sicurezza

Le vulnerabilità si segnalano in privato ([SECURITY.md](SECURITY.md)). Il titolare risponde,
corregge nell'archivio e porta qui la correzione con la prossima esportazione, o prima se serve.

## Attribuzione

La formula **«Ideazione e progettazione: Giuseppe LISI»** è unica e non si cambia. I contributi
restano riconosciuti nella storia dei commit e, per i componenti di terze parti, nel file
[NOTICE](NOTICE).

---

*English.* NEXUM/97 has a single owner, Giuseppe LISI (GitHub `nackbydefault`), who decides what
goes in, when versions are cut and how these rules change. Product decisions are written as
architecture decision records before code. `main` is protected: changes land only through
squash-merged pull requests; the owner's development happens in a private archive and reaches
this repository through an allow-list export at closed milestones, without importing private
history. Automated checks run on every pull request; a known advisory without an upstream fix
stays red and documented. No binaries or installers are published here. Vulnerabilities are
reported privately. The attribution line «Ideazione e progettazione: Giuseppe LISI» is unique and
does not change.
