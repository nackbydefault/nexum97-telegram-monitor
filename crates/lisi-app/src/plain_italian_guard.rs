//! Il linguaggio che l'operatore legge (PR-01, ADR-0117).
//!
//! # Che cosa questa guardia verifica
//!
//! Le sette regole misurabili di ADR-0117 su **ogni** testo della superficie:
//!
//! - **L1** — ogni parola è nel lessico comune (`docs/ux/LESSICO_COMUNE.txt`)
//!   oppure è un concetto del glossario;
//! - **L2** — un termine tecnico del glossario compare **solo** nei dettagli
//!   tecnici;
//! - **L3** — un sinonimo vietato dal glossario non compare in superficie;
//! - **L4** — nessuna frase supera
//!   [`MAX_SENTENCE_WORDS`](lisi_core::glossary::MAX_SENTENCE_WORDS) parole;
//! - **L5** — nessun `**`: né Slint né i documenti interpretano il grassetto di
//!   Markdown, e lo schermo disegnava gli asterischi;
//! - **L6** — ogni avvertenza di sicurezza è registrata con il testo e il
//!   dettaglio della versione corrente, e ogni messaggio registrato si vede;
//! - **L7** — la guardia non passa a vuoto.
//!
//! # Che cosa questa guardia NON verifica
//!
//! Che una frase breve sia chiara, che un errore dica che cosa fare, che il
//! registro sia rispettoso. **Queste le verifica una persona**: è la voce di
//! coda aperta da PR-01.

#[cfg(test)]
pub(crate) mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use lisi_core::glossary::{
        EntryKind, GLOSSARY, MAX_SENTENCE_WORDS, entry_for_form, long_sentences, surface_words,
    };
    use lisi_core::security_messages::{SECURITY_MESSAGES, by_code};

    use crate::surface_text::{Mostrata, radice, sorgenti, stringhe_rust, testo_slint};

    /// Quante asserzioni sul testo dell'interfaccia il prodotto ha, oggi.
    ///
    /// # Che cosa conta, e come
    ///
    /// Le occorrenze di `UI.contains("…")` con un argomento letterale nei
    /// moduli di `crates/lisi-app/src`: moduli Rust che incorporano il file
    /// dell'interfaccia e verificano che una stringa ci sia. Al 2026-10-12
    /// sono **centotto**, in **ventiquattro** moduli: cinquantotto sulla forma
    /// del codice (`reset-panel := Rectangle {`), cinquanta su frasi italiane.
    ///
    /// # Perché c'è un tetto, e non un divieto
    ///
    /// Perché non sono slop: senza un banco grafico, leggere il sorgente
    /// dell'interfaccia è l'unica guardia disponibile, ed è stata scelta con
    /// cognizione. Ma il prezzo è misurato (FINAL-PRODUCT-REVIEW-01, FPR-11):
    /// ogni frase che si cambia fa diventare rossa una prova in un altro
    /// modulo — questa milestone ne ha appena fatte diventare rosse diverse
    /// rinominando quattro schermate — e una stringa **presente** non dice
    /// che l'elemento sia visibile, raggiungibile o sopra un altro.
    ///
    /// La decisione (DEC-388): **restano quelle che ci sono; non se ne
    /// aggiungono altre sul testo ordinario.** Dove una stringa è
    /// un'invariante — l'attribuzione, le avvertenze di sicurezza, i comandi
    /// distruttivi, le etichette che un documento cita — la guardia testuale
    /// resta la cosa giusta. Dove è testo ordinario, una guardia nuova vale
    /// meno di una prova che apre la finestra.
    ///
    /// Questo numero è il modo in cui la decisione si fa controllare: se
    /// cresce, cresce insieme a una riga nel registro delle decisioni che dica
    /// perché.
    ///
    /// 109 da OPERATOR-E2E-REMEDIATION-01 (DEC-396): la guardia di «IN CORSO»
    /// (F-04) lega uno stato mostrato alla condizione che lo rende vero; non è
    /// testo ordinario.
    ///
    /// 112 da NEXUM97-MINOR-FIX-01 (DEC-411): tre asserzioni, e nessuna su una
    /// frase — la condizione del Blocco senza account (CA02-07), il comando che
    /// esporta un dizionario (GAP-19) e la condizione del singolare dei
    /// dizionari (E2E01-15). Le frasi ordinarie di quella milestone non hanno
    /// guardia.
    const ASSERZIONI_SULL_INTERFACCIA: usize = 112;

    /// Il lessico comune: le parole che la superficie può usare.
    static LESSICO: std::sync::LazyLock<String> =
        std::sync::LazyLock::new(|| documento("docs/ux/LESSICO_COMUNE.txt"));

    /// Il lessico si legge quando la prova corre (ADR-0182, decisione 7).
    fn documento(relativo: &str) -> String {
        let percorso = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join(relativo);
        std::fs::read_to_string(&percorso)
            .unwrap_or_else(|errore| panic!("la guardia legge «{relativo}»: {errore}"))
    }

    /// I **nomi ufficiali** che la superficie riporta esattamente, con la
    /// ragione. Dentro un testo non si contano come parole: sono ciò che
    /// l'operatore deve ritrovare, identico, altrove.
    ///
    /// Rinominarli in parole comuni renderebbe il testo più semplice e il
    /// compito impossibile: «API ID» è il nome che Telegram stampa sulla pagina
    /// da cui l'amministratore lo copia.
    const NOMI_UFFICIALI: &[(&str, &str)] = &[
        (
            "CVSS",
            "il nome del sistema di punteggio delle vulnerabilità, come lo scrive NVD (ADR-0184)",
        ),
        (
            "Primary",
            "il valore del campo di NVD che distingue il punteggio primario: si confronta, non si mostra",
        ),
        (
            "API ID",
            "il nome del campo sulla pagina di Telegram da cui si copia",
        ),
        (
            "API hash",
            "il nome del campo sulla pagina di Telegram da cui si copia",
        ),
        (
            "https://",
            "l'inizio di un indirizzo web, come lo si scrive",
        ),
        ("http://", "l'inizio di un indirizzo web, come lo si scrive"),
        (
            "Mostra banner di notifica",
            "il nome dell'impostazione di Windows da riattivare",
        ),
        (
            "Setup.exe",
            "il nome del file d'installazione da rieseguire",
        ),
    ];

    /// Il testo senza i nomi ufficiali, perché la guardia conti il resto.
    fn senza_nomi_ufficiali(testo: &str) -> String {
        NOMI_UFFICIALI
            .iter()
            .fold(testo.to_owned(), |resto, (nome, _)| {
                resto.replace(nome, " ")
            })
    }

    /// I moduli che scrivono il **corpo di un documento prodotto**, con la
    /// ragione.
    ///
    /// # Perché il corpo dei documenti è fuori
    ///
    /// Il piano mette in PR-01 i **titoli** dei documenti, non il loro corpo: il
    /// corpo è un'altra superficie, che governa il gate documentale e, per il
    /// pacchetto, PR-11. Anche dentro questi moduli, però, le funzioni che
    /// parlano **allo schermo** restano sorvegliate: vedere
    /// [`CONTESTI_SEMPRE_MOSTRATI`].
    ///
    /// **Un modulo elencato che non esiste più fa diventare rossa la guardia**:
    /// un'esclusione che non esclude niente è un'esclusione che nessuno rilegge.
    const MODULI_DEL_DOCUMENTO: &[(&str, &str)] = &[
        (
            "lisi-services/src/report_annex.rs",
            "il corpo dell'allegato tecnico",
        ),
        (
            "lisi-services/src/report_ledger.rs",
            "il corpo del registro analitico",
        ),
        (
            "lisi-services/src/report_narrative.rs",
            "il corpo della relazione",
        ),
        (
            "lisi-services/src/report_txt.rs",
            "il registro in testo semplice",
        ),
        ("lisi-services/src/report_pdf.rs", "le pagine PDF"),
        ("lisi-services/src/report_docx.rs", "il file Word"),
        ("lisi-services/src/report_xlsx.rs", "il foglio Excel"),
        ("lisi-services/src/pdf_text.rs", "la codifica del testo PDF"),
        (
            "lisi-services/src/pdf_signature.rs",
            "la struttura della copia PDF firmata; i rifiuti passano da operator_message",
        ),
        (
            "lisi-services/src/report_package.rs",
            "il manifesto del pacchetto sul disco",
        ),
        (
            "lisi-services/src/export.rs",
            "il rapporto in testo e il suo manifesto",
        ),
        (
            "lisi-services/src/stix_export.rs",
            "il pacchetto STIX, letto da altri programmi",
        ),
        (
            "lisi-core/src/model/stix.rs",
            "gli oggetti STIX, letti da altri programmi",
        ),
    ];

    /// I crate i cui testi arrivano all'operatore **solo** attraverso un
    /// `operator_message`, con la ragione. Il resto del loro testo non lo legge
    /// nessuno: si trattano come i moduli del documento.
    ///
    /// `lisi-storage` risponde con errori che `ServiceError::operator_message`
    /// sostituisce con una frase sua («errore della persistenza»): il testo di
    /// una riga danneggiata o di una voce assente resta nel registro tecnico.
    const CRATE_SENZA_SUPERFICIE_PROPRIA: &[(&str, &str)] = &[(
        "lisi-storage/",
        "gli errori dell'archivio arrivano allo schermo solo come frase del servizio",
    )];

    /// Le chiamate il cui testo non si mostra, oltre a quelle di
    /// `surface_text::MACRO_NON_MOSTRATE`.
    ///
    /// Il **dettaglio del registro delle operazioni**: nessuna schermata lo
    /// mostra, e dice che cosa è stato fatto nei termini di chi l'ha fatto.
    const CHIAMATE_NON_MOSTRATE: &[&str] = &["AuditDetail::try_new("];

    /// Le funzioni che, anche dentro un modulo del documento, parlano allo
    /// schermo.
    const CONTESTI_SEMPRE_MOSTRATI: &[&str] =
        &["operator_message", "operator_label", "label", "title"];

    /// I moduli il cui testo **non è per una persona**, con la ragione.
    ///
    /// Stessa regola: un modulo elencato che non esiste più è un errore.
    const MODULI_DI_MACCHINA: &[(&str, &str)] = &[
        // Il glossario e i messaggi di sicurezza si provano a parte, con le
        // stesse regole, campo per campo: la frase semplice come superficie, il
        // dettaglio come dettaglio. Letti come sorgente sarebbero un testo solo.
        (
            "lisi-core/src/glossary.rs",
            "provato campo per campo dalla guardia",
        ),
        (
            "lisi-core/src/security_messages.rs",
            "provato campo per campo dalla guardia",
        ),
        // Le traduzioni delle avvertenze sono in un'altra lingua: le prova la
        // guardia per lingua (I18N-01, ADR-0197), con le loro impronte.
        (
            "lisi-core/src/security_translations.rs",
            "testo in un'altra lingua, provato dalla guardia per lingua",
        ),
        (
            "lisi-telegram/src/tdlib/live_probe.rs",
            "la sonda per chi sviluppa, usata soltanto dal binario tdlib_live_poc",
        ),
    ];

    /// Le funzioni che scrivono **il corpo di un documento su disco**, fuori
    /// dai moduli del documento: modulo, funzione, perché. Stessa regola dei
    /// moduli del documento (ADR-0117, §1).
    const CONTESTI_DEL_DOCUMENTO: &[(&str, &str, &str)] = &[
        (
            "lisi-services/src/backup.rs",
            "note_text",
            "il foglio accanto alla copia: una procedura con i nomi esatti dei file",
        ),
        (
            "lisi-services/src/reset.rs",
            "archive_audit",
            "il file del registro archiviato prima di un azzeramento",
        ),
        (
            "lisi-services/src/reset.rs",
            "continuity_record",
            "la riga di continuità scritta nel registro delle operazioni e nel marcatore \
             dell'azzeramento: un atto registrato, che non si riscrive",
        ),
        (
            "lisi-services/src/diagnostics.rs",
            "render_package",
            "il pacchetto di diagnostica, scritto su disco per chi assiste",
        ),
        (
            "lisi-core/src/model/report.rs",
            "file_stem",
            "il nome dei file del pacchetto sul disco, che le verifiche ritrovano",
        ),
        (
            "lisi-services/src/evidence_package.rs",
            "contents_text",
            "i contenuti del pacchetto di evidenze, scritti su disco per chi li riceve",
        ),
        (
            "lisi-services/src/evidence_package.rs",
            "contents_table",
            "la tabella del pacchetto di evidenze, letta da un foglio di calcolo",
        ),
        (
            "lisi-services/src/evidence_package.rs",
            "documents_text",
            "l'elenco dei rapporti riferiti, con nome e impronta come li scrive il registro",
        ),
        (
            "lisi-services/src/evidence_package.rs",
            "manifest_text",
            "il manifest del pacchetto di evidenze: nomi e impronte che la verifica confronta",
        ),
        (
            "lisi-services/src/report_overview.rs",
            "manifest_text",
            "l'elenco delle impronte del rapporto complessivo: nomi e impronte che la verifica confronta",
        ),
        (
            "lisi-services/src/evidence_package.rs",
            "INTEGRITY_NOT_SIGNATURE",
            "la frase sul manifest, dentro il documento di lettura e il manifest su disco",
        ),
    ];

    /// I singoli testi che si riportano **com'è**, con la ragione: modulo,
    /// funzione o costante, perché.
    ///
    /// Stessa regola: se il modulo non esiste più, o non contiene più quel
    /// nome, l'esclusione è rossa.
    const CONTESTI_ESCLUSI: &[(&str, &str, &str)] = &[
        (
            "lisi-core/src/model/attack.rs",
            "MITRE_ATTRIBUTION",
            "la formula d'attribuzione che le condizioni d'uso di MITRE chiedono testuale, in inglese",
        ),
        (
            "lisi-telegram/src/tdlib/capability.rs",
            "classify",
            "le frasi d'errore inglesi di TDLib, confrontate per testo con la risposta",
        ),
        (
            "lisi-telegram/src/tdlib/live.rs",
            "indicated_wait_seconds",
            "le due forme inglesi dell'errore di frequenza di TDLib, lette per testo (FR-008)",
        ),
        (
            "lisi-telegram/src/tdlib/live.rs",
            "attesa_di_frequenza",
            "il rifiuto locale nella forma inglese del protocollo, perché lo si riconosca come quello di Telegram (FR-008)",
        ),
        (
            "lisi-services/src/source_history.rs",
            "e_un_limite_di_frequenza",
            "le forme inglesi dell'errore di frequenza di TDLib, confrontate per testo (FR-009)",
        ),
        (
            "lisi-services/src/conversation.rs",
            "e_una_fonte_non_accessibile",
            "le forme inglesi dell'errore di TDLib per una conversazione non più accessibile, confrontate per testo (ADR-0151)",
        ),
        (
            "lisi-platform/src/time_sync.rs",
            "time_sync_state",
            "i nomi dei due valori del registro di Windows, letti per nome (ADR-0168)",
        ),
        (
            "lisi-services/src/telegram_runtime.rs",
            "classify_start_failure",
            "le frasi d'errore del connettore, confrontate per testo per classificare un avvio",
        ),
        (
            "lisi-services/src/telegram_runtime.rs",
            "classify_polling_failure",
            "le frasi d'errore del connettore, confrontate per testo per classificare un guasto",
        ),
        (
            "lisi-services/src/telegram_runtime.rs",
            "live_mode_unavailable",
            "la ragione interna di SessionUnavailable: lo schermo mostra la frase del servizio, \
             il registro tecnico conserva questa per chi sviluppa",
        ),
        (
            "lisi-services/src/kev_snapshot.rs",
            "ATTRIBUTION",
            "la citazione del catalogo di CISA con la sua licenza, testuale",
        ),
        (
            "lisi-core/src/model/kev.rs",
            "KNOWN",
            "il valore esatto che CISA scrive nel catalogo, confrontato con il dato",
        ),
        (
            "lisi-core/src/model/kev.rs",
            "UNKNOWN",
            "il valore esatto che CISA scrive nel catalogo, confrontato con il dato",
        ),
        (
            "lisi-core/src/model/cve.rs",
            "REJECTED",
            "il valore esatto che NVD scrive per una voce ritirata, confrontato con il dato",
        ),
        (
            "lisi-telegram/src/tdlib/ffi.rs",
            "send",
            "la ragione tecnica di un errore del connettore, che classify_start_failure \
             riconosce per testo e lo schermo sostituisce con una frase del servizio",
        ),
        (
            "lisi-telegram/src/tdlib/ffi.rs",
            "execute",
            "la ragione tecnica di un errore del connettore, che classify_start_failure \
             riconosce per testo e lo schermo sostituisce con una frase del servizio",
        ),
        (
            "lisi-telegram/src/prohibitions.rs",
            "production_part",
            "la guardia dei divieti che legge il proprio sorgente: cerca `mod tests`",
        ),
        (
            "lisi-services/src/identity_resolver.rs",
            "RESOLVER_TABLE",
            "i messaggi d'errore inglesi di TDLib e i nomi dei guasti della matrice di PR-09, \
             confrontati per testo con la risposta: la schermata mostra le frasi del servizio",
        ),
        (
            "lisi-telegram/src/mock.rs",
            "lookup",
            "la risposta inglese che il connettore simulato imita da TDLib per un dato non \
             fornito, confrontata per codice dalla tabella di PR-09",
        ),
        (
            "lisi-services/src/identity_resolver.rs",
            "matrix_name",
            "le intestazioni delle righe della matrice di PR-09, confrontate per testo con il \
             documento: la schermata non le mostra",
        ),
        (
            "lisi-services/src/identity_resolver.rs",
            "indicated_wait",
            "le forme inglesi con cui TDLib indica un'attesa, confrontate per testo",
        ),
        (
            "lisi-services/src/identity_resolver.rs",
            "LINK_DOMAINS",
            "i domini dei collegamenti di Telegram, confrontati per testo con l'ingresso",
        ),
        (
            "lisi-services/src/cve_snapshot.rs",
            "CVE_ATTRIBUTION",
            "l'attribuzione dei record CVE e il non-avallo di NVD, con i nomi dei titolari e \
             il titolo dei loro termini d'uso, come li chiede cve.lock.json",
        ),
        (
            "lisi-services/src/exercise.rs",
            "MESSAGES",
            "i testi dei messaggi sintetici dell'Esercitazione: sono contenuti monitorati \
             inventati, non parole del prodotto, e una prova ne verifica la forma sintetica",
        ),
        (
            "lisi-services/src/exercise.rs",
            "SOURCES",
            "i nomi delle fonti sintetiche dell'Esercitazione: dati, come il nome di una fonte \
             vera, non parole del prodotto",
        ),
    ];

    /// I testi che sono **dettaglio tecnico per natura**: modulo, funzione o
    /// costante, perché. La guardia li tratta come il testo dentro «Dettagli
    /// tecnici»: nessun termine tecnico è fuori posto, e nessuna frase è
    /// troppo lunga, perché nessuno li legge per sapere che cosa fare.
    const CONTESTI_TECNICI_PER_NATURA: &[(&str, &str, &str)] = &[
        (
            "lisi-core/src/attribution.rs",
            "THIRD_PARTY_COMPONENTS",
            "l'elenco dei componenti di terzi, con nomi e licenze come le licenze li chiedono",
        ),
        (
            "lisi-core/src/attribution.rs",
            "PRODUCT_LICENSE",
            "l'identificativo SPDX della licenza del prodotto",
        ),
        (
            "lisi-core/src/attribution.rs",
            "NOT_DISTRIBUTED",
            "i componenti usati per costruire il programma, nella pagina delle licenze",
        ),
        (
            "lisi-core/src/model/indicator.rs",
            "label",
            "il genere di un indicatore tecnico: il dato stesso è tecnico, e il suo nome \
             (IPv4, SHA-256) è quello con cui lo si cerca altrove",
        ),
    ];

    /// Le proprietà Slint il cui testo non si legge: è un nome di carattere.
    const PROPRIETA_SLINT_NON_TESTO: &[&str] = &["font-family"];

    /// Il file dei token grafici: i suoi soli testi sono nomi di caratteri
    /// («IBM Plex Mono», «Segoe UI»), che nessuno legge sullo schermo.
    const FILE_SLINT_SENZA_TESTO: &str = "tokens.slint";

    /// Le proprietà Slint il cui testo è **dettaglio tecnico per natura**.
    const PROPRIETA_SLINT_TECNICHE: &[&str] = &["product-license"];

    /// Le interrogazioni SQL cominciano così, e non sono testo.
    const SQL: &[&str] = &[
        "SELECT ",
        "INSERT ",
        "UPDATE ",
        "DELETE ",
        "CREATE ",
        "PRAGMA ",
        "WITH ",
        "ALTER ",
        "DROP ",
        "BEGIN",
        "COMMIT",
        "ROLLBACK",
        "SAVEPOINT ",
        "RELEASE ",
        "VACUUM",
    ];

    /// Le parole chiave SQL che, **maiuscole e in mezzo a un testo**, dicono
    /// che il testo è un pezzo d'interrogazione: `"… FROM contents WHERE …"`.
    const SQL_IN_MEZZO: &[&str] = &[
        " FROM ",
        " WHERE ",
        " JOIN ",
        " AND ",
        " OR ",
        " VALUES",
        " SET ",
        " INTO ",
        " ORDER BY",
        " GROUP BY",
        " LIMIT ",
        "EXISTS",
        " AS ",
        " ON ",
        " IS NULL",
        " NOT ",
    ];

    /// Un testo della superficie.
    #[derive(Debug, Clone)]
    pub(crate) struct Voce {
        /// File e riga, per il messaggio di errore.
        pub(crate) dove: String,
        /// Il testo.
        pub(crate) testo: String,
        /// Se è un dettaglio tecnico.
        pub(crate) dettaglio: bool,
    }

    /// Il percorso da `crates/` in giù, con le barre dritte.
    fn relativo(percorso: &std::path::Path) -> String {
        let testo = percorso.to_string_lossy().replace('\\', "/");
        testo
            .split_once("/crates/")
            .map_or(testo.clone(), |(_, resto)| resto.to_owned())
    }

    /// I moduli dichiarati `#[cfg(test)] mod nome;`: tutto il file è una
    /// prova, anche se non contiene un `mod tests` suo.
    fn moduli_di_prova(file: &[std::path::PathBuf]) -> BTreeSet<String> {
        let mut di_prova = BTreeSet::new();
        for percorso in file {
            let Ok(testo) = std::fs::read_to_string(percorso) else {
                continue;
            };
            let righe: Vec<&str> = testo.lines().collect();
            for coppia in righe.windows(2) {
                let [attributo, seguente] = coppia else {
                    continue;
                };
                if !attributo.trim_start().starts_with("#[cfg(test)]") {
                    continue;
                }
                let seguente = seguente.trim();
                let nome = seguente
                    .strip_prefix("pub(crate) mod ")
                    .or_else(|| seguente.strip_prefix("pub mod "))
                    .or_else(|| seguente.strip_prefix("mod "))
                    .and_then(|resto| resto.strip_suffix(';'));
                let Some(nome) = nome else {
                    continue;
                };
                let Some(cartella) = percorso.parent() else {
                    continue;
                };
                let radice_del_modulo = match percorso.file_stem().and_then(|s| s.to_str()) {
                    Some("lib" | "main" | "mod") => cartella.to_path_buf(),
                    Some(stem) => cartella.join(stem),
                    None => continue,
                };
                di_prova.insert(relativo(&radice_del_modulo.join(format!("{nome}.rs"))));
                di_prova.insert(relativo(&radice_del_modulo.join(nome).join("mod.rs")));
            }
        }
        di_prova
    }

    /// Se un testo Rust ha forma di testo per una persona (ADR-0117, §1).
    fn con_forma_di_testo(testo: &str) -> bool {
        let pulito = testo.trim();
        if !pulito.chars().any(char::is_alphabetic) {
            return false;
        }
        if SQL
            .iter()
            .any(|inizio| pulito.to_uppercase().starts_with(inizio))
            || SQL_IN_MEZZO.iter().any(|parola| pulito.contains(parola))
        {
            return false;
        }
        // XML o HTML: lo scheletro di una notifica di Windows, non una frase.
        if pulito.starts_with('<') {
            return false;
        }
        // Un identificatore con il trattino basso — `created_at`,
        // `acquisition_origin` — dice che il testo è un elenco di colonne o
        // un nome di campo. Nessuna frase italiana ne contiene uno.
        if pulito
            .split(|c: char| !c.is_alphanumeric() && c != '_')
            .any(|parola| parola.contains('_') && parola.chars().any(char::is_alphabetic))
        {
            return false;
        }
        // Un nome scritto a gobba di cammello — `authorizationStateWaitCode`,
        // `AuthenticationService` — e' un nome di tipo o di metodo, e una
        // coppia `chiave=valore` e' un parametro: nessuno dei due e' una frase.
        let parole: Vec<&str> = pulito
            .split(|c: char| !c.is_alphanumeric() && c != '=')
            .collect();
        let a_gobba = parole.iter().any(|parola| {
            parola
                .chars()
                .zip(parola.chars().skip(1))
                .any(|(prima, dopo)| prima.is_lowercase() && dopo.is_uppercase())
        });
        let chiave_valore = parole.iter().any(|parola| {
            parola
                .split_once('=')
                .is_some_and(|(chiave, valore)| !chiave.is_empty() && !valore.is_empty())
        });
        if a_gobba || chiave_valore {
            return false;
        }
        if pulito.contains(' ') {
            return true;
        }
        // Una parola sola è testo solo se comincia con una maiuscola ed è
        // fatta di lettere: «Attivo» sì, `acquisition_origin`, `tdjson.dll`,
        // `FLOOD_WAIT` e `application/json` no.
        pulito.chars().next().is_some_and(char::is_uppercase)
            && pulito.chars().all(|c| c.is_alphabetic() || c == '\'')
            && pulito.chars().skip(1).any(char::is_lowercase)
    }

    /// Tutta la superficie: Slint e Rust, con le esclusioni dichiarate.
    pub(crate) fn superficie() -> Vec<Voce> {
        let mut voci: Vec<Voce> = testo_slint()
            .into_iter()
            .filter(|(file, mostrata)| {
                *file != FILE_SLINT_SENZA_TESTO
                    && mostrata.contesto != "codice"
                    && !PROPRIETA_SLINT_NON_TESTO.contains(&mostrata.contesto.as_str())
                    // Una stringa senza proprieta' sta in una condizione o in
                    // una chiamata: e' testo solo se ne ha la forma.
                    && (!mostrata.contesto.is_empty() || con_forma_di_testo(&mostrata.testo))
            })
            .map(|(file, mostrata)| Voce {
                dove: format!("{file}:{}", mostrata.riga),
                dettaglio: mostrata.dettagli_tecnici
                    || PROPRIETA_SLINT_TECNICHE.contains(&mostrata.contesto.as_str()),
                testo: mostrata.testo,
            })
            .collect();

        let mut file = Vec::new();
        sorgenti(&radice().join("crates"), &mut file);
        file.sort();
        let di_prova = moduli_di_prova(&file);

        for percorso in &file {
            let nome = relativo(percorso);
            if nome.contains("/tests/") || nome.contains("/src/bin/") || nome.ends_with("build.rs")
            {
                continue;
            }
            if di_prova.contains(&nome) || MODULI_DI_MACCHINA.iter().any(|(m, _)| *m == nome) {
                continue;
            }
            let del_documento = MODULI_DEL_DOCUMENTO.iter().any(|(m, _)| *m == nome)
                || CRATE_SENZA_SUPERFICIE_PROPRIA
                    .iter()
                    .any(|(prefisso, _)| nome.starts_with(prefisso));
            let Ok(testo) = std::fs::read_to_string(percorso) else {
                continue;
            };
            // I dettagli del registro delle operazioni non li mostra nessuna schermata:
            // sono la traccia di chi ha fatto che cosa, e restano com'erano scritti.
            let prodotto = crate::surface_text::togli_chiamate(
                &crate::surface_text::prodotto_rust(&testo),
                |riga| {
                    CHIAMATE_NON_MOSTRATE
                        .iter()
                        .any(|forma| riga.contains(forma))
                },
            );
            for mostrata in stringhe_rust(&prodotto) {
                if del_documento && !CONTESTI_SEMPRE_MOSTRATI.contains(&mostrata.contesto.as_str())
                {
                    continue;
                }
                if CONTESTI_ESCLUSI
                    .iter()
                    .chain(CONTESTI_DEL_DOCUMENTO)
                    .any(|(modulo, contesto, _)| *modulo == nome && *contesto == mostrata.contesto)
                {
                    continue;
                }
                if !con_forma_di_testo(&mostrata.testo) {
                    continue;
                }
                let per_natura = CONTESTI_TECNICI_PER_NATURA
                    .iter()
                    .any(|(modulo, contesto, _)| *modulo == nome && *contesto == mostrata.contesto);
                let mut voce = voce_rust(&nome, mostrata);
                voce.dettaglio |= per_natura;
                voci.push(voce);
            }
        }
        voci
    }

    fn voce_rust(nome: &str, mostrata: Mostrata) -> Voce {
        let contesto = mostrata.contesto.to_lowercase();
        Voce {
            dove: format!("{nome}:{} ({})", mostrata.riga, mostrata.contesto),
            dettaglio: contesto.contains("technical_detail"),
            testo: mostrata.testo,
        }
    }

    /// Il lessico comune, come insieme.
    fn lessico() -> BTreeSet<&'static str> {
        LESSICO
            .lines()
            .map(str::trim)
            .filter(|riga| !riga.is_empty() && !riga.starts_with('#'))
            .collect()
    }

    /// Se il sinonimo compare nel testo come espressione intera.
    fn contiene_espressione(testo: &str, espressione: &str) -> bool {
        let parole_testo = surface_words(testo);
        let parole_espressione = surface_words(espressione);
        if parole_espressione.is_empty() {
            return false;
        }
        parole_testo
            .windows(parole_espressione.len())
            .any(|finestra| finestra == parole_espressione.as_slice())
    }

    /// Scrive l'elenco dei difetti in modo leggibile: al massimo cento, o tutti
    /// se `PLAIN_ITALIAN_TUTTO` è impostata — serve a chi li corregge.
    fn elenco(difetti: &[String]) -> String {
        let limite = if std::env::var_os("PLAIN_ITALIAN_TUTTO").is_some() {
            usize::MAX
        } else {
            100
        };
        let mut testo = difetti
            .iter()
            .take(limite)
            .cloned()
            .collect::<Vec<_>>()
            .join("\n");
        if difetti.len() > limite {
            testo.push_str(&format!("\n… e altri {}", difetti.len() - limite));
        }
        testo
    }

    // ------------------------------------------------------------------ L7

    /// **La guardia legge davvero la superficie** (L7).
    #[test]
    fn la_guardia_legge_davvero_la_superficie() {
        let voci = superficie();
        let slint = voci.iter().filter(|v| v.dove.contains(".slint:")).count();
        let rust = voci.len() - slint;
        assert!(
            slint > 1_000,
            "solo {slint} testi dall'interfaccia: l'estrazione non funziona"
        );
        assert!(
            rust > 1_000,
            "solo {rust} testi dal Rust: l'estrazione non funziona"
        );
        assert!(
            lessico().len() > 1_500,
            "il lessico ha {} parole: un lessico quasi vuoto non ammette nulla, e una guardia \
             che non ammette nulla viene spenta",
            lessico().len()
        );
        assert!(
            GLOSSARY.len() >= 30,
            "il glossario ha solo {} voci",
            GLOSSARY.len()
        );
        assert!(
            SECURITY_MESSAGES.len() >= 10,
            "registrati solo {} messaggi di sicurezza",
            SECURITY_MESSAGES.len()
        );
    }

    /// **Un'esclusione dichiarata esclude qualcosa che esiste.**
    #[test]
    fn ogni_modulo_escluso_esiste() {
        let crates = radice().join("crates");
        for (modulo, ragione) in MODULI_DEL_DOCUMENTO.iter().chain(MODULI_DI_MACCHINA) {
            assert!(
                crates.join(modulo).is_file(),
                "il modulo escluso «{modulo}» ({ragione}) non esiste più: l'esclusione va tolta"
            );
        }
        for (modulo, contesto, ragione) in CONTESTI_ESCLUSI
            .iter()
            .chain(CONTESTI_TECNICI_PER_NATURA)
            .chain(CONTESTI_DEL_DOCUMENTO)
        {
            let testo = std::fs::read_to_string(crates.join(modulo)).unwrap_or_default();
            assert!(
                testo.contains(contesto),
                "il testo escluso «{contesto}» di «{modulo}» ({ragione}) non esiste più: \
                 l'esclusione va tolta"
            );
        }
    }

    /// **Il lessico è un elenco ordinato di parole, e non ammette un termine
    /// tecnico.**
    ///
    /// Un termine tecnico scritto nel lessico sarebbe insieme ammesso e
    /// vietato: la guardia darebbe ragione al glossario, ma chi legge il
    /// lessico crederebbe il contrario.
    #[test]
    fn il_lessico_e_ordinato_e_non_contiene_termini_tecnici() {
        let parole: Vec<&str> = LESSICO
            .lines()
            .map(str::trim)
            .filter(|riga| !riga.is_empty() && !riga.starts_with('#'))
            .collect();
        for coppia in parole.windows(2) {
            if let [prima, dopo] = coppia {
                assert!(
                    prima < dopo,
                    "il lessico non è ordinato o ha un doppione: «{prima}», «{dopo}»"
                );
            }
        }
        for parola in &parole {
            assert_eq!(
                surface_words(parola),
                vec![String::from(*parola)],
                "«{parola}» non è una parola come la conta la guardia"
            );
            if let Some(voce) = entry_for_form(parola) {
                assert!(
                    voce.kind != EntryKind::Technical,
                    "«{parola}» è nel lessico ed è il termine tecnico «{}» del glossario",
                    voce.term
                );
            }
        }
    }

    /// **La Guida mostra il glossario, con i dettagli tecnici.**
    #[test]
    fn la_guida_mostra_il_glossario() {
        let ui = crate::page_guard::UI;
        assert!(
            ui.contains("for voce in root.glossary-entries:"),
            "la Guida deve elencare le voci del glossario"
        );
        let Some(inizio) = ui.find("for voce in root.glossary-entries:") else {
            return;
        };
        let voce = ui.get(inizio..inizio + 3_000).unwrap_or_default();
        assert!(
            voce.contains("DettagliTecnici") && voce.contains("voce.detail"),
            "ogni voce della Guida deve portare il suo dettaglio tecnico"
        );
    }

    /// **Le asserzioni sul testo dell'interfaccia non crescono** (DEC-388).
    #[test]
    fn le_asserzioni_sul_testo_dell_interfaccia_non_crescono() {
        let mut file = Vec::new();
        sorgenti(&radice().join("crates/lisi-app/src"), &mut file);
        file.sort();

        let mut quante = 0_usize;
        let mut moduli = 0_usize;
        for percorso in &file {
            // Questo file nomina il modello che conta, e quindi contiene la
            // sequenza che cerca: contarlo vorrebbe dire contare il metro
            // insieme a ciò che misura.
            if percorso.ends_with("plain_italian_guard.rs") {
                continue;
            }
            let Ok(testo) = std::fs::read_to_string(percorso) else {
                continue;
            };
            let nel_modulo = testo.matches("UI.contains(\"").count();
            if nel_modulo > 0 {
                moduli += 1;
                quante += nel_modulo;
            }
        }

        assert!(
            quante > 0 && moduli > 0,
            "nessuna asserzione trovata: se il nome della costante del sorgente \
             incorporato è cambiato, questa guardia va aggiornata insieme"
        );
        assert!(
            quante <= ASSERZIONI_SULL_INTERFACCIA,
            "le asserzioni sul testo dell'interfaccia sono {quante} in {moduli} moduli, \
             contro le {ASSERZIONI_SULL_INTERFACCIA} dichiarate. Una guardia nuova su una \
             frase ordinaria lega quella frase a un modulo che non la mostra: se serve \
             davvero, si alza questo numero e si scrive perché nel registro delle decisioni \
             (DEC-388)."
        );
    }

    // ------------------------------------------------------------ L1, L2

    /// **Ogni parola della superficie è di uso comune, oppure è nel
    /// glossario** (L1). E un termine tecnico sta solo nei dettagli (L2).
    #[test]
    fn ogni_parola_e_comune_o_e_nel_glossario() {
        let ammesse = lessico();
        let mut sconosciute: BTreeMap<String, String> = BTreeMap::new();
        let mut tecniche_in_superficie = Vec::new();

        // Il glossario e il registro si provano campo per campo: la frase
        // semplice e il testo di un messaggio sono superficie, i dettagli no.
        let mut voci = superficie();
        voci.extend(GLOSSARY.iter().map(|voce| Voce {
            dove: format!("glossario «{}»", voce.term),
            testo: voce.plain.to_owned(),
            dettaglio: false,
        }));
        voci.extend(SECURITY_MESSAGES.iter().map(|messaggio| Voce {
            dove: String::from(messaggio.code),
            testo: messaggio.current.text.to_owned(),
            dettaglio: false,
        }));
        for voce in voci {
            for parola in surface_words(&senza_nomi_ufficiali(&voce.testo)) {
                match entry_for_form(&parola) {
                    Some(glossario) if glossario.kind == EntryKind::Technical => {
                        if !voce.dettaglio {
                            tecniche_in_superficie.push(format!(
                                "{}: «{parola}» è un termine tecnico ({}): in superficie si scrive \
                                 «{}», e il termine va dietro «Dettagli tecnici» — {}",
                                voce.dove, glossario.term, glossario.plain, voce.testo
                            ));
                        }
                    }
                    Some(_) => {}
                    None => {
                        if !voce.dettaglio && !ammesse.contains(parola.as_str()) {
                            sconosciute
                                .entry(parola)
                                .or_insert_with(|| voce.dove.clone());
                        }
                    }
                }
            }
        }

        let sconosciute: Vec<String> = sconosciute
            .into_iter()
            .map(|(parola, dove)| format!("«{parola}» — prima volta in {dove}"))
            .collect();
        assert!(
            sconosciute.is_empty() && tecniche_in_superficie.is_empty(),
            "{} parole della superficie non sono né nel lessico comune né nel glossario. Se è \
             una parola di uso comune, va aggiunta a docs/ux/LESSICO_COMUNE.txt; se è un termine \
             tecnico, va nel glossario e in superficie si usa la sua frase semplice:\n{}\n\n\
             {} termini tecnici in superficie:\n{}",
            sconosciute.len(),
            elenco(&sconosciute),
            tecniche_in_superficie.len(),
            elenco(&tecniche_in_superficie)
        );
    }

    // ---------------------------------------------------------------- L3

    /// **Una cosa ha un nome solo** (L3).
    #[test]
    fn un_sinonimo_vietato_non_compare() {
        let mut trovati = Vec::new();
        for voce in superficie().iter().filter(|v| !v.dettaglio) {
            for glossario in GLOSSARY {
                for sinonimo in glossario.forbidden_synonyms {
                    if contiene_espressione(&voce.testo, sinonimo) {
                        trovati.push(format!(
                            "{}: «{sinonimo}» — la stessa cosa si chiama «{}» — {}",
                            voce.dove, glossario.term, voce.testo
                        ));
                    }
                }
            }
        }
        assert!(
            trovati.is_empty(),
            "{} sinonimi vietati in superficie:\n{}",
            trovati.len(),
            elenco(&trovati)
        );
    }

    // ---------------------------------------------------------------- L4

    /// **Nessuna frase in superficie supera la soglia** (L4).
    #[test]
    fn nessuna_frase_e_troppo_lunga() {
        let mut lunghe = Vec::new();
        for voce in superficie().iter().filter(|v| !v.dettaglio) {
            for frase in long_sentences(&voce.testo) {
                lunghe.push(format!("{}: {frase}", voce.dove));
            }
        }
        for glossario in GLOSSARY {
            for frase in long_sentences(glossario.plain) {
                lunghe.push(format!("glossario «{}»: {frase}", glossario.term));
            }
        }
        for messaggio in SECURITY_MESSAGES {
            for frase in long_sentences(messaggio.current.text) {
                lunghe.push(format!("{}: {frase}", messaggio.code));
            }
        }
        assert!(
            lunghe.is_empty(),
            "{} frasi superano {MAX_SENTENCE_WORDS} parole. Una frase più lunga si spezza, una \
             idea per frase:\n{}",
            lunghe.len(),
            elenco(&lunghe)
        );
    }

    // ---------------------------------------------------------------- L5

    /// **Nessun grassetto di Markdown in superficie** (L5).
    ///
    /// Né Slint né i documenti lo interpretano: fino a PR-01 lo schermo
    /// disegnava gli asterischi, proprio attorno alle frasi che il testo voleva
    /// far leggere per prime.
    #[test]
    fn nessun_grassetto_markdown_in_superficie() {
        let trovati: Vec<String> = superficie()
            .into_iter()
            .filter(|voce| voce.testo.contains("**"))
            .map(|voce| format!("{}: {}", voce.dove, voce.testo))
            .collect();
        assert!(
            trovati.is_empty(),
            "{} testi mostrati contengono «**», che lo schermo disegna come asterischi:\n{}",
            trovati.len(),
            elenco(&trovati)
        );
    }

    /// **Nessun a capo seguito da un rientro in superficie** (L5).
    ///
    /// # Il difetto che questa prova impedisce
    ///
    /// Dodici messaggi — fra cui «La fotografia MITRE ATT&CK non è stata
    /// importata» e «La protezione locale dei segreti non ha risposto» —
    /// contenevano la sequenza `\n` seguita da diciassette spazi. Era una
    /// continuazione di riga del sorgente (`\` a fine riga) trasformata, da
    /// una vecchia modifica automatica, in un a capo vero: lo schermo andava a
    /// capo a metà frase e rientrava. Nessuna prova se ne accorgeva, perché
    /// l'estrattore trasformava gli a capo in spazi. Da PR-01 li conserva.
    #[test]
    fn nessun_a_capo_rotto_in_superficie() {
        let trovati: Vec<String> = superficie()
            .into_iter()
            .filter(|voce| voce.testo.contains("\n   "))
            .map(|voce| format!("{}: {:?}", voce.dove, voce.testo))
            .collect();
        assert!(
            trovati.is_empty(),
            "{} testi mostrati vanno a capo a metà frase e rientrano: una continuazione di \
             riga del sorgente è diventata un a capo vero:\n{}",
            trovati.len(),
            elenco(&trovati)
        );
    }

    /// **Nessun buco di spazi in superficie** (DEC-459).
    ///
    /// Il gemello del difetto qui sopra: la stessa continuazione di riga,
    /// persa invece che trasformata. Il `\` a fine riga spariva insieme
    /// all'a capo, e il rientro della riga dopo restava dentro la frase —
    /// «Finché                  non c'è». Trovato il 2026-11-04 in sei frasi,
    /// due delle quali sullo schermo dei dizionari e della relazione.
    #[test]
    fn nessun_buco_di_spazi_in_superficie() {
        let trovati: Vec<String> = superficie()
            .into_iter()
            .filter(|voce| voce.testo.trim().contains("    "))
            .map(|voce| format!("{}: {:?}", voce.dove, voce.testo))
            .collect();
        assert!(
            trovati.is_empty(),
            "{} testi mostrati hanno un buco di spazi a metà frase: una continuazione di \
             riga del sorgente ha perso il suo `\\`:\n{}",
            trovati.len(),
            elenco(&trovati)
        );
    }

    // ---------------------------------------------------------------- L6

    /// **Ogni avvertenza di sicurezza sullo schermo è registrata, con il testo
    /// e il dettaglio della versione corrente** (L6).
    #[test]
    fn ogni_avvertenza_mostrata_e_quella_registrata() {
        // Le proprieta' di ogni istanza di AvvertenzaDiSicurezza, raccolte per
        // istanza: il codice, il testo e il dettaglio della STESSA avvertenza.
        let mut istanze: BTreeMap<(String, usize), BTreeMap<String, String>> = BTreeMap::new();
        for (file, mostrata) in testo_slint() {
            if mostrata.elemento != "AvvertenzaDiSicurezza" {
                continue;
            }
            istanze
                .entry((file.to_owned(), mostrata.istanza))
                .or_default()
                .insert(mostrata.contesto.clone(), mostrata.testo.clone());
        }
        assert!(
            istanze.len() >= 10,
            "trovate solo {} avvertenze di sicurezza nell'interfaccia",
            istanze.len()
        );

        let mut difetti = Vec::new();
        let mut mostrati = BTreeSet::new();
        for ((file, _), proprieta) in &istanze {
            let Some(codice) = proprieta.get("codice") else {
                difetti.push(format!("{file}: un'avvertenza senza codice: {proprieta:?}"));
                continue;
            };
            let Some(messaggio) = by_code(codice) else {
                difetti.push(format!("{file}: il codice «{codice}» non è registrato"));
                continue;
            };
            mostrati.insert(messaggio.code);
            // Un messaggio che arriva dal Rust: l'interfaccia lega testo e
            // dettaglio a proprieta' che il Rust riempie con la costante del
            // registro. Qui si verifica che la costante esista davvero nel
            // prodotto; che porti il testo corrente lo impone il suo tipo.
            if let Some(costante) = messaggio.rust_constant {
                if proprieta.contains_key("testo") || proprieta.contains_key("dettaglio") {
                    difetti.push(format!(
                        "{file}: {codice} arriva dal Rust ({costante}): l'interfaccia non ne \
                         scrive una copia, la riceve"
                    ));
                }
                let usata = crate::surface_text::sorgenti_del_prodotto()
                    .iter()
                    .any(|(_, sorgente)| sorgente.contains(&format!("const {costante}:")));
                if !usata {
                    difetti.push(format!(
                        "{codice}: la costante «{costante}» non è definita nel prodotto"
                    ));
                }
                continue;
            }
            if proprieta.get("testo").map(String::as_str) != Some(messaggio.current.text) {
                difetti.push(format!(
                    "{file}: {codice} — il testo mostrato non è quello della versione {}.\n  \
                     mostrato:   {:?}\n  registrato: {:?}",
                    messaggio.current.number,
                    proprieta.get("testo"),
                    messaggio.current.text
                ));
            }
            if proprieta.get("dettaglio").map(String::as_str)
                != Some(messaggio.current.technical_detail)
            {
                difetti.push(format!(
                    "{file}: {codice} — il dettaglio tecnico mostrato non è quello della \
                     versione {}.\n  mostrato:   {:?}\n  registrato: {:?}",
                    messaggio.current.number,
                    proprieta.get("dettaglio"),
                    messaggio.current.technical_detail
                ));
            }
        }
        for messaggio in SECURITY_MESSAGES {
            if !mostrati.contains(messaggio.code) {
                difetti.push(format!(
                    "{} è registrato e nessuna schermata lo mostra: protegge un rischio che \
                     nessuno sta guardando",
                    messaggio.code
                ));
            }
        }
        assert!(difetti.is_empty(), "{}", difetti.join("\n"));
    }

    /// **Un'avvertenza di sicurezza non si scrive fuori dal registro.**
    ///
    /// Le frasi con cui il prodotto avverte — «non è una prova», «non si
    /// annulla», «è il giudizio di una persona» — si riconoscono. Se compaiono
    /// in un testo fisso dell'interfaccia che non è un `AvvertenzaDiSicurezza`,
    /// qualcuno ha scritto un'avvertenza senza versione e senza elementi di
    /// significato: la prossima riformulazione potrà toglierle il senso senza
    /// che nessuna prova se ne accorga.
    #[test]
    fn un_avvertenza_fissa_sta_nel_registro() {
        const SEGNI: &[&str] = &[
            "non è una prova",
            "non diventa una prova",
            "non si annulla",
            "non è reversibile",
            "giudizio di una persona",
            "non è una firma",
        ];
        let mut trovati = Vec::new();
        for (file, mostrata) in testo_slint() {
            if mostrata.elemento == "AvvertenzaDiSicurezza" || mostrata.dettagli_tecnici {
                continue;
            }
            let minuscolo = mostrata.testo.to_lowercase();
            for segno in SEGNI {
                if minuscolo.contains(segno) {
                    trovati.push(format!(
                        "{file}:{} «{segno}» — {}",
                        mostrata.riga, mostrata.testo
                    ));
                }
            }
        }
        assert!(
            trovati.is_empty(),
            "avvertenze fisse fuori dal registro dei messaggi di sicurezza:\n{}",
            trovati.join("\n")
        );
    }

    // --------------------------------------------------- una parola per asse

    /// **«Dal vivo», «recuperato» e «non determinabile» sono il modo di
    /// acquisizione, e «osservato» non lo nomina più** (ADR-0117 §7, ADR-0123).
    #[test]
    fn il_modo_di_acquisizione_si_legge_dal_vivo_recuperato_o_non_determinabile() {
        use lisi_core::Timestamp;
        use lisi_core::model::AcquisitionMode;
        use lisi_services::acquisition_mode::{declared, short_label};

        let recuperato = AcquisitionMode::Recovered {
            at: Timestamp::from_millis(0),
            interval: None,
            operator: None,
        };
        let casi = [
            (AcquisitionMode::Live, "dal vivo"),
            (recuperato, "recuperat"),
            (AcquisitionMode::Undetermined, "non determinabile"),
        ];
        for (modo, attesa) in casi {
            for etichetta in [
                short_label(&modo).to_lowercase(),
                declared(&modo).to_lowercase(),
            ] {
                assert!(
                    !etichetta.contains("osservat"),
                    "il modo di acquisizione «{etichetta}» usa «osservato», che da PR-03 nomina \
                     la natura di un dato"
                );
                assert!(
                    etichetta.contains(attesa),
                    "«{etichetta}» deve dire «{attesa}»"
                );
            }
        }
    }

    // ------------------------------------------------------------ strumenti

    /// Il censimento: scrive nel file indicato da `CENSIMENTO` le parole della
    /// superficie che non sono né nel lessico né nel glossario, con quante
    /// volte compaiono. Serve a chi aggiorna il lessico; non è una prova.
    #[test]
    #[ignore = "strumento: si esegue a mano con CENSIMENTO=<file>"]
    fn censimento() {
        if let Ok(tutto) = std::env::var("CENSIMENTO_SLINT") {
            let righe: Vec<String> = testo_slint()
                .into_iter()
                .map(|(f, m)| format!("{f}:{}	{}	{}	{}", m.riga, m.contesto, m.elemento, m.testo))
                .collect();
            let _ = std::fs::write(
                tutto,
                righe.join(
                    "
",
                ),
            );
        }
        // I testi del Rust, con dove stanno: servono a chi prepara il catalogo
        // di un'altra lingua (I18N-01, ADR-0197).
        if let Ok(rust) = std::env::var("CENSIMENTO_RUST") {
            let righe: Vec<String> = superficie()
                .into_iter()
                .filter(|voce| !voce.dove.contains(".slint:"))
                .map(|voce| {
                    format!(
                        "{}\t{}\t{}",
                        voce.dove,
                        voce.dettaglio,
                        voce.testo.replace('\n', "\\n")
                    )
                })
                .collect();
            let _ = std::fs::write(rust, righe.join("\n"));
        }
        let ammesse = lessico();
        let mut conteggio: BTreeMap<String, (usize, String)> = BTreeMap::new();
        for voce in superficie() {
            if voce.dettaglio {
                continue;
            }
            for parola in surface_words(&voce.testo) {
                if entry_for_form(&parola).is_none() && !ammesse.contains(parola.as_str()) {
                    conteggio
                        .entry(parola)
                        .or_insert_with(|| (0, voce.dove.clone()))
                        .0 += 1;
                }
            }
        }
        let righe: Vec<String> = conteggio
            .into_iter()
            .map(|(parola, (volte, dove))| format!("{volte}\t{parola}\t{dove}"))
            .collect();
        if let Ok(uscita) = std::env::var("CENSIMENTO") {
            let _ = std::fs::write(uscita, righe.join("\n"));
        }
    }
}
