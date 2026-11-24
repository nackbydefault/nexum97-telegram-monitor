//! I messaggi di sicurezza, versionati (PR-01, ADR-0117).
//!
//! # Che cosa è un messaggio di sicurezza
//!
//! Un'avvertenza **fissa** dell'interfaccia che protegge da uno dei cinque
//! rischi di [`Risk`]. Non lo è una frase generata dai dati — «Non significa
//! che non abbia scritto», con i parametri dentro —: quella spiega un dato, e la
//! governano PR-02 e PR-03.
//!
//! # Il significato si conserva, la formulazione si corregge
//!
//! È la decisione 4 di DEC-356. Perché si possa **provare**, ogni versione di un
//! messaggio dichiara i propri **elementi di significato**: le affermazioni che
//! non possono mancare. Le prove qui sotto verificano che:
//!
//! - il testo corrente, con il suo dettaglio, contenga **tutti** gli elementi;
//! - ogni versione porti l'impronta di testo, dettaglio ed elementi — cambiare
//!   una parola senza aggiungere una versione non torna più;
//! - una versione che cambia gli elementi sia un **cambio di significato** con una
//!   decisione registrata, e una che non li cambia lo dichiari;
//! - la storia resti: le versioni precedenti si conservano, non si riscrivono.
//!
//! La guardia `plain_italian_guard.rs` di `lisi-app` verifica l'altra metà: che
//! ogni messaggio registrato **si veda**, con il testo e il dettaglio correnti.

use crate::digest::Sha256Digest;

/// Il rischio da cui un messaggio di sicurezza protegge.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Risk {
    /// Scambiare un'osservazione o un calcolo per un giudizio su una persona o
    /// per una prova.
    Interpretation,
    /// Esporre o perdere un segreto o un accesso.
    Secret,
    /// Compiere senza saperlo un'azione che non si annulla.
    Irreversible,
    /// Fidarsi di un file o di un aggiornamento non verificato.
    Trust,
    /// Scambiare il funzionamento dimostrativo per quello reale.
    Demonstration,
}

/// Che genere di cambiamento è una versione rispetto alla precedente.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Change {
    /// La prima versione registrata.
    First,
    /// Le parole cambiano, gli elementi di significato **no**. Non è una
    /// decisione, e lo dichiara.
    Rewording {
        /// Perché la formulazione precedente andava corretta.
        reason: &'static str,
    },
    /// Gli elementi di significato cambiano. Richiede una decisione registrata.
    MeaningChange {
        /// La decisione in `DECISION_LOG.md`, nella forma `DEC-000`.
        decision: &'static str,
        /// Perché il significato cambia.
        reason: &'static str,
    },
}

/// Una versione di un messaggio di sicurezza.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MessageVersion {
    /// Numero della versione, da 1.
    pub number: u32,
    /// La frase semplice, in superficie.
    pub text: &'static str,
    /// Il dettaglio tecnico, dietro «Dettagli tecnici».
    pub technical_detail: &'static str,
    /// Le affermazioni che non possono mancare. Ciascuna deve comparire, a
    /// meno di maiuscole e spazi, nel testo o nel dettaglio.
    pub meaning_elements: &'static [&'static str],
    /// L'impronta SHA-256 di testo, dettaglio ed elementi ([`fingerprint`]).
    pub fingerprint: &'static str,
    /// Che genere di cambiamento è.
    pub change: Change,
}

/// Un messaggio di sicurezza con la sua storia.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SecurityMessage {
    /// Identificativo stabile, nella forma `SIC-00`. Non si riusa.
    pub code: &'static str,
    /// Il rischio da cui protegge.
    pub risk: Risk,
    /// Le versioni precedenti, dalla prima. **Non si cancellano.**
    pub history: &'static [MessageVersion],
    /// La versione in vigore.
    pub current: MessageVersion,
    /// Se il testo arriva allo schermo **dal Rust**, il nome della costante
    /// che lo porta. La guardia verifica che esista e che l'interfaccia mostri
    /// il messaggio con il suo codice; se è `None`, l'interfaccia scrive testo
    /// e dettaglio per esteso, e la guardia li confronta con quelli registrati.
    pub rust_constant: Option<&'static str>,
}

/// L'impronta di una versione: testo, dettaglio ed elementi, separati da
/// caratteri che nessuno dei tre può contenere per errore.
#[must_use]
pub fn fingerprint(text: &str, technical_detail: &str, meaning_elements: &[&str]) -> Sha256Digest {
    let mut materiale = String::new();
    materiale.push_str(text);
    materiale.push('\u{1f}');
    materiale.push_str(technical_detail);
    materiale.push('\u{1f}');
    materiale.push_str(&meaning_elements.join("\u{1e}"));
    Sha256Digest::of_text(&materiale)
}

/// Il messaggio con il codice indicato.
#[must_use]
pub fn by_code(code: &str) -> Option<&'static SecurityMessage> {
    SECURITY_MESSAGES
        .iter()
        .find(|message| message.code == code)
}

/// Il testo reso confrontabile: minuscolo, spazi uniti.
fn normalised(text: &str) -> String {
    text.to_lowercase()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

/// Gli elementi di significato che il testo e il dettaglio **non** contengono.
#[must_use]
pub fn missing_elements(version: &MessageVersion) -> Vec<&'static str> {
    let insieme = normalised(&format!("{} {}", version.text, version.technical_detail));
    version
        .meaning_elements
        .iter()
        .copied()
        .filter(|elemento| !insieme.contains(&normalised(elemento)))
        .collect()
}

/// Un messaggio alla sua prima versione, scritto nell'interfaccia per esteso.
const fn first(
    code: &'static str,
    risk: Risk,
    text: &'static str,
    technical_detail: &'static str,
    meaning_elements: &'static [&'static str],
    fingerprint: &'static str,
) -> SecurityMessage {
    SecurityMessage {
        code,
        risk,
        history: &[],
        current: MessageVersion {
            number: 1,
            text,
            technical_detail,
            meaning_elements,
            fingerprint,
            change: Change::First,
        },
        rust_constant: None,
    }
}

/// **SIC-15** — la copia costruita senza il componente per Telegram.
///
/// Arriva allo schermo dal Rust: il servizio la usa anche come ragione del
/// comando «Telegram reale» spento. Per questo è una costante a sé, e
/// `lisi_services::TELEGRAM_RUNTIME_MISSING_REASON` è il suo testo corrente.
pub const RUNTIME_MISSING: SecurityMessage = SecurityMessage {
    rust_constant: Some("TELEGRAM_RUNTIME_MISSING_REASON"),
    ..first(
        "SIC-15",
        Risk::Demonstration,
        "Questa copia del programma non può collegarsi a Telegram. È stata costruita senza il \
         componente che lo consente. Si può usare solo in modalità dimostrativa. Segnalarlo a chi \
         ha fornito il pacchetto.",
        "Il programma è stato compilato senza la feature `tdlib-runtime`: la modalità reale non \
         esiste in questo file, e non si può attivare dalle impostazioni.",
        &[
            "non può collegarsi a Telegram",
            "costruita senza il componente",
            "modalità dimostrativa",
            "Segnalarlo a chi ha fornito il pacchetto",
        ],
        "b511bf38dd89328188acdc3fcf73378f72f8d94f28d4016ac343d4321e760fce",
    )
};

/// I messaggi di sicurezza dell'interfaccia.
///
/// Il testo di ciascuno è la versione **corrente**; le precedenti stanno in
/// `history`. Una modifica si fa aggiungendo una versione, mai riscrivendo
/// quella in vigore: le prove qui sotto lo impongono.
pub const SECURITY_MESSAGES: &[SecurityMessage] = &[
    first(
        "SIC-01",
        Risk::Interpretation,
        "Una fotografia conserva ciò che Telegram mostra adesso. Registra chi la prende, quando e \
         perché. Non diventa una prova acquisita: la prova resta il testo dell'archivio.",
        "La fotografia del contesto salva i messaggi attorno a un contenuto, con operatore, \
         istante e ragione. Non sostituisce il contenuto acquisito, che resta la fonte del dato.",
        &[
            "chi la prende, quando e perché",
            "Non diventa una prova acquisita",
            "la prova resta il testo dell'archivio",
        ],
        "d79fd3b4b45531adc39fef4be40dd8fdc43f1f3f5cb742235a2b64c764c82b39",
    ),
    first(
        "SIC-02",
        Risk::Irreversible,
        "Rimuovere un account cancella anche la sua sessione Telegram da questo computer. Per \
         rientrare serviranno di nuovo numero e codice. L'operazione non si annulla. Il registro \
         delle operazioni conserva la traccia della rimozione.",
        "Si cancellano la sessione TDLib e le credenziali protette con DPAPI. Il registro di audit \
         conserva l'operazione, senza alcun segreto.",
        &[
            "cancella anche la sua sessione Telegram",
            "serviranno di nuovo numero e codice",
            "non si annulla",
            "conserva la traccia della rimozione",
        ],
        "f2cff6343d3036d01a34adb2f72d800937144ca4ee429dd46a3db869d59a853b",
    ),
    first(
        "SIC-03",
        Risk::Irreversible,
        "«Azzera l'intero archivio» cancella TUTTO l'archivio di questa postazione. Non solo lo \
         storico: anche monitoraggi, account, profili, fonti, dizionari e impostazioni. Prima, il \
         registro delle operazioni viene salvato in un file a parte, con la sua impronta. La \
         cancellazione non avviene subito: avviene alla prossima apertura del programma. Fino ad \
         allora un avviso in alto la ricorda.",
        "All'avvio successivo il file del database SQLite viene rimosso, quando nessun servizio lo \
         tiene aperto. Il registro di audit viene prima esportato con la sua impronta SHA-256.",
        &[
            "cancella TUTTO l'archivio",
            "Non solo lo storico",
            "non avviene subito",
            "alla prossima apertura del programma",
        ],
        "d60ccfbbe27c05c26aea9b9d8cdafc190143371fee73e8559fe79866d47f10b8",
    ),
    first(
        "SIC-04",
        Risk::Demonstration,
        "Attenzione: la modalità Telegram reale apre una sessione vera sull'account d'ufficio. Usa \
         il canale ufficiale che Telegram offre ai programmi. Va usata solo con autorizzazione. La \
         modalità dimostrativa non contatta Telegram.",
        "La modalità reale usa TDLib e l'API ufficiale di Telegram con le credenziali \
         dell'ufficio. NEXUM/97 non è un client Telegram ufficiale.",
        &[
            "sessione vera sull'account d'ufficio",
            "solo con autorizzazione",
            "non contatta Telegram",
            "non è un client Telegram ufficiale",
        ],
        "39cfd92945611cddd4c85972e504e87a11e5f8bde87f97c6f31c310a0c3e3891",
    ),
    first(
        "SIC-05",
        Risk::Trust,
        "L'impronta dice che due configurazioni sono la stessa. Non è una firma: non prova chi \
         l'abbia composta.",
        "Impronta SHA-256 della configurazione scritta in forma canonica. Una firma richiederebbe \
         una chiave e un'identità: l'impronta non ha né l'una né l'altra.",
        &["Non è una firma", "non prova chi l'abbia composta"],
        "c92d525319f296ea72c93eee4bd7a1ecc4d73aab80cf24939a38efa61d7b79d0",
    ),
    first(
        "SIC-06",
        Risk::Trust,
        "Scaricare il file non lo verifica e non lo installa. «Verifica il file» controlla due \
         cose. La prima: che il file sia arrivato intero. La seconda: che sia firmato da qualcuno \
         che questa postazione riconosce. Solo la seconda dice di chi ci si sta fidando. Nemmeno \
         un file verificato si installa da solo: il programma non si sostituisce a sé stesso.",
        "La prima verifica confronta l'impronta SHA-256 con quella dichiarata dall'informazione \
         sull'aggiornamento: dimostra il trasporto, perché quell'informazione non è fidata. La \
         seconda è la firma Authenticode, verificata da Windows.",
        &[
            "non lo verifica e non lo installa",
            "arrivato intero",
            "di chi ci si sta fidando",
            "non si sostituisce a sé stesso",
        ],
        "fb59005050b551072ed5474e541fb77bccc77d497c48eec0dedb2524ed92e201",
    ),
    first(
        "SIC-07",
        Risk::Trust,
        "Ricalcola l'impronta di ogni rapporto esportato e la confronta con il suo elenco delle \
         impronte. Prova che il rapporto è ancora identico a quello prodotto. Non prova che \
         l'elenco delle impronte sia l'originale.",
        "Confronto byte per byte tramite SHA-256 con il manifest di integrità. Il manifest non è \
         firmato: chi può cambiare il rapporto può cambiare anche il manifest.",
        &[
            "ancora identico a quello prodotto",
            "Non prova che l'elenco delle impronte sia l'originale",
        ],
        "1a3bfe292c9df64686ef4d1bb3678db8f9462bfcbf68882d9174216e5dc03aa6",
    ),
    first(
        "SIC-08",
        Risk::Interpretation,
        "Questo elenco viene dai messaggi già acquisiti: chi compare come autore, quante volte, in \
         quali fonti. Non è una lista chiesta a Telegram. Non comprende chi non ha mai scritto.",
        "Aggregazione dei mittenti dei contenuti in archivio. A Telegram non viene chiesto \
         l'elenco dei membri di alcuna fonte.",
        &[
            "Non è una lista chiesta a Telegram",
            "Non comprende chi non ha mai scritto",
        ],
        "44eaf64391fce5245f1b69f1b1f54d137a96765e4f8abf903ae3789ca8451371",
    ),
    first(
        "SIC-09",
        Risk::Interpretation,
        "Un soggetto non è una persona dell'elenco qui sopra. Quell'elenco dice chi ha scritto \
         durante un monitoraggio. È un'osservazione, e non afferma niente su nessuno. Un soggetto \
         si apre a mano, scrivendo perché. Nessuno diventa un soggetto per aver scritto in un \
         gruppo.",
        "Il fascicolo di un soggetto richiede operatore, motivo e istante, e resta nel registro di \
         audit. L'elenco dei partecipanti è derivato dai mittenti dei contenuti.",
        &[
            "Un soggetto non è una persona dell'elenco qui sopra",
            "non afferma niente su nessuno",
            "si apre a mano, scrivendo perché",
            "Nessuno diventa un soggetto per aver scritto in un gruppo",
        ],
        "a9cba4745f1500d4feb548be19786cb7f5d6cc657303de10e24756d522ba853b",
    ),
    first(
        "SIC-10",
        Risk::Interpretation,
        "Questa figura mostra un elemento e ciò che lo tocca, un passo alla volta. Ogni \
         collegamento dice per quale fatto esiste e da dove viene. Non è una rete di relazioni. \
         Due elementi collegati attraverso un terzo non hanno per questo a che fare l'uno con \
         l'altro.",
        "Il grafo delle prove mostra i nodi a distanza uno. Ogni arco porta il fatto che lo \
         giustifica e la sua provenienza. Nessuna relazione transitiva viene dedotta.",
        &[
            "per quale fatto esiste",
            "Non è una rete di relazioni",
            "non hanno per questo a che fare l'uno con l'altro",
        ],
        "619c0637bb884f943995c22cfa9ea7ab5f1fd049fa187bce43f715b68bd4d012",
    ),
    first(
        "SIC-11",
        Risk::Interpretation,
        "Qui si vede che cosa cambierebbe pubblicando la bozza di un dizionario. Il calcolo usa i \
         contenuti già archiviati. Il confronto non scrive nulla e non pubblica nulla. La decisione \
         resta di una persona.",
        "L'analisi viene rieseguita, con la bozza, sui contenuti archiviati. Il risultato non \
         viene salvato e la bozza non viene pubblicata.",
        &[
            "non scrive nulla e non pubblica nulla",
            "La decisione resta di una persona",
        ],
        "01a88586f4129139809d27967fa9a6647998aad572b6406828ab5a915653539a",
    ),
    first(
        "SIC-12",
        Risk::Interpretation,
        "Queste voci dicono che cosa è stato controllato. Non dicono che tutto funzionerà. \
         Un'area «non misurata» non è un'area a posto. È un'area che il programma non ha potuto \
         controllare, e la riga dice perché.",
        "Ogni controllo di diagnostica ha tre esiti: superato, non superato, non misurato. «Non \
         misurato» vuol dire che la misura non è stata possibile.",
        &[
            "Non dicono che tutto funzionerà",
            "non è un'area a posto",
            "la riga dice perché",
        ],
        "24065f6a9597b7d2f1f8e7c53138717f088d16f5067dc9062c58d416646a3a66",
    ),
    first(
        "SIC-13",
        Risk::Interpretation,
        "Un gruppo non è un attacco, e nemmeno una notizia verificata. È un invito a guardare. La \
         conclusione la trae una persona. Il programma non ha un modo per registrarla al posto \
         suo.",
        "Un grappolo raccoglie contenuti che condividono indicatori, come domini, indirizzi o \
         codici CVE. La correlazione è deterministica e non assegna alcuno stato di minaccia.",
        &[
            "Un gruppo non è un attacco",
            "nemmeno una notizia verificata",
            "La conclusione la trae una persona",
        ],
        "0cf1d1a33d186fe32a8a1fff5edeb7682ef89b8382be430c7dc9c6e962e122c4",
    ),
    first(
        "SIC-14",
        Risk::Interpretation,
        "Il settore compare solo per le organizzazioni dichiarate in Impostazioni. Il programma \
         non lo deduce dal testo: attribuirne uno a occhio sarebbe inventarlo. Un contenuto senza \
         settore non nomina alcuna organizzazione dichiarata. Non vuol dire che non riguardi un \
         settore. Anche un settore che la norma non elenca conta.",
        "Il settore viene dall'elenco delle organizzazioni dichiarate, confrontato per nome. Il \
         testo non viene classificato.",
        &[
            "dichiarate in Impostazioni",
            "non lo deduce dal testo",
            "sarebbe inventarlo",
            "Non vuol dire che non riguardi un settore",
        ],
        "1a5b13c49d932d2242de95b2fa0a4f329f3b90ca1aa7d27d9d7415ee8a6b2b20",
    ),
    RUNTIME_MISSING,
    EVIDENCE_NOT_FORENSIC,
    EXERCISE_NOTICE,
    CVE_NOT_A_CONCLUSION,
];

/// **SIC-16** — il pacchetto di evidenze non è una prova forense (PR-11,
/// ADR-0127).
///
/// La stessa frase sta sulla schermata del workspace e nel documento di lettura
/// dentro il pacchetto: `lisi_services::evidence_package::NOT_FORENSIC` è il
/// suo testo corrente, e il servizio non ne scrive un'altra.
pub const EVIDENCE_NOT_FORENSIC: SecurityMessage = first(
    "SIC-16",
    Risk::Interpretation,
    "Questo pacchetto non è una prova forense e non è una perizia. Il programma non fa \
     acquisizione forense, e non ne ha la catena di custodia.",
    "Il pacchetto riunisce i contenuti scelti, la loro provenienza e un manifest di impronte. Il \
     manifest dice che i file sono quelli prodotti, non chi li ha prodotti.",
    &[
        "non è una prova forense",
        "non è una perizia",
        "catena di custodia",
    ],
    "a12fb2e1cc44678a310b9c30921d960545fdc80f42ceb8363ac14610c356861c",
);

/// **SIC-17** — l'Esercitazione: dati sintetici, nessun contatto con Telegram,
/// nessun valore di atto (PR-13, ADR-0129).
///
/// La stessa frase sta nella fascia in cima a ogni schermata e in apertura di
/// ogni documento prodotto in Esercitazione: `lisi_services::run_mode` la usa
/// per la marcatura, e l'interfaccia per la fascia.
pub const EXERCISE_NOTICE: SecurityMessage = SecurityMessage {
    rust_constant: Some("EXERCISE_MARK"),
    ..first(
        "SIC-17",
        Risk::Demonstration,
        "ESERCITAZIONE. Dati sintetici, nessun contatto con Telegram. Ciò che si produce qui non ha \
     valore di atto.",
        "L'archivio dell'esercitazione è separato da quello dell'ufficio. Ogni documento porta la \
     parola ESERCITAZIONE nel nome del file e in apertura.",
        &[
            "ESERCITAZIONE",
            "Dati sintetici",
            "nessun contatto con Telegram",
            "non ha valore di atto",
        ],
        "4d4041b7cdc5b929be31ff34be1d42cb15fb772d0818671227a2cfb0b622d004",
    )
};

/// **SIC-18** — un identificativo CVE nominato non è una conclusione, e la
/// presenza nel catalogo KEV non dice che sia accaduto qui (PR-14, ADR-0130).
///
/// Sta nella schermata «Riferimenti informatici», sopra le sezioni CVE e KEV.
pub const CVE_NOT_A_CONCLUSION: SecurityMessage = first(
    "SIC-18",
    Risk::Interpretation,
    "Un identificativo CVE nominato in un messaggio non è una conclusione di compromissione né di \
     pericolosità. Essere nel catalogo KEV dice che qualcuno ha sfruttato la vulnerabilità, non \
     che sia accaduto qui.",
    "Le risposte vengono dalle fotografie importate, con la loro data. Ciò che una fotografia non \
     contiene si dice assente, non inesistente.",
    &[
        "non è una conclusione di compromissione",
        "né di pericolosità",
        "non che sia accaduto qui",
        "fotografie importate",
    ],
    "f224a7a8550d50c66ab96c245834622f1938137a3e3dbc0c986c22d7b67df72f",
);

#[cfg(test)]
mod tests {
    use super::{Change, SECURITY_MESSAGES, fingerprint, missing_elements};

    /// Quanti messaggi devono essere registrati, almeno.
    ///
    /// Una prova che scorre un elenco vuoto passa sempre (ADR-0111). Il numero
    /// è quello del censimento di PR-01, meno un margine: scendere sotto vuol
    /// dire che qualcuno ha tolto messaggi, e deve dirlo cambiando questo
    /// numero.
    const MINIMO: usize = 15;

    #[test]
    fn i_messaggi_registrati_non_sono_un_elenco_vuoto() {
        assert!(
            SECURITY_MESSAGES.len() >= MINIMO,
            "registrati {} messaggi di sicurezza, ne servono almeno {MINIMO}: una prova \
             che scorre un elenco vuoto passa sempre",
            SECURITY_MESSAGES.len()
        );
    }

    #[test]
    fn ogni_codice_e_unico_e_ben_formato() {
        let mut visti = std::collections::BTreeSet::new();
        for messaggio in SECURITY_MESSAGES {
            assert!(
                messaggio.code.starts_with("SIC-")
                    && messaggio.code.len() == 6
                    && messaggio.code[4..].chars().all(|c| c.is_ascii_digit()),
                "il codice «{}» non ha la forma SIC-00",
                messaggio.code
            );
            assert!(
                visti.insert(messaggio.code),
                "il codice «{}» è usato due volte",
                messaggio.code
            );
        }
    }

    /// **Il testo corrente contiene tutti i suoi elementi di significato.**
    ///
    /// È la regola di DEC-356, decisione 4: più chiaro, mai più vago.
    #[test]
    fn il_testo_corrente_contiene_tutti_gli_elementi_di_significato() {
        for messaggio in SECURITY_MESSAGES {
            for versione in messaggio
                .history
                .iter()
                .chain(std::iter::once(&messaggio.current))
            {
                assert!(
                    !versione.meaning_elements.is_empty(),
                    "{} v{}: un messaggio senza elementi di significato non si può proteggere",
                    messaggio.code,
                    versione.number
                );
                let mancanti = missing_elements(versione);
                assert!(
                    mancanti.is_empty(),
                    "{} v{}: il testo non contiene più {mancanti:?}. Togliere un elemento è un \
                     cambio di significato: si registra una decisione e si aggiunge una versione",
                    messaggio.code,
                    versione.number
                );
            }
        }
    }

    /// **Ogni messaggio ha il suo dettaglio tecnico.**
    #[test]
    fn ogni_messaggio_ha_un_dettaglio_tecnico() {
        for messaggio in SECURITY_MESSAGES {
            assert!(
                !messaggio.current.technical_detail.trim().is_empty(),
                "{}: il dettaglio tecnico è vuoto. La frase semplice dice che cosa fare; il \
                 dettaglio dice il resto, e senza di esso il messaggio ha perso una parte di ciò \
                 che significava",
                messaggio.code
            );
            assert!(
                !messaggio.current.text.trim().is_empty(),
                "{}: il testo è vuoto",
                messaggio.code
            );
        }
    }

    /// **Cambiare una parola senza aggiungere una versione fa diventare rossa
    /// questa prova.**
    #[test]
    fn ogni_versione_porta_la_propria_impronta() {
        for messaggio in SECURITY_MESSAGES {
            for versione in messaggio
                .history
                .iter()
                .chain(std::iter::once(&messaggio.current))
            {
                let calcolata = fingerprint(
                    versione.text,
                    versione.technical_detail,
                    versione.meaning_elements,
                );
                assert_eq!(
                    calcolata.as_str(),
                    versione.fingerprint,
                    "{} v{}: il testo, il dettaglio o gli elementi non sono quelli registrati. \
                     Una versione non si modifica: se ne aggiunge una nuova, con il numero \
                     successivo, che dichiara se è una riformulazione o un cambio di significato. \
                     L'impronta del testo attuale è {calcolata}",
                    messaggio.code,
                    versione.number
                );
            }
        }
    }

    /// **La storia è in ordine e dichiara che cosa è cambiato.**
    #[test]
    fn ogni_versione_dichiara_che_cosa_e_cambiato() {
        for messaggio in SECURITY_MESSAGES {
            let tutte: Vec<_> = messaggio
                .history
                .iter()
                .chain(std::iter::once(&messaggio.current))
                .collect();
            for (posizione, versione) in tutte.iter().enumerate() {
                let atteso = u32::try_from(posizione + 1).unwrap_or(u32::MAX);
                assert_eq!(
                    versione.number, atteso,
                    "{}: le versioni devono essere numerate da 1 senza salti",
                    messaggio.code
                );
                match (posizione, versione.change) {
                    (0, Change::First) => {}
                    (0, _) => panic!("{}: la prima versione dichiara `First`", messaggio.code),
                    (_, Change::First) => {
                        panic!(
                            "{} v{}: solo la prima è `First`",
                            messaggio.code, versione.number
                        )
                    }
                    (_, Change::Rewording { reason }) => {
                        let precedente = tutte[posizione - 1];
                        assert_eq!(
                            precedente.meaning_elements, versione.meaning_elements,
                            "{} v{}: dichiara una riformulazione ma cambia gli elementi di \
                             significato. È un cambio di significato, e richiede una decisione",
                            messaggio.code, versione.number
                        );
                        assert!(
                            !reason.trim().is_empty(),
                            "{}: la ragione è vuota",
                            messaggio.code
                        );
                    }
                    (_, Change::MeaningChange { decision, reason }) => {
                        let precedente = tutte[posizione - 1];
                        assert_ne!(
                            precedente.meaning_elements, versione.meaning_elements,
                            "{} v{}: dichiara un cambio di significato ma gli elementi sono gli \
                             stessi. È una riformulazione",
                            messaggio.code, versione.number
                        );
                        assert!(
                            !reason.trim().is_empty(),
                            "{}: la ragione è vuota",
                            messaggio.code
                        );
                        assert!(
                            decision.starts_with("DEC-"),
                            "{} v{}: la decisione «{decision}» non ha la forma DEC-n",
                            messaggio.code,
                            versione.number
                        );
                        // Il registro delle decisioni sta soltanto
                        // nell'archivio (ADR-0210).
                    }
                }
            }
        }
    }

    /// **Un messaggio che arriva dal Rust è nell'elenco come gli altri.**
    #[test]
    fn il_messaggio_della_copia_senza_telegram_e_registrato() {
        assert!(SECURITY_MESSAGES.contains(&super::RUNTIME_MISSING));
        assert_eq!(
            super::by_code("SIC-15").map(|m| m.rust_constant),
            Some(Some("TELEGRAM_RUNTIME_MISSING_REASON"))
        );
    }

    /// Stampa l'impronta di ogni versione: serve a chi aggiunge una versione.
    /// Non è una prova.
    #[test]
    #[ignore = "strumento: stampa le impronte da registrare"]
    fn stampa_le_impronte() {
        for messaggio in SECURITY_MESSAGES {
            for versione in messaggio
                .history
                .iter()
                .chain(std::iter::once(&messaggio.current))
            {
                println!(
                    "{} v{} {}",
                    messaggio.code,
                    versione.number,
                    fingerprint(
                        versione.text,
                        versione.technical_detail,
                        versione.meaning_elements
                    )
                );
            }
        }
    }
}
