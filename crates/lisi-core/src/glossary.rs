//! Il glossario del prodotto: una parola per ogni cosa (PR-01, ADR-0117).
//!
//! # Perché esiste
//!
//! Un prodotto che chiama la stessa cosa in tre modi insegna che le parole non
//! contano. Questo prodotto ha avvertenze che servono **solo** se vengono
//! lette e capite: sono ciò che impedisce a un'osservazione di diventare
//! un'accusa. Il glossario fissa, per ogni concetto, **il nome che l'operatore
//! legge**, e per ogni termine tecnico **la frase semplice che lo sostituisce in
//! superficie**.
//!
//! # Due generi di voce
//!
//! - [`EntryKind::Concept`]: una parola che il prodotto usa **in superficie** per
//!   una cosa sua. Ha un nome solo e l'elenco dei sinonimi vietati.
//! - [`EntryKind::Technical`]: una parola che in superficie **non compare**. Vive
//!   solo dentro «Dettagli tecnici»; in superficie si usa la sua frase semplice.
//!
//! La guardia che applica queste regole a ogni testo mostrato è
//! `crates/lisi-app/src/plain_italian_guard.rs`. Qui stanno i dati e le misure
//! che la guardia usa, perché siano provate una volta sola.
//!
//! # Vive al confine, non nel codice
//!
//! Il glossario governa **ciò che l'operatore legge**. Non rinomina moduli,
//! tabelle, colonne né identificativi: la colonna `acquisition_origin` continua
//! a contenere `osservato`, e in superficie quel valore si legge «dal vivo».

/// Quante parole può avere, al massimo, una frase in superficie (ADR-0117, L4).
///
/// Venticinque è la soglia oltre la quale le guide italiane di scrittura
/// amministrativa chiara consigliano di spezzare. Misura la lunghezza, non la
/// chiarezza: la seconda la verifica una persona.
pub const MAX_SENTENCE_WORDS: usize = 25;

/// Il genere di una voce del glossario.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryKind {
    /// Una parola che il prodotto usa in superficie per una cosa sua.
    Concept,
    /// Una parola che in superficie non compare: vive nei dettagli tecnici.
    Technical,
}

/// Una voce del glossario.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GlossaryEntry {
    /// La parola, come la si legge nella Guida.
    pub term: &'static str,
    /// Le forme con cui la parola compare nel testo, minuscole e senza
    /// apostrofi: `["impronta", "impronte"]`.
    ///
    /// Per un concetto sono le forme **ammesse** in superficie; per un termine
    /// tecnico sono quelle **vietate** fuori dai dettagli tecnici.
    pub forms: &'static [&'static str],
    /// Il genere della voce.
    pub kind: EntryKind,
    /// La frase semplice: che cosa vuol dire, in parole comuni.
    pub plain: &'static str,
    /// Il dettaglio tecnico, per chi lo cerca.
    pub technical_detail: &'static str,
    /// Le altre parole con cui qualcuno potrebbe chiamare la stessa cosa, e che
    /// in superficie **non** si usano. Minuscole; possono essere espressioni di
    /// più parole.
    pub forbidden_synonyms: &'static [&'static str],
    /// Versione della voce, da 1. Cresce quando cambia il significato.
    pub version: u32,
}

/// Le parole di un testo, minuscole, come le conta la guardia.
///
/// Una parola è una sequenza di lettere. I segnaposto di formato (`{nome}`,
/// `{}`) non sono parole: stanno per un valore che il testo non conosce. Le
/// cifre non sono parole. L'apostrofo separa: `dell'account` sono due parole,
/// `dell` e `account`.
#[must_use]
pub fn surface_words(text: &str) -> Vec<String> {
    let mut parole = Vec::new();
    let mut corrente = String::new();
    let mut in_segnaposto = false;

    for carattere in text.chars() {
        if in_segnaposto {
            if carattere == '}' {
                in_segnaposto = false;
            }
            continue;
        }
        if carattere == '{' {
            in_segnaposto = true;
            chiudi(&mut corrente, &mut parole);
            continue;
        }
        if carattere.is_alphabetic() {
            corrente.extend(carattere.to_lowercase());
        } else {
            chiudi(&mut corrente, &mut parole);
        }
    }
    chiudi(&mut corrente, &mut parole);
    parole
}

/// Chiude la parola in corso, se ha almeno due lettere.
///
/// Una lettera sola è un'elisione (`l'`, `d'`) o un'iniziale: non porta
/// significato proprio, e contarla riempirebbe il lessico di rumore.
fn chiudi(corrente: &mut String, parole: &mut Vec<String>) {
    if corrente.chars().count() >= 2 {
        parole.push(core::mem::take(corrente));
    } else {
        corrente.clear();
    }
}

/// Le frasi di un testo.
///
/// Una frase finisce con un punto, un punto esclamativo, un punto
/// interrogativo o i puntini, **seguiti da uno spazio o dalla fine**; oppure
/// con un a capo. Un punto dentro un numero (`0.5`) o dentro un nome di file
/// (`rapporto.txt`) non la chiude, perché non è seguito da uno spazio.
#[must_use]
pub fn sentences(text: &str) -> Vec<&str> {
    let mut frasi = Vec::new();
    let mut inizio = 0;
    let mut caratteri = text.char_indices().peekable();

    while let Some((posizione, carattere)) = caratteri.next() {
        let fine_frase = match carattere {
            '\n' => true,
            '.' | '!' | '?' | '…' => caratteri
                .peek()
                .is_none_or(|(_, seguente)| seguente.is_whitespace()),
            _ => false,
        };
        if fine_frase {
            let fine = posizione + carattere.len_utf8();
            if let Some(frase) = text.get(inizio..fine)
                && !frase.trim().is_empty()
            {
                frasi.push(frase.trim());
            }
            inizio = fine;
        }
    }
    if let Some(resto) = text.get(inizio..)
        && !resto.trim().is_empty()
    {
        frasi.push(resto.trim());
    }
    frasi
}

/// Quante parole ha una frase, come le conta la regola L4.
///
/// Conta ogni gruppo separato da spazi che contiene una lettera, una cifra o un
/// segnaposto: «—» da solo non è una parola, `{nome}` sì, perché sullo schermo
/// diventa un nome.
#[must_use]
pub fn sentence_word_count(sentence: &str) -> usize {
    sentence
        .split_whitespace()
        .filter(|gruppo| gruppo.chars().any(|c| c.is_alphanumeric() || c == '{'))
        .count()
}

/// Le frasi di un testo che superano [`MAX_SENTENCE_WORDS`].
#[must_use]
pub fn long_sentences(text: &str) -> Vec<&str> {
    sentences(text)
        .into_iter()
        .filter(|frase| sentence_word_count(frase) > MAX_SENTENCE_WORDS)
        .collect()
}

/// La voce che contiene la forma indicata, se c'è.
#[must_use]
pub fn entry_for_form(form: &str) -> Option<&'static GlossaryEntry> {
    GLOSSARY.iter().find(|voce| voce.forms.contains(&form))
}

/// Una voce tecnica: poche righe per scriverla, perché il glossario si legga.
macro_rules! tecnico {
    ($term:literal, [$($form:literal),+ $(,)?], $plain:literal, $detail:literal $(,)?) => {
        GlossaryEntry {
            term: $term,
            forms: &[$($form),+],
            kind: EntryKind::Technical,
            plain: $plain,
            technical_detail: $detail,
            forbidden_synonyms: &[],
            version: 1,
        }
    };
}

/// Un concetto del prodotto.
macro_rules! concetto {
    ($term:literal, [$($form:literal),* $(,)?], $plain:literal, $detail:literal,
     vietati: [$($vietato:literal),* $(,)?] $(,)?) => {
        GlossaryEntry {
            term: $term,
            forms: &[$($form),*],
            kind: EntryKind::Concept,
            plain: $plain,
            technical_detail: $detail,
            forbidden_synonyms: &[$($vietato),*],
            version: 1,
        }
    };
}

/// Il glossario.
///
/// # Come si legge una voce
///
/// Un **concetto** ha il nome che l'operatore legge, la frase che lo spiega e
/// il dettaglio per chi lo cerca. Le sue forme sono le parole che il concetto
/// porta in superficie e che non sono di uso comune («hub», «workspace»); un
/// concetto fatto di parole comuni («Registro delle operazioni») non ne ha, e
/// serve a fissare il nome e i sinonimi vietati.
///
/// Un **termine tecnico** ha il termine, la frase semplice che lo sostituisce
/// in superficie e il dettaglio in cui il termine sopravvive.
///
/// # I nomi delle parti del prodotto
///
/// Sono i nomi scritti nella navigazione e in ogni documento che descrive una
/// parte del programma. Fino al 2026-10-11 questo paragrafo diceva che
/// «Dashboard», «Workspace», «Cyber Watch» e «Rule Lab» restavano in inglese
/// «fino a PR-14». **Quel rinvio era scaduto**: PR-14 si è chiusa il
/// 2026-10-01 e ADR-0130 dichiara in modo esplicito che non cambia il nome di
/// nessuna schermata. I quattro nomi restavano quindi per inerzia e non per
/// decisione, ed è esattamente ciò che FINAL-PRODUCT-REVIEW-01 ha trovato
/// (FPR-09).
///
/// Dal 2026-10-12 si chiamano **Cruscotto**, **Raccoglitore**, **Segnali
/// cyber** e **Laboratorio regole** (DEC-387). Il nome inglese di ciascuno è
/// ora un **sinonimo vietato**: se torna in superficie, la regola L3 della
/// guardia lo trova. Non è una prova nuova — è quella che c'era, con un dato
/// in più.
///
/// Due nomi **non** sono stati tradotti, e non per dimenticanza. «Hub» è il
/// nome di una macchina dell'ufficio, non di una schermata, e un ufficio che
/// ne possiede uno lo chiama così. «Live condiviso» nomina una vista
/// dell'Hub ed è già mezzo italiano; tradurre «live» in «dal vivo»
/// confonderebbe con il **modo di acquisizione** «dal vivo», che è un'altra
/// cosa e ha una colonna propria nei documenti.
///
/// «Alert» è l'eccezione più vecchia: OPERATOR-SIM-01 (OS-07) ha mostrato che
/// il nome inglese accanto ad «avvisi», detto ovunque nel testo, confondeva, e
/// dal 2026-10-08 la voce del menu e il titolo della schermata dicono
/// «Avvisi». Il concetto resta qui con la sua forma, perché la parola compare
/// ancora nelle associazioni. Dal 2026-10-12 **non compare più nel registro
/// del monitoraggio**, dove il foglio si chiama «04 — Avvisi» (FPR-03): quel
/// registro si allega a una relazione di servizio, e non è un documento
/// tecnico.
pub const GLOSSARY: &[GlossaryEntry] = &[
    // ------------------------------------------------ concetti del prodotto
    concetto!(
        "Monitoraggio",
        [],
        "Un periodo in cui il programma segue alcune fonti e conserva quello che vi viene pubblicato.",
        "Una sessione di acquisizione: fonti scelte, dizionari scelti, inizio e fine registrati.",
        vietati: [],
    ),
    concetto!(
        "Fonte",
        [],
        "Un canale o un gruppo Telegram che l'account d'ufficio può già leggere.",
        "Una chat Telegram raggiungibile dall'account configurato. Il programma non entra in gruppi e non chiede accessi.",
        vietati: [],
    ),
    concetto!(
        "Dizionario",
        [],
        "Un elenco di parole scelte dall'ufficio. Il programma segnala i messaggi che le contengono.",
        "Un insieme versionato di termini, con peso e contesto. Il riscontro è deterministico: stesse parole, stesso risultato.",
        vietati: [],
    ),
    concetto!(
        "Livello",
        [],
        "Un numero da 0 a 4 che dice quanto un messaggio corrisponde ai dizionari scelti. Non dice quanto è pericolosa una persona.",
        "Calcolato da regole fisse sui termini riscontrati. Il livello 0 è un contenuto analizzato e non rilevante.",
        vietati: [],
    ),
    concetto!(
        "Riscontro",
        [],
        "Una parola di un dizionario trovata in un messaggio.",
        "Corrispondenza deterministica fra un termine del dizionario e il testo normalizzato del contenuto.",
        vietati: [],
    ),
    concetto!(
        "Archivio",
        [],
        "Il posto, su questa postazione, dove il programma conserva tutto quello che ha raccolto.",
        "Un database SQLite locale, con le migrazioni numerate. I segreti sono protetti da Windows (DPAPI).",
        vietati: ["banca dati"],
    ),
    concetto!(
        "Registro delle operazioni",
        [],
        "L'elenco di chi ha fatto che cosa e quando. Non si modifica e non si cancella.",
        "Il registro di audit: una riga per ogni operazione rilevante, con autore, istante e ragione.",
        vietati: ["traccia di controllo", "registro di audit"],
    ),
    concetto!(
        "Impronta",
        [],
        "Un codice calcolato dal contenuto di un file. Se il file cambia anche di un carattere, l'impronta cambia.",
        "SHA-256, 64 cifre esadecimali. Dimostra che il file non è cambiato; non dice chi l'ha scritto: non è una firma.",
        vietati: [],
    ),
    concetto!(
        "Elenco delle impronte",
        [],
        "Il file che accompagna un documento e ne riporta l'impronta. Serve a controllare che nessuno lo abbia cambiato.",
        "Il manifest di integrità: nome del file, dimensione e impronta SHA-256 di ciascun file del pacchetto.",
        vietati: [],
    ),
    concetto!(
        "Dal vivo",
        [],
        "Un messaggio arrivato mentre il programma era in ascolto.",
        "Valore `osservato` della colonna `acquisition_origin`. Che questo valore provi l'ascolto dal vivo lo verifica PR-07.",
        vietati: ["osservato dal vivo", "osservati dal vivo", "osservata dal vivo", "osservate dal vivo"],
    ),
    concetto!(
        "Osservato",
        [],
        "Un dato che viene da Telegram o da una fonte esterna, così com'era.",
        "Origin::Observed (ADR-0118). È un'origine, non un modo di acquisizione: anche un messaggio recuperato è osservato.",
        vietati: ["fatto osservato"],
    ),
    concetto!(
        "Calcolato",
        [],
        "Un dato prodotto da una regola fissa del programma, con nome e versione. Con regole diverse sarebbe diverso.",
        "Origin::Computed (ADR-0118): calcolo deterministico, senza modelli appresi (ADR-0048).",
        vietati: ["elaborazione automatica"],
    ),
    concetto!(
        "Operatore",
        [],
        "Un dato scritto o deciso da una persona, con il suo nome, il motivo e l'istante.",
        "Origin::Operator (ADR-0118): un atto registrato nel registro delle operazioni.",
        vietati: ["decisione umana"],
    ),
    concetto!(
        "Origine non registrata",
        [],
        "L'archivio non sa chi ha detto questo dato. Nessuno l'ha indovinato al suo posto.",
        "RecordedOrigin::NotRecorded (ADR-0118): mai sostituito da un valore plausibile.",
        vietati: [],
    ),
    concetto!(
        "Recuperato",
        [],
        "Un messaggio preso dopo, dalla cronologia di Telegram. Il programma non c'era quando è stato pubblicato.",
        "Valore `recuperato` della colonna `acquisition_origin`, scritto dalla funzione di recupero della cronologia.",
        vietati: [],
    ),
    concetto!(
        "Allineamento con l'Hub",
        [],
        "Quando una postazione si ricollega, chiede all'Hub quello che è successo mentre era scollegata.",
        "Il recupero dopo una riconnessione (HUB-CATCHUP-01): lettura degli eventi dell'Hub dall'ultimo numero applicato.",
        vietati: ["recupero automatico", "recupero dall'hub"],
    ),
    concetto!(
        "Funzionamento dimostrativo",
        [],
        "Il programma funziona con dati finti e non si collega a Telegram.",
        "Il connettore simulato (mock). Una copia costruita senza il componente per Telegram offre solo questo.",
        vietati: ["modalità mock"],
    ),
    concetto!(
        "Postazione",
        [],
        "Il computer su cui questo programma è installato.",
        "Un'installazione per utente sotto %LOCALAPPDATA%, con il proprio archivio e la propria identità di dispositivo.",
        vietati: [],
    ),
    concetto!(
        "Account d'ufficio",
        ["account"],
        "L'account Telegram dell'ufficio che il programma usa per leggere le fonti.",
        "Una sessione TDLib autenticata con numero, codice ed eventuale password della verifica in due passaggi.",
        vietati: [],
    ),
    concetto!(
        "Hub",
        ["hub"],
        "Il computer dell'ufficio che tiene insieme il lavoro di più postazioni.",
        "Un servizio su rete locale con collegamento cifrato (TLS) e dispositivi arruolati uno per uno.",
        vietati: [],
    ),
    concetto!(
        "Raccoglitore",
        [],
        "Un contenitore in cui raccogliere, per un lavoro, riferimenti a messaggi e a soggetti.",
        "Un insieme nominato di riferimenti; nel codice e nell'archivio la chiave resta `workspace`. Chiuso, non accetta e non perde elementi.",
        vietati: ["workspace", "workspaces"],
    ),
    concetto!(
        "Soggetto",
        [],
        "Una persona o un profilo su cui qualcuno dell'ufficio ha deciso di raccogliere informazioni, per una ragione scritta.",
        "Il fascicolo di Person Intelligence: aperto e chiuso da una persona, con motivo, istante e registro.",
        vietati: [],
    ),
    concetto!(
        "Cruscotto",
        ["cruscotto"],
        "La schermata che riassume lo stato del lavoro.",
        "Nome di sezione dell'interfaccia; si chiamava «Dashboard» fino al 2026-10-12 (DEC-387).",
        vietati: ["dashboard"],
    ),
    // La voce si chiama come la schermata (UX-EXCELLENCE-02, SIM3-11): il
    // glossario diceva «Alert» e il menu «Avvisi», e chi cercava la parola che
    // vedeva non la trovava. «alert» resta fra le forme, perché compare ancora
    // nelle associazioni di una persona.
    concetto!(
        "Avvisi",
        ["avvisi", "alert"],
        "L'elenco dei messaggi che l'analisi ha portato all'attenzione, dal livello 1 in su.",
        "Ogni riga è un contenuto con livello maggiore di 0. La sezione si chiamava «Alert» fino al 2026-10-08 (OS-07).",
        vietati: [],
    ),
    concetto!(
        "Laboratorio regole",
        ["laboratorio"],
        "La schermata in cui si prova una modifica ai dizionari sui messaggi già archiviati, senza pubblicarla.",
        "Confronto fra la versione pubblicata e una bozza di dizionario, calcolato sull'archivio. Non scrive nulla. Si chiamava «Rule Lab» fino al 2026-10-12 (DEC-387).",
        vietati: ["rule lab"],
    ),
    concetto!(
        "Segnali cyber",
        ["cyber"],
        "La sezione che raccoglie i messaggi che parlano di attacchi informatici e di vulnerabilità.",
        "Correlazione deterministica di indicatori (domini, indirizzi, CVE) fra contenuti e fonti. Si chiamava «Cyber Watch» fino al 2026-10-12 (DEC-387); «Monitoraggio cyber» è stato scartato perché in quel menu «Monitoraggio» è un'altra cosa.",
        vietati: ["cyber watch"],
    ),
    concetto!(
        "Live condiviso",
        ["live"],
        "La vista in cui più postazioni vedono lo stesso lavoro nello stesso momento, attraverso l'Hub.",
        "Flusso di eventi dell'Hub distribuito ai dispositivi arruolati (TEAM-LIVE).",
        vietati: [],
    ),
    concetto!(
        "Telegram Intelligence Monitor",
        ["intelligence", "monitor"],
        "Il sottotitolo del prodotto: il programma che segue fonti Telegram per l'ufficio.",
        "Sottotitolo pubblico di NEXUM/97 (ADR-0011).",
        vietati: [],
    ),
    concetto!(
        "STIX",
        ["stix"],
        "Un formato per passare informazioni su attacchi informatici ad altri programmi di analisi.",
        "STIX 2.1, di OASIS. Il prodotto esporta solo ciò che la semantica del formato regge (STIX-01).",
        vietati: [],
    ),
    concetto!(
        "TAXII",
        ["taxii"],
        "Un modo per mandare a un indirizzo scelto dall'ufficio le stesse informazioni del formato STIX. Il programma manda e non riceve niente.",
        "TAXII 2.1, di OASIS: un POST su una collezione, soltanto su richiesta di una persona, con HTTP Basic (ADR-0179).",
        vietati: [],
    ),
    concetto!(
        "WHOIS",
        ["whois"],
        "Chi ha registrato un nome di rete o un indirizzo, chiesto al registro che lo tiene. La richiesta parte dal PC e il registro la vede.",
        "RDAP in https quando l'elenco IANA lo indica, altrimenti WHOIS in chiaro sulla porta 43 al server che indica whois.iana.org (ADR-0205).",
        vietati: [],
    ),
    concetto!(
        "MITRE ATT&CK",
        ["mitre", "att", "ck"],
        "Un catalogo pubblico dei modi in cui si conducono gli attacchi informatici. Un'associazione la dichiara una persona.",
        "La matrice ATT&CK di MITRE, importata come fotografia verificata (ATTACK-01, ATTACK-02).",
        vietati: [],
    ),
    concetto!(
        "CVE",
        ["cve"],
        "Il codice pubblico di una vulnerabilità informatica, come CVE-2024-12345.",
        "Common Vulnerabilities and Exposures. Il prodotto lo risolve contro una fotografia NVD importata (SNAP-CVE-01).",
        vietati: [],
    ),
    concetto!(
        "KEV",
        ["kev"],
        "L'elenco pubblico, tenuto da CISA, delle vulnerabilità che si sa essere già sfruttate.",
        "Known Exploited Vulnerabilities di CISA, letto da una fotografia importata (SNAP-KEV-01).",
        vietati: [],
    ),
    concetto!(
        "NVD",
        ["nvd"],
        "L'archivio pubblico americano che descrive le vulnerabilità con codice CVE.",
        "National Vulnerability Database del NIST, da cui si acquisisce la fotografia CVE.",
        vietati: [],
    ),
    concetto!(
        "CISA",
        ["cisa"],
        "L'agenzia americana per la sicurezza informatica che pubblica l'elenco KEV.",
        "Cybersecurity and Infrastructure Security Agency.",
        vietati: [],
    ),
    // ------------------------------------------------------ termini tecnici
    tecnico!(
        "SHA-256",
        ["sha", "hash", "digest"],
        "impronta",
        "SHA-256 è la funzione che calcola le impronte: 64 cifre esadecimali.",
    ),
    tecnico!(
        "Manifest",
        ["manifest", "manifesto"],
        "elenco delle impronte",
        "Il manifest di integrità riporta, per ogni file, nome, dimensione e impronta SHA-256.",
    ),
    tecnico!(
        "TDLib",
        ["tdlib", "tdjson"],
        "il componente che collega il programma a Telegram",
        "TDLib è la libreria ufficiale di Telegram per i programmi, a versione fissata (ADR-0008).",
    ),
    tecnico!(
        "API",
        ["api"],
        "il canale ufficiale che Telegram offre ai programmi",
        "L'API ufficiale di Telegram, raggiunta attraverso TDLib con le credenziali di NEXUM/97.",
    ),
    tecnico!(
        "DPAPI",
        ["dpapi"],
        "la protezione dei segreti di Windows",
        "Windows Data Protection API: cifra i dati per l'utente di Windows che li ha scritti.",
    ),
    tecnico!(
        "JSON",
        ["json"],
        "file di dati",
        "JSON: il formato di testo strutturato usato per dizionari, fotografie e scambi con l'Hub.",
    ),
    tecnico!(
        "ID",
        ["id"],
        "identificativo",
        "Identificativo numerico o testuale interno all'archivio o a Telegram.",
    ),
    tecnico!(
        "URL",
        ["url"],
        "indirizzo web",
        "Uniform Resource Locator. Il prodotto apre solo indirizzi controllati (Milestone 14).",
    ),
    tecnico!(
        "HTTPS",
        ["http", "https"],
        "collegamento cifrato",
        "HTTP su TLS, con il certificato del server verificato.",
    ),
    tecnico!(
        "TLS",
        ["tls"],
        "collegamento cifrato",
        "Transport Layer Security, con verifica del certificato del server.",
    ),
    tecnico!(
        "UUID",
        ["uuid"],
        "identificativo unico",
        "Universally Unique Identifier, 128 bit."
    ),
    tecnico!(
        "SQLite",
        ["sqlite", "database"],
        "archivio",
        "L'archivio è un database SQLite locale, compilato nel programma.",
    ),
    tecnico!(
        "Audit",
        ["audit"],
        "registro delle operazioni",
        "Il registro di audit: autore, istante, operazione e ragione, senza cancellazioni.",
    ),
    tecnico!(
        "Log",
        ["log"],
        "registro tecnico",
        "Il file di log del programma, senza contenuti monitorati né segreti.",
    ),
    tecnico!(
        "Mock",
        ["mock"],
        "funzionamento dimostrativo",
        "Il connettore simulato, che risponde con dati sintetici e non apre alcuna rete.",
    ),
    tecnico!(
        "Client",
        ["client"],
        "programma che si collega a un servizio",
        "Nel senso di client Telegram: un programma per usare Telegram come una persona.",
    ),
    tecnico!(
        "Server",
        ["server"],
        "computer che offre un servizio",
        "Il lato che risponde in un collegamento di rete.",
    ),
    tecnico!(
        "Proxy",
        ["proxy"],
        "computer intermedio che fa da tramite",
        "Un server che inoltra il traffico al posto di chi lo invia. Il prodotto non ne usa.",
    ),
    tecnico!(
        "Runtime",
        ["runtime"],
        "componente di esecuzione",
        "La parte del programma che, compilata con la feature `tdlib-runtime`, parla con Telegram.",
    ),
    tecnico!(
        "Feature",
        ["feature"],
        "opzione di costruzione del programma",
        "Una feature di Cargo: una parte del programma inclusa o esclusa quando lo si compila.",
    ),
    tecnico!(
        "Script",
        ["script"],
        "procedura automatica",
        "Uno script PowerShell del repository, da eseguire su una postazione di preparazione.",
    ),
    tecnico!(
        "Setup",
        ["setup"],
        "installazione",
        "Il programma d'installazione o la sua configurazione."
    ),
    tecnico!(
        "Banner",
        ["banner"],
        "riquadro di notifica",
        "Il riquadro con cui Windows mostra una notifica.",
    ),
    tecnico!(
        "Checkpoint",
        ["checkpoint"],
        "punto di ripresa",
        "L'ultimo punto dell'acquisizione registrato, da cui un monitoraggio riprende.",
    ),
    tecnico!(
        "Indirizzo IP",
        ["ip", "ipv"],
        "indirizzo di rete",
        "Indirizzo IPv4 o IPv6."
    ),
    tecnico!(
        "Multicast",
        ["multicast", "broadcast"],
        "invio a più computer della rete insieme",
        "Traffico multicast o broadcast sulla rete locale.",
    ),
    tecnico!(
        "Offset",
        ["offset"],
        "posizione di partenza",
        "Lo scostamento con cui si chiede una pagina di risultati.",
    ),
    tecnico!(
        "Payload",
        ["payload"],
        "contenuto del messaggio tecnico",
        "Il corpo di un messaggio scambiato fra programmi.",
    ),
    tecnico!(
        "Polling",
        ["polling"],
        "controllo ripetuto",
        "Interrogazione a intervalli regolari."
    ),
    tecnico!(
        "Embedding",
        ["embedding"],
        "rappresentazione numerica prodotta da un modello di intelligenza artificiale",
        "Vettori appresi da un modello. Il prodotto non ne usa (ADR-0048).",
    ),
    tecnico!(
        "Indice di Jaccard",
        ["jaccard"],
        "misura di quante sequenze di parole due testi hanno in comune",
        "Rapporto fra l'intersezione e l'unione degli insiemi di sequenze.",
    ),
    tecnico!(
        "Esadecimale",
        ["esadecimale", "esadecimali"],
        "scritto con le cifre da 0 a 9 e le lettere da a a f",
        "Notazione in base sedici.",
    ),
    tecnico!(
        "Deterministico",
        [
            "deterministico",
            "deterministica",
            "deterministici",
            "deterministiche"
        ],
        "sempre uguale, a parità di dati e di regole",
        "Un calcolo senza casualità né modelli appresi: ripetuto, dà lo stesso risultato.",
    ),
    tecnico!(
        "Serializzazione",
        ["serializzabile", "serializzato", "serializzata"],
        "scritto in un formato che si può salvare e rileggere",
        "Conversione di una struttura in una sequenza di byte.",
    ),
    tecnico!(
        "Forma canonica",
        ["canonica", "canonico", "canoniche", "canonici"],
        "forma unica e fissata",
        "Rappresentazione standard, perché due scritture della stessa cosa diano la stessa impronta.",
    ),
    tecnico!(
        "Normalizzazione",
        [
            "normalizzata",
            "normalizzate",
            "normalizzato",
            "normalizzati",
            "normalizzazione"
        ],
        "scritto sempre nello stesso modo",
        "Normalizzazione Unicode NFC e delle maiuscole prima del confronto.",
    ),
    tecnico!(
        "Unicode",
        ["unicode", "nfc"],
        "il sistema con cui il computer scrive le lettere di tutte le lingue",
        "Unicode, forma di normalizzazione NFC.",
    ),
    tecnico!(
        "Eseguibile",
        ["exe"],
        "file del programma",
        "Un file eseguibile di Windows (.exe)."
    ),
    tecnico!(
        "Interfaccia grafica",
        ["gui", "ui"],
        "finestra del programma",
        "GUI o UI: l'interfaccia grafica.",
    ),
    tecnico!(
        "Formati Office",
        ["docx", "xlsx"],
        "file di Word o di Excel",
        "Office Open XML: .docx per Word, .xlsx per Excel.",
    ),
    tecnico!(
        "Cargo",
        ["cargo", "crate"],
        "strumenti con cui il programma è costruito",
        "Cargo è il gestore dei pacchetti di Rust; un crate è un pacchetto.",
    ),
    tecnico!(
        "Binario",
        ["binario", "binari"],
        "file del programma",
        "Un file eseguibile prodotto dalla compilazione.",
    ),
    tecnico!(
        "Standalone",
        ["standalone"],
        "da sola, senza Hub",
        "Postazione che lavora senza essere arruolata in un Hub.",
    ),
    tecnico!(
        "LocalAppData",
        ["localappdata"],
        "la cartella dei programmi dell'utente di Windows",
        "%LOCALAPPDATA%: l'installazione è per utente, senza privilegi di amministratore.",
    ),
    tecnico!(
        "Sottodominio",
        ["sottodomini", "sottodominio"],
        "parte di un indirizzo web",
        "Un nome sotto un dominio, come a.esempio.it sotto esempio.it.",
    ),
    tecnico!(
        "Replay",
        ["replay"],
        "rilettura",
        "La ricostruzione, passo per passo, di come un monitoraggio si è svolto.",
    ),
    tecnico!(
        "Template",
        ["template"],
        "modello",
        "Un modello di documento o di monitoraggio."
    ),
    tecnico!(
        "Codificatore",
        ["codificatore"],
        "componente che scrive il file",
        "Il codificatore che produce il formato del file.",
    ),
    tecnico!(
        "Host",
        ["host"],
        "computer a cui ci si collega",
        "Il nome del computer in un indirizzo web, come aggiornamenti.esempio.it.",
    ),
    tecnico!(
        "Provider",
        ["provider"],
        "componente di Windows che verifica le firme",
        "Il trust provider di Authenticode che Windows usa per verificare un file firmato.",
    ),
    tecnico!(
        "WAL e SHM",
        ["wal", "shm"],
        "file temporanei dell'archivio",
        "I file -wal e -shm di SQLite: modifiche non ancora riportate nel file principale.",
    ),
    tecnico!(
        "PKCS#8",
        ["pkcs"],
        "formato di una chiave",
        "PKCS#8: il formato standard in cui è scritta una chiave privata.",
    ),
    tecnico!(
        "MD5",
        ["md"],
        "impronta di un tipo vecchio",
        "MD5: una funzione di hash superata, che il prodotto riconosce in un testo ma non usa.",
    ),
    tecnico!(
        "Build",
        ["build"],
        "copia del programma costruita per un uso",
        "Una build: il programma compilato con un certo insieme di feature, come `tdlib-runtime`.",
    ),
    concetto!(
        "UTC",
        ["utc"],
        "L'ora universale: l'ora di riferimento, senza fuso orario né ora legale. Gli orari del programma sono scritti così.",
        "Tempo coordinato universale. Gli istanti sono conservati in millisecondi dal 1970 e mostrati in UTC.",
        vietati: [],
    ),
    concetto!(
        "Report",
        ["report"],
        "La schermata in cui si preparano i documenti su un monitoraggio: relazione, allegato e registro.",
        "Nome di sezione dell'interfaccia. Produce il pacchetto di report di MP-18 con il suo elenco delle impronte.",
        vietati: [],
    ),
];

#[cfg(test)]
mod tests {
    use super::{
        EntryKind, GLOSSARY, MAX_SENTENCE_WORDS, long_sentences, sentence_word_count, sentences,
        surface_words,
    };

    /// Quante voci deve avere il glossario, almeno. Un glossario vuoto fa
    /// passare ogni guardia che lo usa (ADR-0111).
    const MINIMO: usize = 60;

    #[test]
    fn le_parole_sono_lettere_minuscole_senza_segnaposto() {
        assert_eq!(
            surface_words("Dell'account {nome}: 3 volte, SHA-256."),
            vec!["dell", "account", "volte", "sha"]
        );
        // «è» ha una lettera sola: non entra nel conto, come «a» ed «e».
        assert_eq!(surface_words("È già così"), vec!["già", "così"]);
    }

    #[test]
    fn un_punto_dentro_un_numero_non_chiude_la_frase() {
        assert_eq!(
            sentences("Il file rapporto.txt pesa 0.5 MB. Poi si chiude! Fine"),
            vec![
                "Il file rapporto.txt pesa 0.5 MB.",
                "Poi si chiude!",
                "Fine"
            ]
        );
        assert_eq!(
            sentences("Riga uno\nRiga due"),
            vec!["Riga uno", "Riga due"]
        );
    }

    #[test]
    fn un_trattino_non_e_una_parola_un_segnaposto_si() {
        assert_eq!(sentence_word_count("Uno — due {nome} tre."), 4);
    }

    #[test]
    fn una_frase_lunga_si_vede() {
        let lunga = "parola ".repeat(MAX_SENTENCE_WORDS + 1);
        assert_eq!(long_sentences(&lunga).len(), 1);
        let breve = "parola ".repeat(MAX_SENTENCE_WORDS);
        assert!(long_sentences(&breve).is_empty());
    }

    #[test]
    fn il_glossario_non_e_vuoto() {
        assert!(
            GLOSSARY.len() >= MINIMO,
            "il glossario ha {} voci, ne servono almeno {MINIMO}: un glossario vuoto fa \
             passare ogni guardia che lo usa",
            GLOSSARY.len()
        );
    }

    #[test]
    fn ogni_voce_ha_frase_semplice_e_dettaglio_tecnico() {
        for voce in GLOSSARY {
            assert!(
                !voce.plain.trim().is_empty(),
                "«{}»: frase semplice vuota",
                voce.term
            );
            assert!(
                !voce.technical_detail.trim().is_empty(),
                "«{}»: dettaglio tecnico vuoto",
                voce.term
            );
            assert!(voce.version >= 1, "«{}»: la versione parte da 1", voce.term);
            assert!(
                voce.kind == EntryKind::Concept || !voce.forms.is_empty(),
                "«{}»: un termine tecnico senza forme non si può cercare in superficie",
                voce.term
            );
            for forma in voce.forms {
                assert_eq!(
                    surface_words(forma),
                    vec![String::from(*forma)],
                    "«{}»: la forma «{forma}» non è una parola come la conta la guardia \
                     (minuscola, solo lettere, almeno due)",
                    voce.term
                );
            }
            assert!(
                long_sentences(voce.plain).is_empty(),
                "«{}»: la frase semplice ha una frase più lunga di {MAX_SENTENCE_WORDS} parole",
                voce.term
            );
            assert!(
                !voce.plain.contains("**"),
                "«{}»: grassetto Markdown",
                voce.term
            );
        }
    }

    /// **La stessa parola non nomina due cose.**
    ///
    /// È il caso di «osservato» (arrivato mentre il programma ascoltava, e da
    /// PR-03 dato che viene da Telegram) e di «recupero» (la cronologia, e il
    /// riallineamento con l'Hub).
    #[test]
    fn una_parola_nomina_una_cosa_sola() {
        let mut viste: std::collections::BTreeMap<&str, &str> = std::collections::BTreeMap::new();
        for voce in GLOSSARY {
            for forma in voce.forms {
                if let Some(altra) = viste.insert(forma, voce.term) {
                    panic!(
                        "la forma «{forma}» appartiene sia a «{altra}» sia a «{}»",
                        voce.term
                    );
                }
            }
        }
    }

    /// **Un sinonimo vietato non è il nome ammesso di un'altra cosa.**
    ///
    /// Altrimenti la stessa parola sarebbe insieme vietata e ammessa, e la
    /// guardia darebbe ragione a chiunque.
    #[test]
    fn un_sinonimo_vietato_non_e_una_forma_ammessa() {
        for voce in GLOSSARY {
            for sinonimo in voce.forbidden_synonyms {
                assert_eq!(
                    sinonimo.to_lowercase(),
                    *sinonimo,
                    "«{}»: il sinonimo vietato «{sinonimo}» va scritto minuscolo",
                    voce.term
                );
                let ammessa = GLOSSARY.iter().any(|altra| {
                    altra.kind == EntryKind::Concept && altra.forms.contains(sinonimo)
                });
                assert!(
                    !ammessa,
                    "«{sinonimo}» è vietato per «{}» ed è la forma ammessa di un altro concetto",
                    voce.term
                );
            }
        }
    }
}
