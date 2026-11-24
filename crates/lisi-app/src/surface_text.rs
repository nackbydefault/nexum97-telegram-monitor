//! Il testo che l'operatore legge, estratto dai sorgenti **in un posto solo**.
//!
//! # Perché questo modulo esiste
//!
//! Due guardie leggono il testo mostrato: quella degli accenti (DEC-231) e
//! quella del linguaggio (PR-01, ADR-0117). Fino a PR-01 l'estrazione stava
//! dentro la prima, e la seconda ne avrebbe fatto una copia.
//!
//! In questo progetto l'estrattore di una guardia **si è già accecato tre
//! volte da solo**, sempre allo stesso modo: si fermava al primo segno che
//! somigliava al confine del modulo di prova invece che al confine vero
//! (vedere la storia in [`prodotto_rust`]). Due copie dello stesso
//! estrattore sono due posti in cui quella correzione va ricordata, e la copia
//! che se ne dimentica è quella che resta verde.
//!
//! # Che cosa è «mostrato»
//!
//! - nei file `.slint`, ogni stringa fuori dai commenti;
//! - nei sorgenti Rust del prodotto, ogni stringa fuori dai commenti, dai
//!   moduli di prova, dalle prove d'integrazione, dai binari di sonda e dalle
//!   chiamate che nessun operatore legge ([`MACRO_NON_MOSTRATE`]).
//!
//! È una definizione **larga di proposito**: si guarda tutto e si dichiara che
//! cosa si salta. Un elenco di posti dove guardare è una guardia che si
//! dimentica (UX-02).

use std::path::{Path, PathBuf};

/// I sorgenti dell'interfaccia, letti a tempo di compilazione.
pub const SCHERMATE: [(&str, &str); 4] = [
    ("app-window.slint", include_str!("../ui/app-window.slint")),
    ("components.slint", include_str!("../ui/components.slint")),
    ("brand.slint", include_str!("../ui/brand.slint")),
    ("tokens.slint", include_str!("../ui/tokens.slint")),
];

/// Un pezzo di testo mostrato, con la riga da cui viene e il suo contesto.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mostrata {
    /// Riga di partenza, da 1.
    pub riga: usize,
    /// Il testo fra virgolette. Nei file `.slint`, i letterali uniti da `+`
    /// sono **un testo solo**, perché sullo schermo sono una frase sola.
    pub testo: String,
    /// Dove sta il testo.
    ///
    /// - Rust: il nome dell'ultimo `fn`, `const` o `static` aperto prima del
    ///   testo;
    /// - Slint: la proprietà a cui il testo è assegnato (`text`, `label`, …).
    pub contesto: String,
    /// Solo Slint: se il testo è un **dettaglio tecnico** — sta dentro un
    /// elemento `DettagliTecnici`, oppure è il `dettaglio` di un
    /// `AvvertenzaDiSicurezza`, che lo passa al proprio `DettagliTecnici`.
    pub dettagli_tecnici: bool,
    /// Solo Slint: l'elemento che contiene il testo (`Text`,
    /// `AvvertenzaDiSicurezza`, …).
    pub elemento: String,
    /// Solo Slint: il numero progressivo dell'istanza di quell'elemento nel
    /// file. Due testi con lo stesso numero sono proprietà della STESSA
    /// istanza: è ciò che lega il codice di un'avvertenza al suo testo.
    pub istanza: usize,
}

/// Le chiamate il cui testo nessun operatore legge.
///
/// **I nomi di azione salvati nell'audit** non hanno bisogno di
/// un'esclusione: sono identificativi come `configurazione_fissata`.
///
/// Si salta invece ciò che **nessun operatore legge**: le righe di registro,
/// i messaggi di `panic!` e `expect`, le asserzioni. Correggerli non
/// cambierebbe nulla per chi usa il prodotto.
pub const MACRO_NON_MOSTRATE: [&str; 13] = [
    "tracing::",
    // Le stesse macro importate con `use tracing::{debug, warn}`: senza il
    // prefisso sono la stessa riga di registro, e nessun operatore la legge.
    "debug!(",
    "warn!(",
    "trace!(",
    "panic!",
    "assert",
    ".expect(",
    "unreachable!",
    "todo!",
    "include_str!",
    "env!",
    "cargo:warning",
    // Una stringa di byte NON PUO' contenere un accento: `b"…à…"` non
    // compila. Non e' una scappatoia, e' il linguaggio. L'unica del
    // prodotto e' il contenuto del file di prova della cartella dati, che
    // finisce su disco e non su uno schermo.
    "&[u8] = b\"",
];

/// Se la riga contiene testo che nessun operatore leggerà mai.
pub fn riga_non_mostrata(riga: &str) -> bool {
    let inizio = riga.trim_start();
    if inizio.starts_with("//") || inizio.starts_with("#[") {
        return true;
    }
    MACRO_NON_MOSTRATE.iter().any(|forma| riga.contains(forma))
}

/// Se la riga introduce un **modulo**, e non un'altra cosa.
///
/// È ciò che distingue il confine vero — `#[cfg(test)] mod tests` in fondo al
/// file — da un `#[cfg(test)]` posato su una funzione a metà file, che non è un
/// confine e non deve far smettere di guardare.
pub fn introduce_un_modulo(riga: &str) -> bool {
    let riga = riga.trim_start();
    riga.starts_with("mod ") || riga.starts_with("pub mod ") || riga.starts_with("pub(crate) mod ")
}

/// La radice del repository, dedotta dalla posizione di questo crate.
pub fn radice() -> PathBuf {
    let mio = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let Some(crates) = mio.parent() else {
        panic!("il crate deve stare dentro «crates»");
    };
    let Some(radice) = crates.parent() else {
        panic!("«crates» deve stare dentro la radice del repository");
    };
    radice.to_path_buf()
}

/// Tutti i sorgenti Rust sotto il percorso indicato, esclusa `target`.
pub fn sorgenti(percorso: &Path, trovati: &mut Vec<PathBuf>) {
    let Ok(voci) = std::fs::read_dir(percorso) else {
        return;
    };
    for voce in voci.flatten() {
        let percorso = voce.path();
        if percorso.is_dir() {
            if percorso.file_name().is_some_and(|nome| nome == "target") {
                continue;
            }
            sorgenti(&percorso, trovati);
        } else if percorso.extension().is_some_and(|e| e == "rs") {
            trovati.push(percorso);
        }
    }
}

/// I sorgenti Rust **del prodotto**: sotto `crates/`, senza prove
/// d'integrazione né binari di sonda. Il file di ciascuno è già ridotto alla
/// parte che un operatore può leggere ([`prodotto_rust`]).
pub fn sorgenti_del_prodotto() -> Vec<(PathBuf, String)> {
    let mut file = Vec::new();
    sorgenti(&radice().join("crates"), &mut file);
    file.sort();

    file.into_iter()
        .filter(|percorso| {
            // Le prove di integrazione e i binari di sonda non sono il
            // prodotto: nessun operatore ne legge una riga.
            let come_testo = percorso.to_string_lossy().replace('\\', "/");
            !come_testo.contains("/tests/") && !come_testo.contains("/src/bin/")
        })
        .filter_map(|percorso| {
            let testo = std::fs::read_to_string(&percorso).ok()?;
            Some((percorso, prodotto_rust(&testo)))
        })
        .collect()
}

/// La parte di un sorgente Rust che un operatore può leggere.
///
/// # Il taglio deve cadere sul MODULO di prova
///
/// Il modulo di prova sta in fondo al file e ci resta: da `#[cfg(test)] mod`
/// in giù non c'è testo che qualcuno mostri.
///
/// La prima stesura della guardia degli accenti cercava la stringa
/// `#[cfg(test)]` ovunque nel file. In `crates/lisi-telegram/src/tdlib/live.rs`
/// quella sequenza compare **dentro un commento** che la nomina fra apici — e
/// il taglio cadeva lì, lasciando fuori milletrecento righe di prodotto.
///
/// La seconda tagliava al primo attributo `#[cfg(test)]` ovunque fosse. In
/// `crates/lisi-app/src/lock.rs` quell'attributo stava su una funzione sola a
/// metà file, e da lì in giù la guardia **non guardava più nulla**: trecento
/// righe di prodotto con dentro tre frasi che un operatore legge.
///
/// È la TERZA volta che quella guardia si è accecata da sola, sempre nello
/// stesso modo. Ora il taglio cade solo dove l'attributo introduce davvero il
/// modulo di prova.
///
/// # Una chiamata non mostrata si toglie INTERA, non per riga
///
/// `rustfmt` manda a capo gli argomenti lunghi, e il testo di un `panic!`
/// finisce quasi sempre sulla riga DOPO la macro. Togliere la sola riga della
/// macro lascerebbe il testo dentro la guardia: si conta quindi il bilancio
/// delle parentesi e si toglie la chiamata fino alla sua chiusura. Le righe
/// tolte restano **vuote**, così che i numeri di riga restino veri.
pub fn prodotto_rust(testo: &str) -> String {
    let taglio = testo
        .lines()
        .scan(0usize, |consumati, riga| {
            let inizio = *consumati;
            *consumati += riga.len() + 1;
            Some((inizio, riga))
        })
        .collect::<Vec<(usize, &str)>>()
        .windows(2)
        .find(|coppia| match coppia {
            [(_, attributo), (_, seguente)] => {
                attributo.trim_start().starts_with("#[cfg(test)]") && introduce_un_modulo(seguente)
            }
            _ => false,
        })
        .and_then(|coppia| coppia.first().map(|(inizio, _)| *inizio));

    let prodotto = match taglio {
        Some(inizio) => testo.get(..inizio).unwrap_or(testo),
        None => testo,
    };

    togli_chiamate(prodotto, riga_non_mostrata)
}

/// Il sorgente con le chiamate indicate tolte **intere**, fino alla parentesi
/// che le chiude. Le righe tolte restano vuote, perché i numeri di riga
/// restino veri.
pub fn togli_chiamate(prodotto: &str, apre: impl Fn(&str) -> bool) -> String {
    let mut da_togliere = 0i32;
    prodotto
        .lines()
        .map(|riga| {
            let apre = apre(riga);
            if apre || da_togliere > 0 {
                da_togliere += i32::try_from(riga.matches('(').count()).unwrap_or(0);
                da_togliere -= i32::try_from(riga.matches(')').count()).unwrap_or(0);
                if da_togliere < 0 {
                    da_togliere = 0;
                }
                return "";
            }
            riga
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Il nome dell'elemento Rust che una riga apre, se ne apre uno.
///
/// Riconosce `fn nome`, `const NOME` e `static NOME`, con qualunque
/// visibilità davanti. È ciò che serve a sapere se un testo sta dentro una
/// funzione che restituisce un **dettaglio tecnico** (ADR-0117).
fn elemento_aperto(riga: &str) -> Option<String> {
    // Solo all'INIZIO della riga: `&'static str` in mezzo a un tipo non apre
    // niente, e leggerlo come un elemento chiamato `str` darebbe a ogni testo
    // seguente un contesto falso.
    let mut resto = riga.trim_start();
    for visibilita in ["pub(crate) ", "pub(super) ", "pub "] {
        if let Some(dopo) = resto.strip_prefix(visibilita) {
            resto = dopo;
            break;
        }
    }
    for qualificatore in ["const fn ", "async fn ", "unsafe fn "] {
        if let Some(dopo) = resto.strip_prefix(qualificatore) {
            resto = dopo;
            return nome_in_testa(resto);
        }
    }
    ["fn ", "const ", "static "]
        .iter()
        .find_map(|parola| resto.strip_prefix(parola))
        .and_then(nome_in_testa)
}

/// L'identificatore con cui comincia il testo, se comincia con uno.
fn nome_in_testa(testo: &str) -> Option<String> {
    let nome: String = testo
        .chars()
        .take_while(|c| c.is_alphanumeric() || *c == '_')
        .collect();
    (!nome.is_empty()).then_some(nome)
}

/// Il testo fra virgolette di un sorgente Rust, **anche quando va a capo**.
///
/// # Il buco che questa funzione esiste per chiudere
///
/// Una frase lunga si scrive con la continuazione, e la barra rovesciata a fine
/// riga la prosegue sulla successiva. Le righe di continuazione **non
/// contengono virgolette**: una guardia che spezzasse per riga vedrebbe la
/// prima e non le altre. È successo davvero, sul riquadro d'avviso della
/// schermata Account (UX-02).
///
/// # Che cosa questa funzione non sa fare, ed è dichiarato
///
/// Non riconosce le stringhe grezze (`r"…"`, `r#"…"#`): la sequenza `r"` la
/// vede come una virgoletta d'apertura normale. Nel prodotto non ce ne sono con
/// testo mostrato.
pub fn stringhe_rust(sorgente: &str) -> Vec<Mostrata> {
    let mut trovate = Vec::new();
    let mut dentro: Option<(usize, String, String)> = None;
    let mut contesto = String::new();
    // La riga precedente finiva, dentro una stringa, con la barra rovesciata.
    let mut continuazione = false;
    // Il rientro di questa riga va saltato: e' la riga dopo una continuazione.
    let mut salta_rientro = false;

    for (indice, riga) in sorgente.lines().enumerate() {
        let numero = indice + 1;
        let riga = if salta_rientro {
            salta_rientro = false;
            riga.trim_start()
        } else {
            riga
        };

        // Un commento fuori da una stringa non conta. Dentro una stringa, la
        // sequenza `//` e' testo e va tenuta: e' il caso di un URL mostrato.
        if dentro.is_none() && riga.trim_start().starts_with("//") {
            continue;
        }
        if dentro.is_none()
            && let Some(nome) = elemento_aperto(riga.split('"').next().unwrap_or(""))
        {
            contesto = nome;
        }

        let mut caratteri = riga.chars().peekable();
        while let Some(carattere) = caratteri.next() {
            match (&mut dentro, carattere) {
                // La barra rovesciata protegge il carattere seguente: dentro
                // una stringa `\"` non chiude nulla.
                (Some((_, accumulato, _)), '\\') => {
                    if let Some(protetto) = caratteri.next() {
                        match protetto {
                            // `\n`, `\r` e `\t` sono spazio bianco nel testo
                            // vero: accumularne la LETTERA incollerebbe due
                            // parole separate (DEC-231). Un a capo resta un a
                            // capo, perche' chiude una riga e la misura delle
                            // frasi lo deve vedere (ADR-0117).
                            'n' => accumulato.push('\n'),
                            'r' | 't' => accumulato.push(' '),
                            // `\u{e8}` e' una «è» scritta in ASCII. Lasciarla
                            // com'e' farebbe leggere alla guardia «u», «e8»:
                            // due parole che sullo schermo non ci sono, e una
                            // vera che la guardia non vedrebbe.
                            'u' if caratteri.peek() == Some(&'{') => {
                                caratteri.next();
                                let cifre: String =
                                    caratteri.by_ref().take_while(|c| *c != '}').collect();
                                if let Some(decodificato) = u32::from_str_radix(&cifre, 16)
                                    .ok()
                                    .and_then(char::from_u32)
                                {
                                    accumulato.push(decodificato);
                                }
                            }
                            altro => accumulato.push(altro),
                        }
                    } else {
                        // La barra a fine riga: la continuazione di Rust.
                        continuazione = true;
                    }
                }
                (Some((inizio, accumulato, dove)), '"') => {
                    trovate.push(Mostrata {
                        riga: *inizio,
                        testo: accumulato.clone(),
                        contesto: dove.clone(),
                        dettagli_tecnici: false,
                        elemento: String::new(),
                        istanza: 0,
                    });
                    dentro = None;
                }
                (Some((_, accumulato, _)), altro) => accumulato.push(altro),
                // Un carattere fra apici — `'"'`, `'\''` — non apre una
                // stringa. Senza questo ramo la virgoletta dentro `'"'`
                // rovesciava il conto delle coppie, e la guardia leggeva il
                // CODICE come testo mostrato e il testo come codice: in
                // `indicator.rs` e `stix.rs` era cosi' per centinaia di righe.
                // Un apice non seguito da un carattere e da un altro apice e'
                // una durata di vita (`'static`), e si lascia stare.
                (None, '\'') => {
                    let mut avanti = caratteri.clone();
                    match (avanti.next(), avanti.next()) {
                        (Some('\\'), _) => {
                            caratteri.next();
                            caratteri.next();
                            for chiuso in caratteri.by_ref() {
                                if chiuso == '\'' {
                                    break;
                                }
                            }
                        }
                        (Some(_), Some('\'')) => {
                            caratteri.next();
                            caratteri.next();
                        }
                        _ => {}
                    }
                }
                (None, '"') => dentro = Some((numero, String::new(), contesto.clone())),
                (None, _) => {}
            }
        }

        // Una stringa aperta prosegue sulla riga successiva, in uno di due modi,
        // e la guardia deve leggere cio' che Rust legge (ADR-0117):
        //
        // - con la barra a fine riga, Rust mangia l'a capo E il rientro della
        //   riga dopo: non si aggiunge nulla, e il rientro si salta;
        // - senza barra, l'a capo e il rientro FANNO PARTE della stringa: sullo
        //   schermo si va a capo a meta' frase. E' il difetto che la regola
        //   «a capo rotto» esiste per trovare, e va lasciato vedere.
        if let Some((_, accumulato, _)) = &mut dentro {
            if continuazione {
                salta_rientro = true;
            } else {
                accumulato.push('\n');
            }
        }
        continuazione = false;
    }

    trovate
}

/// Il testo fra virgolette di un file `.slint`, con la proprietà a cui è
/// assegnato e l'elemento che lo contiene.
///
/// # Perché i letterali uniti da `+` sono un testo solo
///
/// Perché sullo schermo sono una frase sola. L'interfaccia scrive le frasi
/// lunghe così:
///
/// ```text
/// text: "Rimuovere un account cancella anche la sua sessione "
///     + "Telegram dal disco: per rientrare servirà di nuovo "
///     + "numero e codice.";
/// ```
///
/// Una guardia che misura la lunghezza di una frase e la leggesse a pezzi
/// misurerebbe dei pezzi. Un'espressione in mezzo (`"a" + root.nome + "b"`)
/// invece separa: quel che sta in mezzo non è testo scritto qui.
///
/// # Che cosa questa funzione salta
///
/// I commenti di riga e di blocco, e il percorso di `@image-url(…)`, che è un
/// nome di file e non testo.
pub fn stringhe_slint(sorgente: &str) -> Vec<Mostrata> {
    let caratteri: Vec<char> = sorgente.chars().collect();
    let mut trovate: Vec<Mostrata> = Vec::new();
    // La pila degli elementi aperti: il nome che precede ogni `{`.
    let mut elementi: Vec<(String, usize)> = Vec::new();
    let mut istanze = 0usize;
    // L'ultimo identificatore letto, e l'ultima proprieta' (identificatore
    // seguito da `:`).
    let mut identificatore = String::new();
    let mut proprieta = String::new();
    // La proprieta' vale per la SOLA istruzione `nome: …;` in cui il testo
    // compare. Una stringa in una condizione — `if root.stato == "aperto":` —
    // o in una chiamata — `root.azione("riprendi")` — non ha proprieta': e'
    // un gettone confrontato dal codice, non un testo che qualcuno legge.
    let mut candidato: Option<String> = None;
    let mut a_inizio = true;
    let mut ultimo = '{';
    // Se l'ultimo segno significativo e' stato un `+` dopo un letterale: il
    // letterale seguente continua lo stesso testo.
    let mut continua = false;
    let mut riga = 1usize;
    let mut i = 0usize;

    while let Some(&carattere) = caratteri.get(i) {
        match carattere {
            '\n' => {
                riga += 1;
                i += 1;
            }
            '/' if caratteri.get(i + 1) == Some(&'/') => {
                while caratteri.get(i).is_some_and(|c| *c != '\n') {
                    i += 1;
                }
            }
            '/' if caratteri.get(i + 1) == Some(&'*') => {
                i += 2;
                while i < caratteri.len()
                    && !(caratteri.get(i) == Some(&'*') && caratteri.get(i + 1) == Some(&'/'))
                {
                    if caratteri.get(i) == Some(&'\n') {
                        riga += 1;
                    }
                    i += 1;
                }
                i += 2;
            }
            '"' => {
                let inizio = riga;
                let mut testo = String::new();
                i += 1;
                while let Some(&dentro) = caratteri.get(i) {
                    match dentro {
                        '\\' => {
                            match caratteri.get(i + 1) {
                                Some('n') => testo.push('\n'),
                                Some('r' | 't') => testo.push(' '),
                                // `\u{2014}`: anche Slint scrive i caratteri
                                // cosi', e la guardia deve leggere il
                                // carattere, non «u» seguita da cifre.
                                Some('u') if caratteri.get(i + 2) == Some(&'{') => {
                                    let cifre: String = caratteri
                                        .get(i + 3..)
                                        .unwrap_or(&[])
                                        .iter()
                                        .take_while(|c| **c != '}')
                                        .collect();
                                    if let Some(decodificato) = u32::from_str_radix(&cifre, 16)
                                        .ok()
                                        .and_then(char::from_u32)
                                    {
                                        testo.push(decodificato);
                                    }
                                    // `u`, `{`, le cifre e `}`: la barra la
                                    // salta il `+= 2` qui sotto.
                                    i += 2 + cifre.chars().count();
                                }
                                Some(altro) => testo.push(*altro),
                                None => {}
                            }
                            i += 2;
                        }
                        '"' => {
                            i += 1;
                            break;
                        }
                        altro => {
                            if altro == '\n' {
                                riga += 1;
                            }
                            testo.push(altro);
                            i += 1;
                        }
                    }
                }
                // `@image-url("…")`: un percorso, non testo.
                candidato = None;
                a_inizio = false;
                ultimo = '"';
                // `@image-url("…")` e `import { … } from "…"`: un percorso,
                // non testo.
                if identificatore == "image-url" || identificatore == "from" {
                    continua = false;
                    continue;
                }
                let nei_dettagli = elementi.iter().any(|(nome, _)| nome == "DettagliTecnici")
                    || (elementi
                        .last()
                        .is_some_and(|(nome, _)| nome == "AvvertenzaDiSicurezza")
                        && proprieta == "dettaglio");
                let (elemento, istanza) = elementi.last().cloned().unwrap_or_default();
                match trovate.last_mut() {
                    Some(precedente) if continua => precedente.testo.push_str(&testo),
                    _ => trovate.push(Mostrata {
                        riga: inizio,
                        testo,
                        contesto: proprieta.clone(),
                        dettagli_tecnici: nei_dettagli,
                        elemento,
                        istanza,
                    }),
                }
                continua = false;
                // Dopo un letterale si guarda avanti: se il prossimo segno
                // significativo e' `+` seguito da un letterale, il testo
                // continua.
                let mut j = i;
                while caratteri.get(j).is_some_and(|c| c.is_whitespace()) {
                    j += 1;
                }
                if caratteri.get(j) == Some(&'+') {
                    let mut k = j + 1;
                    while caratteri.get(k).is_some_and(|c| c.is_whitespace()) {
                        k += 1;
                    }
                    if caratteri.get(k) == Some(&'"') {
                        // Si consumano spazi e `+`, contando gli a capo.
                        for c in caratteri.get(i..k).unwrap_or(&[]) {
                            if *c == '\n' {
                                riga += 1;
                            }
                        }
                        i = k;
                        continua = true;
                    }
                }
            }
            '{' => {
                istanze += 1;
                elementi.push((identificatore.clone(), istanze));
                proprieta.clear();
                candidato = None;
                a_inizio = true;
                ultimo = '{';
                i += 1;
            }
            '}' | ';' => {
                if carattere == '}' {
                    elementi.pop();
                }
                proprieta.clear();
                candidato = None;
                a_inizio = true;
                ultimo = carattere;
                i += 1;
            }
            // `nome := Elemento {` da' un nome a un elemento: non e' una
            // proprieta'. Solo `nome:` in testa a un'istruzione lo e'.
            ':' if caratteri.get(i + 1) != Some(&'=') => {
                if let Some(nome) = candidato.take() {
                    proprieta = nome;
                }
                a_inizio = false;
                ultimo = ':';
                i += 1;
            }
            c if c.is_alphanumeric() || c == '-' || c == '_' => {
                let mut parola = String::new();
                while let Some(&c) = caratteri.get(i) {
                    if c.is_alphanumeric() || c == '-' || c == '_' {
                        parola.push(c);
                        i += 1;
                    } else {
                        break;
                    }
                }
                // Il nome di una proprieta' sta in testa all'istruzione, o
                // subito dopo il tipo di una dichiarazione:
                // `in property <string> nome: "…";`.
                candidato = (a_inizio || ultimo == '>').then(|| parola.clone());
                a_inizio = false;
                ultimo = 'a';
                identificatore = parola;
            }
            c if c.is_whitespace() => {
                i += 1;
            }
            altro => {
                candidato = None;
                a_inizio = false;
                ultimo = altro;
                i += 1;
            }
        }
    }

    trovate
}

/// Se l'interfaccia assegna `testo` alla proprietà, scritto per esteso o
/// fatto tradurre con `@tr` (I18N-01, ADR-0197): le prove che cercano una
/// scritta nel sorgente la trovano in entrambe le forme.
pub fn assegna(sorgente: &str, proprieta: &str, testo: &str) -> bool {
    sorgente.contains(&format!("{proprieta}: \"{testo}\";"))
        || sorgente.contains(&format!("{proprieta}: @tr(\"{testo}\");"))
}

/// Tutto il testo mostrato dall'interfaccia `.slint`, con il file di origine.
pub fn testo_slint() -> Vec<(&'static str, Mostrata)> {
    SCHERMATE
        .iter()
        .flat_map(|(nome, sorgente)| {
            stringhe_slint(sorgente)
                .into_iter()
                .map(move |mostrata| (*nome, mostrata))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{elemento_aperto, stringhe_rust, stringhe_slint};

    #[test]
    fn i_letterali_uniti_da_piu_sono_un_testo_solo() {
        let sorgente = "Text {\n    text: \"Prima meta' \"\n        + \"seconda meta'.\";\n}\n";
        let trovate = stringhe_slint(sorgente);
        assert_eq!(trovate.len(), 1, "{trovate:?}");
        assert_eq!(trovate[0].testo, "Prima meta' seconda meta'.");
        assert_eq!(trovate[0].contesto, "text");
        assert_eq!(trovate[0].riga, 2);
    }

    #[test]
    fn slint_scrive_i_caratteri_anche_come_codice() {
        let trovate = stringhe_slint("Text { text: \"Account\\u{2014}fine \\\"citato\\\"\"; }");
        assert_eq!(trovate[0].testo, "Account\u{2014}fine \"citato\"");
    }

    /// **La proprietà vale per la sola istruzione in cui il testo compare.**
    #[test]
    fn una_stringa_in_una_condizione_non_ha_proprieta() {
        let sorgente = "import { A } from \"altro.slint\";\nText {\n  wrap: word-wrap;\n  in property <string> nome: \"Mario\";\n}\nif root.stato == \"aperto\": Text {\n  text: root.ok ? \"Sì\" : \"No\";\n  clicked => { root.azione(\"riprendi\"); }\n}\nbox := Rectangle { }\n";
        let trovate = stringhe_slint(sorgente);
        let coppie: Vec<(&str, &str)> = trovate
            .iter()
            .map(|m| (m.contesto.as_str(), m.testo.as_str()))
            .collect();
        assert_eq!(
            coppie,
            vec![
                ("nome", "Mario"),
                ("", "aperto"),
                ("text", "Sì"),
                ("text", "No"),
                ("", "riprendi")
            ]
        );
    }

    #[test]
    fn un_espressione_in_mezzo_separa() {
        let sorgente = "Text { text: \"Nome: \" + root.nome + \" fine\"; }";
        let trovate = stringhe_slint(sorgente);
        assert_eq!(trovate.len(), 2, "{trovate:?}");
    }

    #[test]
    fn i_commenti_slint_non_sono_testo() {
        let sorgente = "// \"no\"\n/* \"nemmeno\" */\nText { text: \"si\"; }";
        let trovate = stringhe_slint(sorgente);
        assert_eq!(trovate.len(), 1);
        assert_eq!(trovate[0].testo, "si");
        assert_eq!(trovate[0].riga, 3);
    }

    #[test]
    fn il_testo_dentro_i_dettagli_tecnici_lo_sa() {
        let sorgente = "VerticalLayout {\n  Text { text: \"sopra\"; }\n  DettagliTecnici {\n    testo: \"sotto\";\n  }\n}";
        let trovate = stringhe_slint(sorgente);
        assert_eq!(trovate.len(), 2);
        assert!(!trovate[0].dettagli_tecnici);
        assert!(trovate[1].dettagli_tecnici);
        assert_eq!(trovate[1].contesto, "testo");
    }

    #[test]
    fn un_percorso_d_immagine_non_e_testo() {
        let sorgente = "Image { source: @image-url(\"../assets/logo.png\"); }";
        assert!(stringhe_slint(sorgente).is_empty());
    }

    #[test]
    fn il_contesto_rust_e_la_funzione_che_contiene_il_testo() {
        let sorgente = "pub fn technical_detail(&self) -> &str {\n    \"dettaglio\"\n}\nconst AVVISO: &str = \"avviso\";\n";
        let trovate = stringhe_rust(sorgente);
        assert_eq!(trovate.len(), 2);
        assert_eq!(trovate[0].contesto, "technical_detail");
        assert_eq!(trovate[1].contesto, "AVVISO");
    }

    /// **La guardia legge una stringa su più righe come la legge Rust.**
    ///
    /// Con la barra a fine riga, l'a capo e il rientro spariscono; senza,
    /// restano nella stringa e lo schermo va a capo a metà frase.
    #[test]
    fn la_continuazione_si_legge_come_la_legge_rust() {
        let con_barra = stringhe_rust("const A: &str = \"prima \\\n        seconda\";\n");
        assert_eq!(con_barra[0].testo, "prima seconda");

        let con_a_capo = stringhe_rust("const A: &str = \"prima\\n\\\n        seconda\";\n");
        assert_eq!(con_a_capo[0].testo, "prima\nseconda");

        let senza_barra = stringhe_rust("const A: &str = \"prima\n        seconda\";\n");
        assert_eq!(senza_barra[0].testo, "prima\n        seconda");
    }

    #[test]
    fn una_lettera_scritta_in_ascii_si_legge_come_lettera() {
        let trovate = stringhe_rust("const A: &str = \"Perch\\u{e9} \\u{c8} cos\\u{ec}\";\n");
        assert_eq!(trovate.len(), 1);
        assert_eq!(trovate[0].testo, "Perché È così");
    }

    /// **Un apostrofo scritto come `\u{27}` è un apostrofo.**
    ///
    /// Fino a PR-01 l'estrattore lo leggeva come «u{27}», e la guardia degli
    /// accenti era verde mentre la schermata della somiglianza scriveva «Il
    /// piu' corto e' interamente contenuto nell'altro». Il difetto l'ha trovato
    /// il primo estrattore che decodificava la sequenza.
    #[test]
    fn un_apostrofo_scritto_in_ascii_non_nasconde_un_accento_mancante() {
        let trovate = stringhe_rust("const A: &str = \"Il piu\\u{27} corto e\\u{27} qui\";\n");
        assert_eq!(trovate[0].testo, "Il piu' corto e' qui");
    }

    /// **Una virgoletta fra apici non apre una stringa.**
    #[test]
    fn un_carattere_fra_apici_non_apre_una_stringa() {
        let sorgente = "fn f(c: char) -> bool {\n    c == '\"' || c == '\\'' || c == '\\\\'\n}\nconst T: &'static str = \"testo\";\nfn g<'a>(x: &'a str) {}\n";
        let trovate = stringhe_rust(sorgente);
        assert_eq!(trovate.len(), 1, "{trovate:?}");
        assert_eq!(trovate[0].testo, "testo");
    }

    #[test]
    fn il_dettaglio_di_un_avvertenza_e_un_dettaglio_tecnico() {
        let sorgente = "AvvertenzaDiSicurezza {\n  codice: \"X-01\";\n  testo: \"sopra\";\n  dettaglio: \"sotto\";\n}\nText { text: \"fuori\"; }";
        let trovate = stringhe_slint(sorgente);
        assert_eq!(trovate.len(), 4, "{trovate:?}");
        assert!(!trovate[1].dettagli_tecnici);
        assert!(trovate[2].dettagli_tecnici);
        assert!(!trovate[3].dettagli_tecnici);
        assert_eq!(trovate[0].istanza, trovate[2].istanza);
        assert_ne!(trovate[2].istanza, trovate[3].istanza);
        assert_eq!(trovate[0].elemento, "AvvertenzaDiSicurezza");
    }

    #[test]
    fn gli_elementi_rust_si_riconoscono_con_qualunque_visibilita() {
        assert_eq!(
            elemento_aperto("    pub const fn label(self) -> &str {").as_deref(),
            Some("label")
        );
        assert_eq!(
            elemento_aperto("pub(crate) const NOME: &str ="),
            Some(String::from("NOME"))
        );
        assert_eq!(
            elemento_aperto("static TESTO: &str ="),
            Some(String::from("TESTO"))
        );
        assert_eq!(elemento_aperto("let x = 3;"), None);
        assert_eq!(elemento_aperto("    let x: &'static str = \"a\";"), None);
    }
}
