//! Gli accenti nel testo che l'operatore legge.
//!
//! # La convenzione, e dove finisce
//!
//! Questo repository scrive i **commenti** in ASCII — `perche'`, `attivita'`,
//! `e'` — ed è una convenzione di sorgente che resta (DEC-175). Vale per chi
//! legge il codice.
//!
//! Non vale per chi legge lo **schermo**. DEC-175 aveva corretto le stringhe
//! che finiscono nel documento, perché «una relazione che un ufficio consegna
//! scritta con "attivita'" e "e'" è italiano sbagliato su carta intestata», e
//! aveva lasciato fuori l'interfaccia dichiarandolo: *«è una superficie diversa,
//! con la propria coerenza, e cambiarla è una decisione a sé»*.
//!
//! # Perché quella coerenza non esisteva
//!
//! La schermata **Guida** prende il testo da `lisi-core::guide`, dove gli
//! accenti sono scritti correttamente, e li disegna correttamente: «Che cos'è»,
//! «già», «può», «metà», «È la condizione».
//!
//! Nella **stessa finestra**, in alto a destra, l'intestazione scriveva
//! «Modalita' amministratore».
//!
//! Non era una convenzione: erano due convenzioni sullo stesso schermo. La
//! decisione è stata presa in DEC-231.
//!
//! # Che cosa questa guardia sorveglia, e che cosa no
//!
//! Solo il testo **fra virgolette** nei file dell'interfaccia, e solo fuori dai
//! commenti. Un commento può continuare a scrivere `e'` per sempre: nessun
//! operatore lo legge.

use crate::surface_text::SCHERMATE;

/// Le forme che non devono comparire nel testo mostrato, con la loro correzione.
///
/// # Perché un elenco e non una regola generale
///
/// Una regola del tipo «vocale seguita da apostrofo» colpirebbe anche
/// `dell'`, `un'`, `l'`, che sono elisioni corrette e frequentissime. Una
/// guardia che dà falsi allarmi viene disattivata dal primo che ha fretta, e
/// allora non sorveglia più niente.
const SBAGLIATE: [(&str, &str); 26] = [
    ("e'", "è"),
    ("idoneita'", "idoneità"),
    ("piu'", "più"),
    ("gia'", "già"),
    ("cio'", "ciò"),
    ("puo'", "può"),
    ("ne'", "né"),
    ("se'", "sé"),
    ("pie'", "piè"),
    ("cosi'", "così"),
    ("cioe'", "cioè"),
    ("perche'", "perché"),
    ("finche'", "finché"),
    ("poiche'", "poiché"),
    ("modalita'", "modalità"),
    ("attivita'", "attività"),
    ("gravita'", "gravità"),
    ("identita'", "identità"),
    ("capacita'", "capacità"),
    ("proprieta'", "proprietà"),
    ("formalita'", "formalità"),
    ("inattivita'", "inattività"),
    ("verra'", "verrà"),
    ("sara'", "sarà"),
    ("lascera'", "lascerà"),
    ("comparira'", "comparirà"),
];

/// Le due terminazioni **produttive** dell'italiano accentato, con la loro
/// correzione.
///
/// # Perché un elenco di forme non basta, e come si è visto
///
/// `SBAGLIATE` è un elenco chiuso, e un elenco chiuso copre le parole che
/// qualcuno ha già incontrato. La nota di rilascio di un dizionario
/// tematico scriveva **«Rientrera' quando sarà scritto come formula»** —
/// `sarà` giusto e `Rientrera'` sbagliato **nella stessa frase** — e la guardia
/// era verde, perché `rientrera'` nell'elenco non c'era e non poteva esserci:
/// i verbi italiani al futuro sono una classe **aperta**.
///
/// Due terminazioni la chiudono, e sono regole di grammatica, non elenchi:
///
/// - **`-rà`**: la terza persona del futuro semplice finisce sempre così.
///   `sarà`, `verrà`, `dovrà`, `potrà`, `rientrerà`, `occorrerà`. Non esiste in
///   italiano un'elisione che produca `ra'`;
/// - **`-tà`**: i nomi astratti in `-tà`. `attività`, `modalità`, `identità`,
///   `possibilità`, `città`, `età`.
///
/// # L'unica eccezione vera, e perché è una sola
///
/// `sta'` è l'imperativo di *stare* e finisce davvero con l'apostrofo, come
/// `da'`, `fa'`, `va'`, `di'` e `po'` — ma di questi soltanto `sta'` termina in
/// `ta'`, quindi soltanto lui va dichiarato.
///
/// **Le elisioni non hanno bisogno di eccezioni**: `dell'`, `un'`, `l'`,
/// `nell'` sono seguite da una lettera, e una regola che guarda la fine di una
/// parola non le tocca mai. È la stessa ragione per cui l'elenco chiuso non le
/// segnalava.
const TERMINAZIONI_PRODUTTIVE: [(&str, char); 2] = [("ra'", 'à'), ("ta'", 'à')];

/// Le parole che finiscono davvero con l'apostrofo e non sono un errore.
const APOSTROFO_LEGITTIMO: [&str; 1] = ["sta'"];

/// Le parole del testo che finiscono con una terminazione accentata scritta in
/// ASCII, con la forma corretta.
///
/// Una parola è la sequenza di lettere che precede l'apostrofo: `Rientrera'`
/// diventa `Rientrerà`. Il confronto ignora le maiuscole, la correzione le
/// conserva.
fn terminazioni_senza_accento(testo: &str) -> Vec<(String, String)> {
    let mut trovate = Vec::new();

    for parola in testo.split(|c: char| !c.is_alphanumeric() && c != '\'') {
        if !parola.ends_with('\'') {
            continue;
        }
        let minuscola = parola.to_lowercase();
        if APOSTROFO_LEGITTIMO.contains(&minuscola.as_str()) {
            continue;
        }

        for (terminazione, accentata) in TERMINAZIONI_PRODUTTIVE {
            if !minuscola.ends_with(terminazione) {
                continue;
            }
            // Serve una radice: `ta'` da sola non e' una parola, e `e'` lo
            // gestisce gia' l'elenco chiuso con la propria correzione.
            let Some(radice) = parola.get(..parola.len() - terminazione.len()) else {
                continue;
            };
            if radice.len() < 2 {
                continue;
            }

            let mut corretta = String::from(radice);
            corretta.push(terminazione.as_bytes()[0].into());
            corretta.push(accentata);
            trovate.push((String::from(parola), corretta));
            break;
        }
    }

    trovate
}

/// Il testo fra virgolette di una riga, se la riga non è un commento.
///
/// # Perché i commenti si saltano per primi
///
/// Alcuni commenti dell'interfaccia contengono virgolette **spaiate** — citano
/// una parola sola fra virgolette su una riga e la chiudono sulla successiva.
/// Contarle insieme al codice sfaserebbe le coppie, e la guardia leggerebbe
/// come «testo mostrato» pezzi di commento e viceversa.
fn stringhe_mostrate(riga: &str) -> Vec<&str> {
    if riga.trim_start().starts_with("//") {
        return Vec::new();
    }
    riga.split('"').skip(1).step_by(2).collect()
}

/// Se il termine compare nel testo come **parola intera**.
///
/// `e'` dentro `perche'` non è un `e'`: senza questo controllo la guardia
/// segnalerebbe due volte la stessa cosa e la correzione suggerita sarebbe
/// quella sbagliata.
fn parola_intera(testo: &str, termine: &str) -> bool {
    let byte = testo.as_bytes();
    let mut da = 0;
    while let Some(posizione) = testo[da..].find(termine) {
        let inizio = da + posizione;
        let prima_e_lettera = inizio
            .checked_sub(1)
            .is_some_and(|precedente| byte[precedente].is_ascii_alphanumeric());
        if !prima_e_lettera {
            return true;
        }
        da = inizio + termine.len();
    }
    false
}

#[cfg(test)]
mod tests {
    use super::{
        SBAGLIATE, SCHERMATE, parola_intera, stringhe_mostrate, terminazioni_senza_accento,
    };
    use crate::surface_text::{radice, sorgenti_del_prodotto, stringhe_rust};

    /// **Il testo mostrato all'operatore usa gli accenti italiani.**
    ///
    /// # Il difetto che questa prova impedisce
    ///
    /// «Modalita' amministratore» compariva nell'intestazione di **tutte e
    /// sedici** le schermate, accanto a una Guida che scriveva «Che cos'è» e
    /// «già» correttamente. Nessuna prova se ne accorgeva, e nessuna avrebbe
    /// potuto: il prodotto funzionava.
    ///
    /// Se ne accorge chi lo usa, e in un ufficio che produce atti l'italiano
    /// sbagliato sullo schermo è la stessa cosa dell'italiano sbagliato sulla
    /// carta intestata (DEC-175, DEC-231).
    #[test]
    fn il_testo_mostrato_usa_gli_accenti_italiani() {
        let mut trovati = Vec::new();

        for (nome, sorgente) in SCHERMATE {
            for (numero, riga) in sorgente.lines().enumerate() {
                for mostrata in stringhe_mostrate(riga) {
                    // Il confronto ignora le maiuscole, e non e' un dettaglio:
                    // il difetto che ha fatto nascere questa guardia era
                    // «Modalita'» con la maiuscola, e un elenco di sole forme
                    // minuscole lo avrebbe mancato. Il controllo negativo lo ha
                    // scoperto: la guardia era verde a vuoto.
                    let minuscola = mostrata.to_lowercase();
                    for (sbagliata, giusta) in SBAGLIATE {
                        if parola_intera(&minuscola, sbagliata) {
                            trovati.push(format!(
                                "{nome}:{}: «{sbagliata}» va scritto «{giusta}» — {mostrata}",
                                numero + 1
                            ));
                        }
                    }
                    for (sbagliata, giusta) in terminazioni_senza_accento(mostrata) {
                        trovati.push(format!(
                            "{nome}:{}: «{sbagliata}» va scritto «{giusta}» — {mostrata}",
                            numero + 1
                        ));
                    }
                }
            }
        }

        assert!(
            trovati.is_empty(),
            "il testo mostrato all'operatore contiene {} forme senza accento:\n{}",
            trovati.len(),
            trovati.join("\n")
        );
    }

    /// **Anche il testo che arriva dal Rust usa gli accenti italiani.**
    ///
    /// # Il difetto che questa prova impedisce
    ///
    /// La correzione dell'interfaccia era completa, la guardia sulle schermate
    /// era verde, e la finestra continuava a mostrare «Modalita' amministratore»
    /// in alto a destra, su **tutte e sedici** le schermate.
    ///
    /// Il testo non veniva dal file dell'interfaccia: veniva da `Role::label`,
    /// in `lisi-core`. Il valore scritto nel `.slint` era solo il predefinito, e
    /// Rust lo sostituiva all'avvio.
    ///
    /// Se ne è accorto **chi ha guardato la schermata**, non una prova. Questa
    /// esiste perché la prossima volta se ne accorga una prova.
    ///
    /// # E la seconda volta se ne è accorto di nuovo chi ha guardato
    ///
    /// La prova esisteva, era verde, e la schermata Account continuava a
    /// scrivere «non **puo'** collegarsi». Guardava solo dentro sei funzioni, e
    /// quel testo è una costante di modulo. Vedere `MACRO_NON_MOSTRATE` per la
    /// regola rovesciata che ne è seguita (UX-02).
    #[test]
    fn anche_il_testo_che_viene_dal_rust_usa_gli_accenti() {
        // L'estrazione sta in `crate::surface_text`, condivisa con la guardia
        // del linguaggio: le tre volte in cui questa guardia si e' accecata da
        // sola sono raccontate li', accanto al codice che le corregge.
        let sorgenti = sorgenti_del_prodotto();
        assert!(
            sorgenti.len() > 50,
            "trovati solo {} sorgenti: la guardia non sta percorrendo il prodotto",
            sorgenti.len()
        );

        let mut trovati = Vec::new();
        for (percorso, mostrabile) in &sorgenti {
            // Questo file contiene le forme sbagliate come DATI: sono l'elenco
            // che la guardia cerca, e i suoi casi di prova. Guardarsi dentro
            // significherebbe trovarsi sempre in difetto.
            if percorso.ends_with("accents_guard.rs") {
                continue;
            }

            for mostrata in stringhe_rust(mostrabile) {
                let minuscola = mostrata.testo.to_lowercase();
                for (sbagliata, giusta) in SBAGLIATE {
                    if parola_intera(&minuscola, sbagliata) {
                        trovati.push(format!(
                            "{}:{}: «{sbagliata}» va scritto «{giusta}» — {}",
                            percorso.display(),
                            mostrata.riga,
                            mostrata.testo
                        ));
                    }
                }
                for (sbagliata, giusta) in terminazioni_senza_accento(&mostrata.testo) {
                    trovati.push(format!(
                        "{}:{}: «{sbagliata}» va scritto «{giusta}» — {}",
                        percorso.display(),
                        mostrata.riga,
                        mostrata.testo
                    ));
                }
            }
        }

        assert!(
            trovati.is_empty(),
            "il testo mostrato che arriva dal Rust contiene {} forme senza accento:\n{}",
            trovati.len(),
            trovati.join("\n")
        );
    }

    /// **Anche i dizionari forniti con il prodotto usano gli accenti.**
    ///
    /// # Il difetto che questa prova impedisce
    ///
    /// La schermata Dizionari mostra la **descrizione** di ogni dizionario, e
    /// quella del Contesto riduttivo diceva «**Piu'** termini positivi si
    /// aggiungono, **piu'** questo dizionario deve crescere».
    ///
    /// Il testo non stava in un sorgente Rust né in un file di interfaccia:
    /// stava in `assets/dictionaries/*.json`, che nessuna guardia guardava. È lo
    /// stesso difetto di due gradini più su — una guardia verde perché cerca
    /// dove il difetto non è.
    ///
    /// # Che cosa si controlla, e che cosa no
    ///
    /// Si controllano **`description` e le note dei termini**: sono prosa, e la
    /// schermata le disegna.
    ///
    /// **Non** si controlla `text`, che è il termine cercato. Correggere un
    /// termine cambierebbe **che cosa il dizionario riscontra**, e non è una
    /// questione di ortografia: se una fonte scrive `attivita'` senza accento,
    /// il termine senza accento è quello che serve a trovarla.
    #[test]
    fn anche_i_dizionari_forniti_usano_gli_accenti() {
        // I dizionari operativi stanno soltanto nell'archivio, quelli d'esempio
        // anche nella copia pubblica (ADR-0210): si leggono le cartelle che ci
        // sono, e la soglia dice quanti se ne devono trovare.
        let mut voci = Vec::new();
        for nome in ["dictionaries", "dizionari-esempio"] {
            if let Ok(lette) = std::fs::read_dir(radice().join("assets").join(nome)) {
                voci.extend(lette.flatten());
            }
        }

        let mut letti = 0usize;
        let mut trovati = Vec::new();

        for voce in voci {
            let percorso = voce.path();
            if !percorso.extension().is_some_and(|e| e == "json") {
                continue;
            }
            let Ok(testo) = std::fs::read_to_string(&percorso) else {
                continue;
            };
            letti += 1;

            for (numero, riga) in testo.lines().enumerate() {
                let campo = riga.trim_start();
                // Solo la prosa mostrata: la descrizione del dizionario, la nota
                // del termine, la nota di rilascio della versione.
                let e_prosa = campo.starts_with("\"description\"")
                    || campo.starts_with("\"note\"")
                    || campo.starts_with("\"category\"");
                if !e_prosa {
                    continue;
                }

                for mostrata in stringhe_mostrate(riga).iter().skip(1) {
                    let minuscola = mostrata.to_lowercase();
                    for (sbagliata, giusta) in SBAGLIATE {
                        if parola_intera(&minuscola, sbagliata) {
                            trovati.push(format!(
                                "{}:{}: «{sbagliata}» va scritto «{giusta}» — {mostrata}",
                                percorso.display(),
                                numero + 1
                            ));
                        }
                    }
                    for (sbagliata, giusta) in terminazioni_senza_accento(mostrata) {
                        trovati.push(format!(
                            "{}:{}: «{sbagliata}» va scritto «{giusta}» — {mostrata}",
                            percorso.display(),
                            numero + 1
                        ));
                    }
                }
            }
        }

        assert!(
            letti >= 2,
            "la guardia ha letto solo {letti} dizionari: non sta guardando quelli forniti"
        );
        assert!(
            trovati.is_empty(),
            "i dizionari forniti contengono {} forme senza accento nel testo mostrato:\n{}",
            trovati.len(),
            trovati.join("\n")
        );
    }
    /// **La guardia sta davvero guardando le schermate.**
    ///
    /// Una guardia che leggesse un file vuoto sarebbe verde per sempre. E' la
    /// forma di difetto gia' vista due volte in questo progetto: una prova che
    /// non misura nulla e non lo dice.
    #[test]
    fn la_guardia_legge_davvero_le_schermate() {
        let righe: usize = SCHERMATE
            .iter()
            .map(|(_, sorgente)| sorgente.lines().count())
            .sum();
        assert!(
            righe > 5_000,
            "la guardia vede solo {righe} righe: non sta leggendo l'interfaccia"
        );

        let mostrate: usize = SCHERMATE
            .iter()
            .flat_map(|(_, sorgente)| sorgente.lines())
            .map(|riga| stringhe_mostrate(riga).len())
            .sum();
        assert!(
            mostrate > 500,
            "la guardia trova solo {mostrate} stringhe mostrate: l'estrazione non funziona"
        );
    }

    /// **Un commento puo' continuare a scrivere in ASCII.**
    ///
    /// La convenzione di sorgente resta (DEC-175): vale per chi legge il
    /// codice. Una guardia che la vietasse anche li' chiederebbe di riscrivere
    /// migliaia di righe di commento senza che nessun operatore ne veda una.
    #[test]
    fn i_commenti_restano_liberi_di_usare_l_ascii() {
        assert!(
            stringhe_mostrate("    // questo e' un commento con \"virgolette\"").is_empty(),
            "un commento non deve essere trattato come testo mostrato"
        );
        assert_eq!(
            stringhe_mostrate("        text: \"Questo si vede\";"),
            vec!["Questo si vede"]
        );
    }

    /// **«e'» dentro «perche'» non e' un «e'».**
    ///
    /// Senza questo controllo la guardia segnalerebbe due volte la stessa
    /// parola, e la correzione suggerita sarebbe quella sbagliata: «perchè»
    /// invece di «perché».
    #[test]
    fn un_termine_dentro_un_altro_non_conta() {
        assert!(!parola_intera("perche'", "e'"));
        assert!(parola_intera("non e' vero", "e'"));
        assert!(parola_intera("e' cosi'", "e'"));
        assert!(!parola_intera("dell'ufficio", "e'"));
    }

    /// **Una stringa Rust che va a capo si legge per intero.**
    ///
    /// # Il difetto che questa prova impedisce
    ///
    /// Le righe di continuazione non contengono virgolette. Una guardia che
    /// spezzasse per riga leggerebbe la prima e non le altre, e su questo esatto
    /// testo — il riquadro d'avviso della schermata Account — `modalita'` stava
    /// sulla terza riga di una frase di tre (UX-02).
    #[test]
    fn una_stringa_che_va_a_capo_si_legge_intera() {
        let sorgente = "pub const A: &str = \"prima riga \\\n    seconda con modalita' dentro\";";
        let trovate = stringhe_rust(sorgente);

        assert_eq!(trovate.len(), 1, "e' una stringa sola: {trovate:?}");
        let Some(prima) = trovate.first() else {
            panic!("la stringa deve essere stata trovata");
        };
        assert_eq!(
            prima.riga, 1,
            "la riga e' quella in cui la stringa COMINCIA"
        );
        assert!(
            parola_intera(&prima.testo.to_lowercase(), "modalita'"),
            "la forma sulla riga di continuazione deve essere vista: «{}»",
            prima.testo
        );
    }

    /// **`\n` non diventa la lettera «n», e non fabbrica un «ne'».**
    ///
    /// # Il falso allarme che questa prova impedisce
    ///
    /// Accumulare la lettera dell'escape incollerebbe due parole separate. Un
    /// `\n` seguito da «e' » produrrebbe «ne' », che la guardia segnalerebbe
    /// come un «ne'» da accentare — su un testo che è già corretto.
    ///
    /// Una guardia che dà falsi allarmi viene disattivata dal primo che ha
    /// fretta: il falso allarme è un difetto quanto il mancato allarme
    /// (DEC-231).
    #[test]
    fn un_a_capo_non_incolla_due_parole() {
        let sorgente = "let a = \"riga\\ne' vero\";";
        let trovate = stringhe_rust(sorgente);

        let Some(prima) = trovate.first() else {
            panic!("la stringa deve essere stata trovata");
        };
        // Dal 2026-09-25 l'a capo resta un a capo (ADR-0117): e' spazio
        // bianco come prima, e separa le parole come prima.
        assert_eq!(
            prima.testo, "riga\ne' vero",
            "l'a capo deve separare le parole"
        );
        assert!(
            !parola_intera(&prima.testo.to_lowercase(), "ne'"),
            "«{}» non contiene alcun «ne'»",
            prima.testo
        );
        assert!(
            parola_intera(&prima.testo.to_lowercase(), "e'"),
            "il vero «e'» deve restare visibile"
        );
    }

    /// **Le due regole produttive coprono ciò che l'elenco non può.**
    ///
    /// `rientrera'` non era nell'elenco e non poteva esserci: i verbi italiani
    /// al futuro sono una classe aperta. La prova fissa anche l'altra metà —
    /// che le elisioni **non** vengano segnalate — perché una regola che
    /// gridasse al lupo su `dell'` verrebbe disattivata subito.
    #[test]
    fn le_terminazioni_produttive_trovano_cio_che_un_elenco_non_puo() {
        let trovate = terminazioni_senza_accento("Rientrera' quando la citta' sara' pronta");
        let forme: Vec<&str> = trovate
            .iter()
            .map(|(sbagliata, _)| sbagliata.as_str())
            .collect();
        assert!(
            forme.contains(&"Rientrera'"),
            "il futuro deve essere visto: {forme:?}"
        );
        assert!(
            forme.contains(&"citta'"),
            "il nome in -ta' deve essere visto: {forme:?}"
        );

        let corrette: Vec<&str> = trovate.iter().map(|(_, giusta)| giusta.as_str()).collect();
        assert!(
            corrette.contains(&"Rientrerà"),
            "la maiuscola si conserva: {corrette:?}"
        );

        assert!(
            terminazioni_senza_accento("l'archivio dell'ufficio, un'altra fonte nell'atto")
                .is_empty(),
            "le elisioni italiane non sono errori"
        );
        assert!(
            terminazioni_senza_accento("sta' fermo").is_empty(),
            "«sta'» e' l'imperativo di stare, non un errore"
        );
    }

    /// **Le maiuscole non sfuggono alla guardia.**
    ///
    /// # Il buco che il controllo negativo ha trovato
    ///
    /// La prima versione di questa guardia confrontava solo forme minuscole. Il
    /// difetto che l'ha fatta nascere era «Modalita' amministratore», con la
    /// maiuscola, e la guardia lo mancava: era **verde a vuoto**, che e' peggio
    /// di non averla.
    #[test]
    fn una_maiuscola_non_nasconde_l_errore() {
        assert!(
            parola_intera(&"Modalita' amministratore".to_lowercase(), "modalita'"),
            "una forma con la maiuscola sfugge alla guardia"
        );
        assert!(parola_intera(&"IDONEITA'".to_lowercase(), "idoneita'"));
        assert!(parola_intera(&"E' arrivato".to_lowercase(), "e'"));
    }

    /// **Le elisioni corrette non vengono segnalate.**
    ///
    /// Una guardia che gridasse al lupo su `dell'` e `un'` verrebbe
    /// disattivata dal primo che ha fretta, e allora non sorveglierebbe piu'
    /// niente.
    #[test]
    fn le_elisioni_italiane_non_sono_errori() {
        for corretta in [
            "l'archivio dell'ufficio",
            "un'altra fonte",
            "nell'intestazione",
            "sull'archivio",
            "dall'amministratore",
        ] {
            for (sbagliata, _) in SBAGLIATE {
                assert!(
                    !parola_intera(corretta, sbagliata),
                    "«{corretta}» segnalata per «{sbagliata}»: e' italiano corretto"
                );
            }
        }
    }
}
