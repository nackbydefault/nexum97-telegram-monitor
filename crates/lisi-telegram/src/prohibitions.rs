//! I divieti che nessuna versione futura deve poter violare per distrazione.
//!
//! # Perché una guardia e non una promessa
//!
//! ADR-0035 fissa due regole che, se cadessero, cadrebbero **in silenzio**:
//!
//! - **Zero Telegram Stars.** `searchPublicPosts` ha un parametro economico: è
//!   l'unico punto del prodotto in cui una riga di codice può spendere denaro.
//! - **Il prodotto non entra da nessuna parte.** Non entra in gruppi, non esce,
//!   non usa link d'invito, non scrive messaggi, non reagisce, non contatta
//!   amministratori.
//!
//! Entrambe sono regole che si rispettano finché qualcuno se ne ricorda. Un
//! giorno servirà «solo per provare» una chiamata a `joinChat`, e resterà; o un
//! ripiego a ricerca a pagamento sembrerà ragionevole in un caso limite. Nessuna
//! prova funzionale se ne accorgerebbe: il prodotto continuerebbe a funzionare,
//! semplicemente farebbe una cosa che aveva promesso di non fare.
//!
//! Questo modulo **legge il sorgente di produzione** e verifica che quei
//! percorsi non esistano. È la stessa forma di guardia usata per l'elenco delle
//! persone nei rapporti e per la cartella di destinazione (DEC-185), applicata
//! alle due capacità che rendono la tentazione più concreta.
//!
//! # Perché cerca richieste e non parole
//!
//! Nominare `joinChat` in un commento — come fa questo modulo — non è entrare in
//! un gruppo. La guardia cerca la forma in cui una richiesta TDLib viene
//! **costruita**: `"@type":"joinChat"`. Una guardia che vietasse la parola
//! renderebbe impossibile documentare il divieto, e finirebbe disattivata.
//!
//! # Se non trova i sorgenti, fallisce
//!
//! Una guardia che non riesce a leggere ciò che sorveglia e passa lo stesso è
//! peggio di nessuna guardia: dichiara sicuro ciò che non ha guardato. Qui
//! l'impossibilità di trovare il sorgente è un fallimento, non un rinvio.

use std::path::{Path, PathBuf};

/// Le richieste TDLib che il prodotto non deve costruire mai.
///
/// Non è un elenco di cose «da non fare per ora»: è ciò che distingue un
/// prodotto che **osserva** fonti autorizzate da uno che vi **partecipa**.
pub const FORBIDDEN_REQUESTS: &[(&str, &str)] = &[
    ("joinChat", "entrare in un gruppo o canale"),
    (
        "joinChatByInviteLink",
        "entrare con un link d'invito, cioè aggirare il fatto che l'accesso non era pubblico",
    ),
    (
        "leaveChat",
        "uscire da un gruppo, cioè aver deciso di entrarci",
    ),
    ("sendMessage", "scrivere in una conversazione osservata"),
    (
        "sendMessageAlbum",
        "scrivere in una conversazione osservata",
    ),
    ("addChatMember", "aggiungere qualcuno a una conversazione"),
    ("addChatMembers", "aggiungere qualcuno a una conversazione"),
    (
        "setChatMemberStatus",
        "cambiare il ruolo di qualcuno in una conversazione",
    ),
    ("addReaction", "reagire a un messaggio osservato"),
    ("setMessageReactions", "reagire a un messaggio osservato"),
    (
        "forwardMessages",
        "inoltrare un messaggio osservato, cioè pubblicarlo altrove",
    ),
    (
        "forwardMessage",
        "inoltrare un messaggio osservato, cioè pubblicarlo altrove",
    ),
    (
        "importContacts",
        "caricare una rubrica su Telegram, che è un dato di terzi",
    ),
    ("addContact", "farsi riconoscere da qualcuno"),
    (
        "createNewSupergroupChat",
        "creare una conversazione, cioè esistere come partecipante",
    ),
    (
        "createNewBasicGroupChat",
        "creare una conversazione, cioè esistere come partecipante",
    ),
];

/// Il parametro economico, e l'unico valore ammesso.
pub const PAID_PARAMETER: &str = "star_count";

/// Una violazione trovata nel sorgente.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Violation {
    /// Il file, relativo alla radice del progetto.
    pub file: String,
    /// Che cosa è stato trovato.
    pub what: String,
    /// Perché è vietato.
    pub why: String,
}

/// I file che possono nominare i divieti senza violarli.
///
/// Solo questo modulo: è quello che li elenca. Ogni altra esenzione sarebbe una
/// crepa, perché un file esentato è un file in cui il divieto non vale più.
const EXEMPT: &[&str] = &["prohibitions.rs"];

/// Cerca la radice del progetto salendo dalla cartella del crate.
///
/// # Errori
///
/// Fallisce se non la trova: è il caso in cui la guardia non sa che cosa
/// sorvegliare, e passare sarebbe dichiarare sicuro ciò che non si è guardato.
fn workspace_root() -> Result<PathBuf, String> {
    let mut directory = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    loop {
        let manifest = directory.join("Cargo.toml");
        if manifest.is_file()
            && std::fs::read_to_string(&manifest).is_ok_and(|testo| testo.contains("[workspace]"))
        {
            return Ok(directory);
        }
        if !directory.pop() {
            return Err(String::from(
                "la radice del progetto non è stata trovata: la guardia non sa che \
                 cosa sorvegliare",
            ));
        }
    }
}

/// Tutti i file sorgente di produzione del progetto.
fn sources(root: &Path) -> Result<Vec<PathBuf>, String> {
    let mut trovati = Vec::new();
    for gruppo in ["crates", "tools"] {
        let cartella = root.join(gruppo);
        if !cartella.is_dir() {
            continue;
        }
        raccogli(&cartella, &mut trovati)?;
    }

    // Una soglia, non un numero esatto: il progetto cresce, e una guardia che
    // pretendesse il conteggio di oggi diventerebbe rossa domani per una ragione
    // che non c'entra nulla. Ma se ne trovasse tre, avrebbe guardato la cartella
    // sbagliata e non lo saprebbe.
    if trovati.len() < 30 {
        return Err(format!(
            "trovati solo {} file sorgente: la guardia sta guardando nel posto \
             sbagliato",
            trovati.len()
        ));
    }
    Ok(trovati)
}

/// Raccoglie ricorsivamente i file `.rs`.
fn raccogli(directory: &Path, trovati: &mut Vec<PathBuf>) -> Result<(), String> {
    let voci = std::fs::read_dir(directory)
        .map_err(|errore| format!("«{}» non è leggibile: {errore}", directory.display()))?;

    for voce in voci {
        let voce = voce.map_err(|errore| format!("voce non leggibile: {errore}"))?;
        let percorso = voce.path();
        if percorso.is_dir() {
            // `target` contiene codice generato e dipendenze compilate: non è
            // sorgente del prodotto, e scandirlo richiederebbe minuti.
            if percorso.file_name().is_some_and(|nome| nome == "target") {
                continue;
            }
            raccogli(&percorso, trovati)?;
        } else if percorso.extension().is_some_and(|ext| ext == "rs") {
            trovati.push(percorso);
        }
    }
    Ok(())
}

/// La sola parte del file che viene consegnata.
///
/// # Perché le prove restano fuori
///
/// ADR-0035 chiede la guardia sul **sorgente di produzione**, e la distinzione
/// non è formale. Una prova che costruisce `"star_count":5000` per verificare
/// che la funzione di protezione lo neutralizzi è l'esatto **contrario** di una
/// violazione: è la difesa contro quell'attacco. Segnalarla insegnerebbe a
/// ignorare la guardia, che è il modo in cui una guardia muore.
///
/// Il taglio avviene al blocco `#[cfg(test)] mod tests`, che è la convenzione
/// usata in tutto il progetto. Un `#[cfg(test)]` in altra forma **non** viene
/// riconosciuto e il file resta interamente sorvegliato: nel dubbio la guardia
/// guarda di più, non di meno.
fn production_part(testo: &str) -> &str {
    let mut resto = testo;
    let mut fine = testo.len();
    let mut consumato = 0;

    while let Some(posizione) = resto.find("#[cfg(test)]") {
        let dopo = &resto[posizione..];
        // Solo il blocco delle prove, non un singolo elemento condizionato.
        let apre_il_modulo = dopo
            .lines()
            .nth(1)
            .is_some_and(|riga| riga.trim_start().starts_with("mod tests"));
        if apre_il_modulo {
            fine = consumato + posizione;
            break;
        }
        let avanza = posizione + "#[cfg(test)]".len();
        consumato += avanza;
        resto = &resto[avanza..];
    }

    &testo[..fine]
}

/// Cerca nel sorgente del progetto i percorsi che ADR-0035 vieta.
///
/// # Errori
///
/// Fallisce se il sorgente non è leggibile. **Non** restituisce «nessuna
/// violazione» in quel caso: non aver guardato e non aver trovato nulla sono
/// due esiti diversi.
pub fn scan() -> Result<Vec<Violation>, String> {
    let root = workspace_root()?;
    let mut violazioni = Vec::new();

    for percorso in sources(&root)? {
        let nome = percorso
            .file_name()
            .and_then(|nome| nome.to_str())
            .unwrap_or_default();
        if EXEMPT.contains(&nome) {
            continue;
        }

        let testo = std::fs::read_to_string(&percorso)
            .map_err(|errore| format!("«{}» non è leggibile: {errore}", percorso.display()))?;

        let relativo = percorso
            .strip_prefix(&root)
            .unwrap_or(&percorso)
            .to_string_lossy()
            .replace('\\', "/");

        let produzione = production_part(&testo);
        violazioni.extend(cerca_richieste_vietate(produzione, &relativo));
        violazioni.extend(cerca_spese(produzione, &relativo));
    }

    Ok(violazioni)
}

/// Le richieste vietate costruite nel testo indicato.
///
/// Cerca la forma in cui una richiesta TDLib viene **costruita**, non la parola:
/// nominare `joinChat` in un commento non è entrare in un gruppo.
fn cerca_richieste_vietate(testo: &str, file: &str) -> Vec<Violation> {
    FORBIDDEN_REQUESTS
        .iter()
        .filter(|(nome, _)| testo.contains(&format!("\"@type\":\"{nome}\"")))
        .map(|(nome, perche)| Violation {
            file: String::from(file),
            what: format!("costruisce la richiesta «{nome}»"),
            why: String::from(*perche),
        })
        .collect()
}

/// Le spese diverse da zero nel testo indicato.
///
/// Il parametro economico è ammesso **solo** con valore zero. Un ripiego a
/// ricerca a pagamento sarebbe una spesa che nessun operatore ha autorizzato,
/// fatta da una riga di codice.
fn cerca_spese(testo: &str, file: &str) -> Vec<Violation> {
    let chiave = format!("\"{PAID_PARAMETER}\":");
    let mut violazioni = Vec::new();
    let mut resto = testo;

    while let Some(posizione) = resto.find(&chiave) {
        let dopo = &resto[posizione + chiave.len()..];
        let valore: String = dopo
            .chars()
            .skip_while(|carattere| carattere.is_whitespace())
            .take_while(|carattere| carattere.is_ascii_digit())
            .collect();

        if valore != "0" {
            violazioni.push(Violation {
                file: String::from(file),
                what: format!("passa «{PAID_PARAMETER}» con valore «{valore}»"),
                why: String::from(
                    "è l'unico punto del prodotto in cui una riga di codice può \
                     spendere denaro, e deve valere sempre zero",
                ),
            });
        }
        resto = dopo;
    }
    violazioni
}

#[cfg(test)]
mod tests {
    use super::{
        FORBIDDEN_REQUESTS, cerca_richieste_vietate, cerca_spese, production_part, scan, sources,
        workspace_root,
    };

    /// **Il prodotto non entra da nessuna parte, e non spende.**
    ///
    /// È la guardia vera: legge tutto il sorgente di produzione, non un elenco
    /// di sonde. Se un giorno qualcuno aggiunge una chiamata a `joinChat` «solo
    /// per provare», questa prova diventa rossa prima che il codice arrivi da
    /// qualche parte.
    #[test]
    fn il_sorgente_non_contiene_alcun_percorso_vietato() {
        let Ok(violazioni) = scan() else {
            panic!(
                "la guardia non e' riuscita a leggere il sorgente: non aver guardato e non aver trovato nulla sono due esiti diversi"
            );
        };

        assert!(
            violazioni.is_empty(),
            "il sorgente contiene percorsi che ADR-0035 vieta:\n{}",
            violazioni
                .iter()
                .map(|violazione| format!(
                    "  {} — {} ({})",
                    violazione.file, violazione.what, violazione.why
                ))
                .collect::<Vec<_>>()
                .join("\n")
        );
    }

    /// **Una guardia che non trova ciò che sorveglia deve fallire.**
    ///
    /// È la lezione piu' cara imparata su questo progetto: due prove diverse
    /// sono passate in verde mentre non misuravano nulla. Qui la premessa e'
    /// verificata invece che presunta.
    #[test]
    fn la_guardia_trova_davvero_il_sorgente() {
        let Ok(radice) = workspace_root() else {
            panic!("la radice del progetto deve essere trovabile");
        };
        assert!(radice.join("Cargo.toml").is_file());

        let Ok(file) = sources(&radice) else {
            panic!("il sorgente deve essere leggibile");
        };
        assert!(
            file.len() > 40,
            "trovati {} file: troppo pochi per essere questo progetto",
            file.len()
        );

        // E deve aver visto i file che contano davvero, non una cartella a caso.
        let nomi: Vec<String> = file
            .iter()
            .map(|percorso| percorso.to_string_lossy().replace('\\', "/"))
            .collect();
        for atteso in [
            "crates/lisi-telegram/src/tdlib/capability.rs",
            "crates/lisi-app/src/main.rs",
            "crates/lisi-storage/src/database.rs",
        ] {
            assert!(
                nomi.iter().any(|nome| nome.ends_with(atteso)),
                "la guardia non ha visto «{atteso}»"
            );
        }
    }

    #[test]
    fn una_richiesta_vietata_viene_trovata() {
        // Il controllo positivo della guardia: se non riconoscesse una
        // violazione costruita apposta, il suo verde non significherebbe nulla.
        let finto = r##"let richiesta = r#"{"@type":"joinChat","chat_id":1}"#;"##;
        let trovate = cerca_richieste_vietate(finto, "finto.rs");
        assert_eq!(trovate.len(), 1);
        assert!(trovate[0].what.contains("joinChat"));
        assert!(
            !trovate[0].why.is_empty(),
            "la violazione deve dire PERCHE' e' vietata, non solo che lo e'"
        );
    }

    #[test]
    fn nominare_un_divieto_in_un_commento_non_e_violarlo() {
        // Una guardia che vietasse la parola renderebbe impossibile documentare
        // il divieto, e finirebbe disattivata.
        let commento = "// Il prodotto non chiama mai joinChat ne' leaveChat.";
        assert!(cerca_richieste_vietate(commento, "finto.rs").is_empty());
    }

    #[test]
    fn una_spesa_diversa_da_zero_viene_trovata() {
        let finto = r#"{"@type":"searchPublicPosts","star_count":5}"#;
        let trovate = cerca_spese(finto, "finto.rs");
        assert_eq!(trovate.len(), 1);
        assert!(trovate[0].what.contains('5'));
    }

    #[test]
    fn zero_stars_non_e_una_violazione() {
        let corretto = r#"{"@type":"searchPublicPosts","star_count":0}"#;
        assert!(cerca_spese(corretto, "finto.rs").is_empty());
    }

    #[test]
    fn un_parametro_economico_senza_valore_e_una_violazione() {
        // `"star_count":` seguito da una variabile invece che da un numero
        // significa che il valore lo decide qualcos'altro — ed e' esattamente
        // cio' che il divieto esclude.
        let variabile = r#"{"star_count":quanto}"#;
        assert!(
            !cerca_spese(variabile, "finto.rs").is_empty(),
            "un valore deciso altrove non e' zero dimostrabile"
        );
    }

    /// **La separazione fra produzione e prove non deve tagliare troppo.**
    ///
    /// Se `production_part` restituisse una porzione vuota, o tagliasse alla
    /// prima riga, l'intera guardia diventerebbe verde senza guardare nulla —
    /// che e' il modo in cui una guardia muore in silenzio.
    #[test]
    fn la_separazione_fra_produzione_e_prove_taglia_nel_punto_giusto() {
        let file = concat!(
            "fn produzione() {}
",
            "
",
            "#[cfg(test)]
",
            "mod tests {
",
            "    fn prova() {}
",
            "}
"
        );
        let produzione = super::production_part(file);
        assert!(produzione.contains("fn produzione"));
        assert!(
            !produzione.contains("fn prova"),
            "il codice di prova non doveva restare"
        );
    }

    #[test]
    fn un_file_senza_prove_resta_intero() {
        let file = "fn tutto() {}
";
        assert_eq!(super::production_part(file), file);
    }

    #[test]
    fn un_cfg_test_su_un_solo_elemento_non_spegne_la_guardia() {
        // Nel dubbio la guardia guarda di piu', non di meno: un
        // `#[cfg(test)]` che non apre il modulo delle prove non deve far
        // sparire tutto cio' che viene dopo.
        let file = concat!(
            "#[cfg(test)]
",
            "const SOLO_PER_PROVE: u8 = 1;
",
            "fn produzione_dopo() {}
"
        );
        let produzione = super::production_part(file);
        assert!(
            produzione.contains("fn produzione_dopo"),
            "la guardia ha smesso di guardare al primo #[cfg(test)]"
        );
    }

    /// **E su un file vero del progetto, la porzione sorvegliata non e' vuota.**
    #[test]
    fn su_un_file_vero_resta_qualcosa_da_sorvegliare() {
        let sorgente = include_str!("tdlib/live_probe.rs");
        let produzione = super::production_part(sorgente);
        assert!(
            produzione.len() > sorgente.len() / 4,
            "resta solo {} di {} caratteri: la guardia sta tagliando quasi tutto",
            produzione.len(),
            sorgente.len()
        );
        assert!(
            produzione.contains("searchPublicPosts"),
            "la porzione sorvegliata non contiene nemmeno la chiamata che il divieto riguarda"
        );
    }

    /// **Nessuna capacita' costruita deve restare non invocata.**
    ///
    /// E' il difetto che questo progetto ha incontrato piu' volte — *un motore
    /// costruito, collaudato e mai invocato* — e che si ricrea alla prima
    /// distrazione: CY-01 lo ha chiuso per l'estrattore di indicatori, e CY-02
    /// e CY-05 lo hanno riaperto lo stesso giorno per la correlazione e la
    /// rilevanza.
    ///
    /// # Come funziona, e che cosa NON garantisce
    ///
    /// Cerca ogni nome elencato nel sorgente di produzione **fuori dal file che
    /// lo definisce**. Se compare solo dove nasce, e' costruito e non collegato.
    ///
    /// Non garantisce che la chiamata sia raggiungibile da `main`: quella e' una
    /// domanda sul grafo delle chiamate, e questa e' una guardia testuale. E'
    /// scritto perche' chi la legge non le attribuisca piu' di quanto faccia.
    #[test]
    fn nessuna_capacita_costruita_resta_non_invocata() {
        let Ok(radice) = workspace_root() else {
            panic!("la radice del progetto deve essere trovabile");
        };
        let Ok(file) = sources(&radice) else {
            panic!("il sorgente deve essere leggibile");
        };

        // Nome della funzione, e file in cui e' definita.
        let capacita = [
            ("extract(", "indicator.rs"),
            ("correlate_by_indicator(", "indicator.rs"),
            ("assess_italy(", "relevance.rs"),
            // Collegata da CYBER-SECTOR (DEC-247). Era dichiarata non collegata
            // dalla prova qui sotto, che DEC-235 aveva scritto per fissare
            // l'assenza: la regola che assegna un settore ora esiste, e non la
            // inventa il prodotto - la dichiara un amministratore.
            ("assess_sectors(", "relevance.rs"),
            ("verify_integrity(", "integrity.rs"),
            ("notification_state(", "toast.rs"),
            ("system_motion(", "motion.rs"),
        ];

        for (nome, definita_in) in capacita {
            let mut chiamata_altrove = false;

            for percorso in &file {
                let file_name = percorso
                    .file_name()
                    .and_then(|nome| nome.to_str())
                    .unwrap_or_default();
                if file_name == definita_in {
                    continue;
                }
                let Ok(testo) = std::fs::read_to_string(percorso) else {
                    continue;
                };
                if production_part(&testo).contains(nome) {
                    chiamata_altrove = true;
                    break;
                }
            }

            assert!(
                chiamata_altrove,
                "«{nome}» compare solo in «{definita_in}»: e' una capacita' \
                 costruita, collaudata e mai invocata"
            );
        }
    }

    /// **Le capacita' costruite e NON ancora collegate sono dichiarate qui.**
    ///
    /// # Perche' una prova che fissa un'assenza
    ///
    /// La prova qui sopra elenca dei nomi e verifica che siano invocati. E' un
    /// elenco, e un elenco copre cio' che qualcuno ci ha messo: una capacita'
    /// costruita e mai collegata resterebbe verde per il solo fatto di non
    /// essere stata elencata.
    ///
    /// Questa prova serve al caso opposto: una capacita' che si sa non
    /// collegata, e che **deve restare tale finche' manca la condizione che la
    /// renderebbe onesta**. L'assenza diventa dichiarata invece che silenziosa,
    /// e la prova si rompe il giorno in cui qualcuno la collega — che e' il
    /// momento giusto per riesaminarla.
    ///
    /// # L'elenco e' vuoto, e la ragione va letta
    ///
    /// Conteneva `Sector::`, la tassonomia dei diciotto settori NIS2 costruita
    /// in CY-05 e non invocata da nessuna parte. DEC-235 lo aveva scritto cosi':
    /// «collegarla richiede una regola che assegni un settore a un contenuto, e
    /// nessuna regola verificata esiste».
    ///
    /// **CYBER-SECTOR ha costruito quella regola** (DEC-247), e non l'ha
    /// inventata il prodotto: un contenuto ricade in un settore perche' un
    /// amministratore ha dichiarato che quella organizzazione appartiene a quel
    /// settore, e il contenuto la nomina. Ogni attribuzione porta con se' chi
    /// l'ha dichiarata e che cosa ha riscontrato.
    ///
    /// Da quel momento questa prova e' diventata rossa, come doveva, e
    /// `assess_sectors(` e' passata nell'elenco delle capacita' invocate.
    ///
    /// # Perche' la prova resta, con l'elenco vuoto
    ///
    /// Perche' il meccanismo serve ancora. La prossima capacita' costruita e non
    /// collegabile subito — e ce ne saranno, il piano ne pianifica molte — si
    /// dichiara qui invece di restare un difetto silenzioso. Cancellare la prova
    /// insieme all'ultima voce significherebbe riscriverla da capo la prossima
    /// volta, e nel frattempo non averla.
    #[test]
    fn le_capacita_non_ancora_collegate_restano_dichiarate() {
        let Ok(radice) = workspace_root() else {
            panic!("la radice del progetto deve essere trovabile");
        };
        let Ok(file) = sources(&radice) else {
            panic!("il sorgente deve essere leggibile");
        };

        // Nome del tipo, file che lo definisce, e perche' non e' collegato.
        //
        // Vuoto: nessuna capacita' e' oggi costruita e deliberatamente non
        // collegata. Vedere la nota qui sopra per il perche' la prova resta.
        let non_collegate: [(&str, &str, &str); 0] = [];

        for (nome, definita_in, perche) in non_collegate {
            let mut chiamata_altrove = false;

            for percorso in &file {
                let file_name = percorso
                    .file_name()
                    .and_then(|nome| nome.to_str())
                    .unwrap_or_default();
                if file_name == definita_in {
                    continue;
                }
                let Ok(testo) = std::fs::read_to_string(percorso) else {
                    continue;
                };
                if production_part(&testo).contains(nome) {
                    chiamata_altrove = true;
                    break;
                }
            }

            assert!(
                !chiamata_altrove,
                "«{nome}» ora e' invocato altrove, e questa prova non descrive \
                 piu' la realta'. Spostarlo fra le capacita' invocate e togliere \
                 la riga da qui. Era dichiarato non collegato perche': {perche}"
            );
        }

        // Che il meccanismo funzioni ancora si verifica sul meccanismo, non
        // sull'elenco: con l'elenco vuoto il ciclo non gira, e una prova che
        // non gira e' una prova che non protegge. Qui si esercita la stessa
        // ricerca su un nome che NON esiste nel sorgente, e si pretende che non
        // risulti invocato.
        let mut trovato = false;
        for percorso in &file {
            let Ok(testo) = std::fs::read_to_string(percorso) else {
                continue;
            };
            if production_part(&testo).contains("CapacitaCheNonEsiste::") {
                trovato = true;
                break;
            }
        }
        assert!(
            !trovato,
            "la ricerca sul sorgente ha trovato un nome inventato: il \
             meccanismo di questa prova non sta piu' leggendo cio' che crede"
        );
    }

    #[test]
    fn ogni_divieto_dice_perche_esiste() {
        // Un elenco di divieti senza ragioni e' un elenco che qualcuno
        // cancellera' il giorno in cui gli sara' scomodo.
        for (nome, perche) in FORBIDDEN_REQUESTS {
            assert!(
                perche.len() > 15,
                "«{nome}» e' vietato senza dire perche': «{perche}»"
            );
        }
    }
}
