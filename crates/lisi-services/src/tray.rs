//! L'area di notifica, e ciò che non deve far passare.
//!
//! # La regola che governa questo modulo
//!
//! **Il vassoio non è una finestra sul blocco.**
//!
//! Il blocco della postazione esiste perché una postazione condivisa viene
//! lasciata sola. Mentre è bloccata, la schermata di blocco mostra **un fatto e
//! non un contenuto**: «Monitoraggio: In corso · 3 avvisi da esaminare». Il
//! numero è il fatto; **quali** siano gli avvisi è il contenuto, e resta dietro
//! il blocco.
//!
//! **L'icona nell'area di notifica resta sullo schermo mentre la postazione è
//! bloccata.** Il suggerimento compare al passaggio del puntatore, il menu si
//! apre con un clic destro, e chi si siede davanti a quella macchina li vede
//! senza sbloccare nulla. Un vassoio che mostrasse più della schermata di blocco
//! **sarebbe un buco nel blocco** — e nessuno se ne accorgerebbe, perché il
//! blocco continuerebbe a funzionare benissimo.
//!
//! Perciò il vassoio mostra il fatto e mai il contenuto, **sempre** e non solo a
//! postazione bloccata: un'unica regola non ha un ramo in cui sbagliarsi, e
//! l'icona è vista dai colleghi che passano tanto quanto da chi si siede.
//!
//! **E non è una raccomandazione**: [`StationFact`] non ha un campo in cui
//! mettere un nome di fonte, un testo o un oggetto di avviso.
//!
//! # Qui vivono tutte le decisioni
//!
//! La parte di Windows è `unsafe` e non si può provare senza una persona che
//! guardi uno schermo. Perciò **non contiene alcuna decisione**: riceve un
//! elenco di voci già composte e restituisce quale è stata scelta. Tutto ciò che
//! ADR-0063 stabilisce si prova qui, in Rust sicuro.
//!
//! La decisione completa sta in
//! `docs/adr/ADR-0063-IL-VASSOIO-NON-E-UNA-FINESTRA-SUL-BLOCCO.md`.

/// Che cosa il vassoio può dire del monitoraggio.
///
/// # Perché porta ciò che la schermata mostra, e non lo ricalcola
///
/// Perché è la stessa regola della schermata di blocco: **la frase deve dire ciò
/// che l'operatore vedrebbe se fosse davanti allo schermo**, e ricalcolarla da
/// un'altra fonte la farebbe divergere da quella. L'etichetta nasce una volta
/// sola, da `SessionState::label`, e arriva qui attraverso ciò che la schermata
/// del monitoraggio ha già scritto.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MonitoringVisibility {
    /// Il binario **non può** monitorare: è compilato senza TDLib.
    ///
    /// Non è «fermo». Un'icona che dicesse «fermo» in un binario che non può
    /// monitorare sarebbe una bugia piccola e permanente (ADR-0008, DEC-203).
    Unavailable,
    /// Ciò che la schermata del monitoraggio mostra.
    ///
    /// Vuoto significa **nessun monitoraggio**, ed è lo stesso vuoto che la
    /// schermata di blocco interpreta così.
    AsShown(String),
    /// Più di un monitoraggio in corso: **quanti**, mai quali.
    ///
    /// # Perché un numero e non un elenco
    ///
    /// Perché un elenco di etichette di monitoraggio è **più vicino al contenuto
    /// che al fatto**, e il vassoio è visibile a postazione bloccata (ADR-0063).
    /// «Tre monitoraggi in corso» è un fatto su questa macchina; «Corteo di
    /// sabato, Canale Alfa, Verifica X» è un elenco di ciò che questo ufficio
    /// guarda, letto da chiunque passi (ADR-0065).
    Several(u32),
}

impl MonitoringVisibility {
    /// Lo stato, come si scrive a una persona.
    ///
    /// **Non è mai vuoto**: una riga di menu vuota non dice nulla a nessuno.
    #[must_use]
    pub fn label(&self) -> String {
        match self {
            Self::Unavailable => String::from("Non disponibile"),
            Self::AsShown(testo) if testo.trim().is_empty() => String::from("Nessun monitoraggio"),
            Self::AsShown(testo) => testo.clone(),
            Self::Several(quanti) => format!("{quanti} monitoraggi in corso"),
        }
    }
}

/// Il fatto che questa postazione può dire di sé, e **nient'altro**.
///
/// # Perché i campi sono questi, e perché non ce ne sono altri
///
/// Perché sono esattamente ciò che la schermata di blocco già mostra a chi non
/// ha sbloccato: lo stato del monitoraggio, **quanti** avvisi attendono, e se la
/// postazione è bloccata — che è un fatto su questa macchina, non un contenuto.
///
/// Un campo in più qui sarebbe un campo in più sullo schermo di una postazione
/// lasciata sola.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StationFact {
    /// Che cosa sta facendo il monitoraggio.
    pub monitoring: MonitoringVisibility,
    /// **Quanti** avvisi attendono di essere esaminati. Non quali.
    pub pending_alerts: u32,
    /// Se la postazione è bloccata.
    pub locked: bool,
}

/// Perché «Blocca postazione» può non essere premibile.
///
/// # Perché una voce che non fa nulla è peggio di una che spiega
///
/// Il blocco appartiene a un **account Telegram**, e senza una parola di sblocco
/// fissata il codice esistente — giustamente — non blocca: la postazione
/// resterebbe chiusa senza che nessuno possa riaprirla. Una voce premibile che
/// non facesse nulla insegnerebbe che il vassoio non funziona, e la prossima
/// volta nessuno la proverebbe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockAvailability {
    /// Si può bloccare.
    Available,
    /// La postazione è già bloccata.
    AlreadyLocked,
    /// Non c'è un account attivo: non c'è nulla da bloccare.
    NoActiveAccount,
    /// L'account attivo non ha una parola di sblocco fissata.
    NoUnlockWord,
}

impl LockAvailability {
    /// Perché non si può bloccare, come si scrive a una persona.
    ///
    /// `None` quando si può.
    #[must_use]
    pub const fn reason(self) -> Option<&'static str> {
        match self {
            Self::Available => None,
            Self::AlreadyLocked => Some("la postazione è già bloccata"),
            Self::NoActiveAccount => Some("nessun account attivo"),
            Self::NoUnlockWord => Some("l'account attivo non ha una parola di sblocco"),
        }
    }
}

/// Ciò che una voce del menu può chiedere.
///
/// # Perché l'enumerazione è chiusa, e perché ne contiene due
///
/// Perché «**non aggira** l'autorizzazione operatore/amministratore» va reso
/// **impossibile** invece che rispettato. Nessuna delle sei azioni riservate di
/// `RestrictedAction` è raggiungibile dal vassoio, e non esiste un comando che
/// le nomini.
///
/// Aprire la finestra non è un'azione: è la stessa porta di sempre, e su una
/// postazione bloccata porta davanti **la finestra bloccata**. Bloccare è
/// l'unica direzione che **aggiunge** protezione e non ne toglie.
///
/// Non c'è «sblocca», che sarebbe una seconda porta. Non c'è «esci», né alcuna
/// azione distruttiva: ciò che distrugge continua a passare da dove passa oggi.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrayCommand {
    /// Porta davanti la finestra dell'applicazione.
    OpenWindow,
    /// Blocca la postazione.
    LockStation,
}

impl TrayCommand {
    /// Etichetta stabile, per l'audit e la diagnostica.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::OpenWindow => "vassoio_apri_finestra",
            Self::LockStation => "vassoio_blocca_postazione",
        }
    }
}

/// Una voce del menu, già decisa.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrayMenuItem {
    /// Che cosa c'è scritto.
    pub label: String,
    /// Che cosa chiede, se è premibile.
    ///
    /// `None` è una voce che **non si preme**: o è una riga di stato, o è
    /// un'azione che in questo momento non si può compiere e che dice perché.
    pub command: Option<TrayCommand>,
}

impl TrayMenuItem {
    /// Se la voce si può premere.
    #[must_use]
    pub const fn is_enabled(&self) -> bool {
        self.command.is_some()
    }
}

/// Che cosa il vassoio deve disegnare.
///
/// Attraversa il confine verso la parte `unsafe`, che di questi valori sa
/// soltanto che sono testo.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrayView {
    /// Il suggerimento che compare al passaggio del puntatore.
    pub tooltip: String,
    /// Le voci del menu, nell'ordine in cui vanno mostrate.
    pub items: Vec<TrayMenuItem>,
}

/// Quanto può essere lungo un suggerimento dell'area di notifica.
///
/// Windows tronca a 128 caratteri, e **un suggerimento troncato da Windows
/// finirebbe a metà parola**: si compone entro il limite invece di scoprirlo.
pub const MAX_TOOLTIP_CHARS: usize = 120;

/// **Il fatto**, come lo legge chi non ha sbloccato.
///
/// # Perché questa funzione esiste
///
/// Perché la stessa frase la mostrano **due** superfici — la schermata di blocco
/// e il vassoio — e due composizioni sono due frasi che divergono alla prima
/// modifica. La seconda a divergere sarebbe quella che nessuno guarda.
///
/// Il contenuto non entra mai: né fonte, né motivazione, né estratto. Solo che
/// qualcosa è successo, e **quanto**.
#[must_use]
pub fn station_fact(monitoring_label: &str, pending_alerts: u32) -> String {
    let mut parts = Vec::new();
    if !monitoring_label.is_empty() {
        parts.push(format!("Monitoraggio: {monitoring_label}"));
    }
    if pending_alerts > 0 {
        parts.push(if pending_alerts == 1 {
            String::from("1 avviso da esaminare")
        } else {
            format!("{pending_alerts} avvisi da esaminare")
        });
    }
    parts.join(" \u{b7} ")
}

/// Compone che cosa il vassoio mostra.
///
/// # Errori
///
/// Nessuno: questa funzione non può fallire, perché tutto ciò che le serve è già
/// stato deciso da chi la chiama.
#[must_use]
pub fn compose(product_name: &str, fact: &StationFact, lock: LockAvailability) -> TrayView {
    let fatto = station_fact(&fact.monitoring.label(), fact.pending_alerts);

    let mut tooltip = if fatto.is_empty() {
        String::from(product_name)
    } else {
        format!("{product_name} \u{2014} {fatto}")
    };
    if fact.locked {
        tooltip.push_str(" \u{b7} postazione bloccata");
    }
    // SI COMPONE ENTRO IL LIMITE INVECE DI SCOPRIRLO.
    //
    // Windows tronca a 128 caratteri senza avvisare, e a meta' parola.
    if tooltip.chars().count() > MAX_TOOLTIP_CHARS {
        tooltip = tooltip.chars().take(MAX_TOOLTIP_CHARS).collect();
    }

    let mut items = vec![
        // La riga di stato: si legge, non si preme.
        TrayMenuItem {
            label: format!("Monitoraggio: {}", fact.monitoring.label()),
            command: None,
        },
        TrayMenuItem {
            label: format!("Apri {product_name}"),
            command: Some(TrayCommand::OpenWindow),
        },
    ];

    items.push(match lock.reason() {
        None => TrayMenuItem {
            label: String::from("Blocca postazione"),
            command: Some(TrayCommand::LockStation),
        },
        Some(motivo) => TrayMenuItem {
            label: format!("Blocca postazione \u{2014} {motivo}"),
            command: None,
        },
    });

    TrayView { tooltip, items }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Il codice di produzione del modulo, senza commenti e senza le prove.
    fn codice_di_produzione() -> String {
        let sorgente = include_str!("tray.rs");
        let produzione = sorgente
            .split_once("\n#[cfg(test)]")
            .map_or(sorgente, |(prima, _)| prima);
        produzione
            .lines()
            .filter(|riga| {
                let trimmed = riga.trim_start();
                !trimmed.starts_with("//") && !trimmed.starts_with("///")
            })
            .collect::<Vec<&str>>()
            .join("\n")
    }

    const PRODOTTO: &str = "NEXUM/97";

    fn fatto(monitoring: MonitoringVisibility, pending: u32, locked: bool) -> StationFact {
        StationFact {
            monitoring,
            pending_alerts: pending,
            locked,
        }
    }

    /// **Il vassoio dice il fatto, e la frase è la stessa della schermata di
    /// blocco.**
    #[test]
    fn il_suggerimento_porta_il_fatto_e_non_il_contenuto() {
        let vista = compose(
            PRODOTTO,
            &fatto(
                MonitoringVisibility::AsShown(String::from("In corso")),
                3,
                false,
            ),
            LockAvailability::Available,
        );
        assert!(vista.tooltip.contains("NEXUM/97"));
        assert!(vista.tooltip.contains("Monitoraggio: In corso"));
        assert!(vista.tooltip.contains("3 avvisi da esaminare"));
    }

    /// Un avviso solo non si dice al plurale.
    #[test]
    fn un_avviso_solo_si_dice_al_singolare() {
        let vista = compose(
            PRODOTTO,
            &fatto(
                MonitoringVisibility::AsShown(String::from("In corso")),
                1,
                false,
            ),
            LockAvailability::Available,
        );
        assert!(vista.tooltip.contains("1 avviso da esaminare"));
        assert!(!vista.tooltip.contains("avvisi"));
    }

    /// Senza avvisi non si dice «0 avvisi»: non si dice nulla.
    #[test]
    fn senza_avvisi_non_si_annuncia_uno_zero() {
        let vista = compose(
            PRODOTTO,
            &fatto(MonitoringVisibility::AsShown(String::new()), 0, false),
            LockAvailability::NoActiveAccount,
        );
        assert!(!vista.tooltip.contains("0 avvisi"));
        assert!(!vista.tooltip.contains("esaminare"));
    }

    /// **«Non disponibile» non è «fermo».**
    ///
    /// Un binario compilato senza TDLib non può monitorare, e dire «fermo»
    /// sarebbe una bugia piccola e permanente.
    #[test]
    fn un_binario_senza_tdlib_non_dice_fermo() {
        let vista = compose(
            PRODOTTO,
            &fatto(MonitoringVisibility::Unavailable, 0, false),
            LockAvailability::NoActiveAccount,
        );
        assert!(vista.tooltip.contains("Non disponibile"));
        assert!(!vista.tooltip.contains("Fermo"));

        let Some(stato) = vista.items.first() else {
            panic!("la riga di stato deve esserci");
        };
        assert_eq!(stato.label, "Monitoraggio: Non disponibile");
        assert!(!stato.is_enabled(), "la riga di stato non si preme");
    }

    /// **Con più monitoraggi il vassoio dice QUANTI, mai QUALI.**
    ///
    /// Un elenco di etichette di monitoraggio è più vicino al contenuto che al
    /// fatto, e il vassoio è visibile a postazione bloccata (ADR-0065 §3.4).
    #[test]
    fn con_piu_monitoraggi_si_dice_quanti_e_mai_quali() {
        let vista = compose(
            PRODOTTO,
            &fatto(MonitoringVisibility::Several(3), 2, true),
            LockAvailability::AlreadyLocked,
        );

        assert!(vista.tooltip.contains("3 monitoraggi in corso"));

        let Some(stato) = vista.items.first() else {
            panic!("la riga di stato deve esserci");
        };
        assert_eq!(stato.label, "Monitoraggio: 3 monitoraggi in corso");

        // Nessuna etichetta di monitoraggio puo' entrare: il tipo non ha un
        // posto in cui metterla, e questa prova lo fissa sulla frase.
        for voce in &vista.items {
            assert!(
                !voce.label.contains('«'),
                "una citazione nel menu sarebbe il nome di un monitoraggio: «{}»",
                voce.label
            );
        }
    }

    /// Un monitoraggio solo continua a dirsi con la propria etichetta.
    #[test]
    fn un_monitoraggio_solo_si_dice_come_lo_mostra_la_schermata() {
        let vista = compose(
            PRODOTTO,
            &fatto(
                MonitoringVisibility::AsShown(String::from("In corso")),
                0,
                false,
            ),
            LockAvailability::Available,
        );
        assert!(vista.tooltip.contains("Monitoraggio: In corso"));
        assert!(!vista.tooltip.contains("monitoraggi in corso"));
    }

    /// La postazione bloccata è **un fatto su questa macchina**, e si dice.
    #[test]
    fn la_postazione_bloccata_lo_dichiara() {
        let vista = compose(
            PRODOTTO,
            &fatto(
                MonitoringVisibility::AsShown(String::from("In corso")),
                2,
                true,
            ),
            LockAvailability::AlreadyLocked,
        );
        assert!(vista.tooltip.contains("postazione bloccata"));
    }

    /// **Un suggerimento non supera il limite che Windows tronca a metà parola.**
    #[test]
    fn il_suggerimento_si_compone_entro_il_limite() {
        let nome_lunghissimo = "N".repeat(500);
        let vista = compose(
            &nome_lunghissimo,
            &fatto(
                MonitoringVisibility::AsShown(String::from("In corso")),
                99,
                true,
            ),
            LockAvailability::Available,
        );
        assert!(vista.tooltip.chars().count() <= MAX_TOOLTIP_CHARS);
    }

    /// **«Blocca postazione» si preme quando si può.**
    #[test]
    fn bloccare_si_puo_quando_si_puo() {
        let vista = compose(
            PRODOTTO,
            &fatto(
                MonitoringVisibility::AsShown(String::from("In corso")),
                0,
                false,
            ),
            LockAvailability::Available,
        );
        let Some(blocca) = vista.items.last() else {
            panic!("la voce del blocco deve esserci");
        };
        assert_eq!(blocca.command, Some(TrayCommand::LockStation));
        assert_eq!(blocca.label, "Blocca postazione");
    }

    /// **E quando non si può, non si preme e dice perché.**
    ///
    /// Una voce premibile che non facesse nulla insegnerebbe che il vassoio non
    /// funziona.
    #[test]
    fn quando_non_si_puo_bloccare_la_voce_non_si_preme_e_dice_perche() {
        for (disponibilita, atteso) in [
            (LockAvailability::AlreadyLocked, "già bloccata"),
            (LockAvailability::NoActiveAccount, "nessun account attivo"),
            (LockAvailability::NoUnlockWord, "parola di sblocco"),
        ] {
            let vista = compose(
                PRODOTTO,
                &fatto(MonitoringVisibility::AsShown(String::new()), 0, false),
                disponibilita,
            );
            let Some(blocca) = vista.items.last() else {
                panic!("la voce del blocco deve esserci");
            };
            assert!(
                !blocca.is_enabled(),
                "«{atteso}»: la voce non doveva essere premibile"
            );
            assert!(
                blocca.label.contains(atteso),
                "la voce deve dire perché: «{}»",
                blocca.label
            );
        }
    }

    /// **Nessuna voce PREMIBILE offre di sbloccare, uscire o distruggere.**
    ///
    /// # Perché la prova guarda le voci premibili e non tutte
    ///
    /// Perché la prima versione guardava tutte, ed era **sbagliata**: è
    /// diventata rossa su «Blocca postazione — l'account attivo non ha una
    /// parola di sblocco», cioè su una frase che spiega, correttamente, perché
    /// **non** si può fare qualcosa. Vietare una parola dentro una spiegazione
    /// avrebbe costretto a scrivere peggio la spiegazione.
    ///
    /// Ciò che conta è che **nessuna voce premibile** prometta quelle cose. Che
    /// non possa nemmeno farle è garantito altrove, e meglio: l'enumerazione dei
    /// comandi è chiusa e ne contiene due.
    #[test]
    fn nessuna_voce_premibile_sblocca_esce_o_distrugge() {
        for disponibilita in [
            LockAvailability::Available,
            LockAvailability::AlreadyLocked,
            LockAvailability::NoActiveAccount,
            LockAvailability::NoUnlockWord,
        ] {
            let vista = compose(
                PRODOTTO,
                &fatto(
                    MonitoringVisibility::AsShown(String::from("In corso")),
                    5,
                    true,
                ),
                disponibilita,
            );
            for voce in vista.items.iter().filter(|voce| voce.is_enabled()) {
                let etichetta = voce.label.to_lowercase();
                for vietato in ["sblocc", "esci", "chiudi", "termina", "arresta", "elimina"] {
                    assert!(
                        !etichetta.contains(vietato),
                        "una voce premibile non deve promettere «{vietato}»: «{}»",
                        voce.label
                    );
                }
            }
        }
    }

    /// **Ogni comando del menu è uno dei due, e non ce ne sono altri.**
    #[test]
    fn i_comandi_sono_due_e_sono_quelli() {
        let vista = compose(
            PRODOTTO,
            &fatto(
                MonitoringVisibility::AsShown(String::from("In corso")),
                0,
                false,
            ),
            LockAvailability::Available,
        );
        let comandi: Vec<TrayCommand> =
            vista.items.iter().filter_map(|voce| voce.command).collect();
        assert_eq!(
            comandi,
            vec![TrayCommand::OpenWindow, TrayCommand::LockStation]
        );
    }

    /// **Il vassoio non nomina alcuna azione riservata.**
    ///
    /// «Non aggira l'autorizzazione operatore/amministratore» va reso
    /// impossibile invece che rispettato: se un giorno qualcuno aggiungesse un
    /// comando che le nomina, questa prova diventerebbe rossa.
    #[test]
    fn il_vassoio_non_nomina_alcuna_azione_riservata() {
        let codice = codice_di_produzione();
        for riservata in lisi_core::RestrictedAction::ALL {
            assert!(
                !codice.contains(riservata.as_str()),
                "il vassoio non deve nominare l'azione riservata «{}»",
                riservata.as_str()
            );
        }
        for vietato in [
            "RestrictedAction",
            "return_to_administrator",
            "enter_operator_mode",
            "unlock",
        ] {
            assert!(
                !codice.contains(vietato),
                "il vassoio non deve nominare «{vietato}»: sarebbe la seconda porta"
            );
        }
    }

    /// **Il fatto non ha un posto in cui mettere un contenuto.**
    ///
    /// Non è una raccomandazione: il tipo che attraversa il confine non ha
    /// quei campi, e un campo aggiunto qui sarebbe un campo in più sullo schermo
    /// di una postazione lasciata sola.
    #[test]
    fn il_fatto_non_ha_un_posto_per_il_contenuto() {
        let codice = codice_di_produzione();
        for vietato in [
            "source_name",
            "source_id",
            "body",
            "subject",
            "excerpt",
            "message",
            "content",
            "author",
            "title",
        ] {
            assert!(
                !codice.contains(vietato),
                "il vassoio non deve avere un campo «{vietato}»: il contenuto resta \
                 dietro il blocco"
            );
        }
    }

    /// La frase del fatto è **una sola**, e questa prova la fissa.
    ///
    /// Se la schermata di blocco e il vassoio smettessero di comporla qui,
    /// divergerebbero.
    #[test]
    fn la_frase_del_fatto_e_una_sola() {
        assert_eq!(
            station_fact("In corso", 3),
            "Monitoraggio: In corso \u{b7} 3 avvisi da esaminare"
        );
        assert_eq!(station_fact("In corso", 0), "Monitoraggio: In corso");
        assert_eq!(station_fact("", 2), "2 avvisi da esaminare");
        assert_eq!(station_fact("", 0), "");
    }
}
