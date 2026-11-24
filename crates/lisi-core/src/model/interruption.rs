//! Un monitoraggio interrotto, e ciò che non è.
//!
//! # La regola che governa questo modulo
//!
//! **Un monitoraggio interrotto non è un monitoraggio fermato.**
//!
//! L'osservazione avviene dentro il processo dell'applicazione: quando il
//! processo muore, l'osservazione finisce — ma la riga in archivio resta `In
//! corso`, e alla riapertura la schermata, il cruscotto e l'icona nell'area di
//! notifica **affermano tutti che questa postazione sta osservando**, mentre non
//! osserva nulla.
//!
//! Le due correzioni ovvie sono entrambe sbagliate. Lasciarla `In corso` è il
//! difetto. Portarla ad `Arrestata` — che in questo prodotto si legge
//! **«Arrestata dall'operatore»** — significherebbe **attribuire a una persona un
//! atto che non ha compiuto**, e lasciarlo scritto in un archivio che qualcuno
//! rileggerà.
//!
//! La terza riga è dire che cosa è successo davvero: il monitoraggio **è stato
//! interrotto**. Nessuno lo ha deciso, e il prodotto non sa nemmeno perché.
//!
//! # Perché è un fatto e non uno stato
//!
//! Perché [`crate::model::session::SessionState`] racconta **ciò che le persone
//! hanno deciso** — pianificata, in corso, sospesa, conclusa, arrestata. Un
//! arresto anomalo non è un atto di nessuno: metterlo lì farebbe raccontare alla
//! storia delle decisioni una cosa che non è una decisione, e da quel momento
//! nessuno potrebbe più distinguere le due specie di riga.
//!
//! **Lo stato della sessione non si tocca.** Resta `In corso`, che è vero —
//! nessuno l'ha fermata — e accanto c'è scritto che il processo che la osservava
//! non c'è più.
//!
//! La decisione completa sta in
//! `docs/adr/ADR-0064-UN-MONITORAGGIO-INTERROTTO-NON-E-UN-MONITORAGGIO-FERMATO.md`.

use crate::time::Timestamp;

/// Da quando questa postazione non stava più guardando.
///
/// # Perché non è un semplice istante
///
/// Perché l'inizio del buco può venire da due posti diversi, e **quale dei due
/// cambia ciò che si può dire**. Un istante solo li confonderebbe, e la frase
/// che ne esce sarebbe più precisa di quanto il prodotto sappia.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GapStart {
    /// L'ultimo contenuto acquisito da quella sessione.
    ///
    /// È l'inizio del buco quando la sessione aveva acquisito qualcosa.
    LastContent(Timestamp),
    /// L'avvio del monitoraggio.
    ///
    /// La sessione non aveva acquisito nulla: **non si inventa un istante**, e
    /// l'unico che si conosce è quello in cui il monitoraggio è cominciato.
    MonitoringStart(Timestamp),
    /// La chiusura ordinata del programma, con il monitoraggio in corso
    /// (ADR-0195).
    ///
    /// Fino a quell'istante la postazione guardava: l'ultimo contenuto in
    /// archivio è l'ultimo fatto, non la fine dell'osservazione
    /// (FULL-OPERATIONAL-VALIDATION-01, OBS-RST-1). Si usa solo quando è
    /// successiva all'ultimo contenuto e all'avvio del monitoraggio.
    OrderlyClose(Timestamp),
}

impl GapStart {
    /// L'istante, qualunque sia la sua provenienza.
    #[must_use]
    pub const fn instant(self) -> Timestamp {
        match self {
            Self::LastContent(at) | Self::MonitoringStart(at) | Self::OrderlyClose(at) => at,
        }
    }

    /// Da dove viene, come si scrive a una persona.
    #[must_use]
    pub const fn provenance(self) -> &'static str {
        match self {
            Self::LastContent(_) => "l'ultimo contenuto acquisito",
            Self::MonitoringStart(_) => {
                "l'avvio del monitoraggio, perché non era stato acquisito nulla"
            }
            Self::OrderlyClose(_) => "la chiusura del programma",
        }
    }
}

/// Il fatto: un monitoraggio risultava in corso all'avvio di un processo che non
/// lo aveva avviato.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Interruption {
    /// Quando questa postazione se n'è accorta.
    ///
    /// È l'avvio del processo che ha trovato la riga: un istante **misurato**,
    /// non dedotto.
    noticed_at: Timestamp,
    /// Da quando non si stava più guardando.
    gap_start: GapStart,
}

impl Interruption {
    /// Registra il fatto.
    #[must_use]
    pub const fn new(noticed_at: Timestamp, gap_start: GapStart) -> Self {
        Self {
            noticed_at,
            gap_start,
        }
    }

    /// Quando questa postazione se n'è accorta.
    #[must_use]
    pub const fn noticed_at(&self) -> Timestamp {
        self.noticed_at
    }

    /// Da quando non si stava più guardando.
    #[must_use]
    pub const fn gap_start(&self) -> GapStart {
        self.gap_start
    }

    /// Se l'istante in cui ci si è accorti precede l'inizio del buco.
    ///
    /// # Perché può succedere, e perché non si corregge
    ///
    /// Perché i due istanti vengono da **due orologi diversi**: l'inizio del buco
    /// da ciò che la fonte dichiara o dall'archivio, l'accorgersene
    /// dall'orologio di questa macchina. Un cambio d'ora, una sincronizzazione,
    /// o semplicemente una fonte che data i propri messaggi altrove bastano a
    /// invertirli.
    ///
    /// **Non si corregge**, perché correggerlo significherebbe scegliere quale
    /// dei due orologi ha ragione. Si dichiara, e la frase smette di dire «da
    /// quando»: è la regola di CYT-01, dove due righe una sotto l'altra
    /// *sembrano* dire «prima questo, poi quello».
    #[must_use]
    pub fn instants_disagree(&self) -> bool {
        self.noticed_at.as_millis() < self.gap_start.instant().as_millis()
    }
}

/// Come si scrive a una persona che un monitoraggio è stato interrotto.
///
/// # Perché la frase la compone il dominio
///
/// Perché la dicono **tre superfici** — la schermata del monitoraggio, il
/// cruscotto e l'icona nell'area di notifica — e tre composizioni sono tre frasi
/// che divergono alla prima modifica. È la stessa regola di ADR-0063.
///
/// # Che cosa la frase non dice
///
/// **Non dice perché.** Un arresto anomalo, un riavvio di Windows, una caduta di
/// corrente e una chiusura forzata si assomigliano tutti da qui, e il prodotto
/// non ha modo di distinguerli: dire «è andato in errore» sarebbe inventare una
/// causa.
///
/// **Non dice quanto si è perso.** Non lo sa: dice **da quando** non stava
/// guardando, e lascia il resto a chi decide.
///
/// **Non dice che qualcuno lo abbia fermato**, che sarebbe l'unica cosa davvero
/// falsa fra tutte quelle che potrebbe dire.
#[must_use]
pub fn as_sentence(
    interruption: &Interruption,
    format_instant: impl Fn(Timestamp) -> String,
) -> String {
    let accorto = format_instant(interruption.noticed_at());

    if interruption.instants_disagree() {
        // I DUE ISTANTI VENGONO DA DUE OROLOGI, E QUI NON TORNANO.
        //
        // Dire «da quando» con un intervallo che va all'indietro sarebbe una
        // frase precisa e falsa.
        return format!(
            "Questo monitoraggio risultava in corso alla riapertura del {accorto}, e nessuno \
             lo aveva fermato: è stato interrotto. Non è noto da quando questa postazione \
             abbia smesso di guardare — gli istanti disponibili vengono da due orologi diversi \
             e non concordano. Quello che è stato acquisito resta; quello che non è stato \
             acquisito non c'è, e nessuno lo ha ancora cercato."
        );
    }

    let inizio = format_instant(interruption.gap_start().instant());
    let provenienza = interruption.gap_start().provenance();

    format!(
        "Questo monitoraggio risultava in corso alla riapertura del {accorto}, e nessuno lo \
         aveva fermato: è stato interrotto. Questa postazione non stava più guardando dal \
         {inizio} ({provenienza}). Quello che è stato acquisito resta; quello che non è stato \
         acquisito non c'è, e nessuno lo ha ancora cercato."
    )
}

/// Che cosa l'operatore deve decidere, detto accanto all'avviso (ADR-0146).
///
/// Un monitoraggio interrotto **non riprende da solo** quando l'accesso a
/// Telegram torna: aspetta che qualcuno lo decida. Se nel frattempo è concluso
/// — la durata è scaduta mentre il programma era chiuso — non c'è nulla da
/// riprendere, e la frase lo dice.
#[must_use]
pub const fn decision_sentence(still_acquiring: bool) -> &'static str {
    if still_acquiring {
        "Finché qualcuno non decide, questo monitoraggio non riceve contenuti, anche con \
         Telegram collegato. «Riprendi l'acquisizione» lo fa continuare fino alla sua \
         scadenza; per chiudere il monitoraggio, «Arresta» in Monitoraggio."
    } else {
        "Il monitoraggio è già concluso: non riceve più contenuti."
    }
}

/// Il nome del comando che prende in carico l'avviso (ADR-0146).
#[must_use]
pub const fn decision_label(still_acquiring: bool) -> &'static str {
    if still_acquiring {
        "Riprendi l'acquisizione"
    } else {
        "Ho letto"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Il codice di produzione del modulo, senza commenti e senza le prove.
    fn codice_di_produzione() -> String {
        let sorgente = include_str!("interruption.rs");
        let produzione = sorgente
            .split_once("\n#[cfg(test)]\nmod tests {")
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

    fn istante(millis: i64) -> Timestamp {
        Timestamp::from_millis(millis)
    }

    /// Un formattatore riconoscibile, per le prove.
    fn formatta(at: Timestamp) -> String {
        format!("[{}]", at.as_millis())
    }

    /// **La frase dice «interrotto», e non dice «fermato».**
    ///
    /// È la milestone: «arrestata» in questo prodotto significa «arrestata
    /// dall'operatore», e l'operatore non ha fatto nulla.
    #[test]
    fn la_frase_dice_interrotto_e_non_fermato() {
        let fatto = Interruption::new(istante(2_000), GapStart::LastContent(istante(1_000)));
        let frase = as_sentence(&fatto, formatta);

        assert!(frase.contains("è stato interrotto"));
        assert!(frase.contains("nessuno lo aveva fermato"));
        for vietato in ["arrestat", "fermato dall", "sospes"] {
            assert!(
                !frase.to_lowercase().contains(vietato),
                "la frase non deve dire «{vietato}»: attribuirebbe un atto a qualcuno"
            );
        }
    }

    /// **La frase non inventa una causa.**
    #[test]
    fn la_frase_non_inventa_una_causa() {
        let fatto = Interruption::new(istante(2_000), GapStart::LastContent(istante(1_000)));
        let frase = as_sentence(&fatto, formatta).to_lowercase();

        for vietato in ["errore", "guasto", "crash", "difetto", "anomal", "corrotto"] {
            assert!(
                !frase.contains(vietato),
                "la frase non deve dire «{vietato}»: il prodotto non sa perché"
            );
        }
    }

    /// **La frase non dice quanto si è perso.**
    #[test]
    fn la_frase_non_dice_quanto_si_e_perso() {
        let fatto = Interruption::new(istante(9_000), GapStart::LastContent(istante(1_000)));
        let frase = as_sentence(&fatto, formatta).to_lowercase();

        for vietato in ["mancano", "persi", "perduti", "messaggi non"] {
            assert!(
                !frase.contains(vietato),
                "la frase non deve dire «{vietato}»: il prodotto non lo sa"
            );
        }
        assert!(frase.contains("nessuno lo ha ancora cercato"));
    }

    /// **Il buco ha un inizio, e la frase dice da dove viene.**
    #[test]
    fn il_buco_ha_un_inizio_e_si_dice_da_dove_viene() {
        let con_contenuto =
            Interruption::new(istante(5_000), GapStart::LastContent(istante(1_000)));
        let frase = as_sentence(&con_contenuto, formatta);
        assert!(frase.contains("[1000]"));
        assert!(frase.contains("l'ultimo contenuto acquisito"));

        let senza_contenuto =
            Interruption::new(istante(5_000), GapStart::MonitoringStart(istante(400)));
        let frase = as_sentence(&senza_contenuto, formatta);
        assert!(frase.contains("[400]"));
        assert!(frase.contains("non era stato acquisito nulla"));
    }

    /// **Quando i due orologi non concordano, la frase smette di dire «da
    /// quando».**
    #[test]
    fn due_orologi_che_non_concordano_non_producono_un_intervallo() {
        let fatto = Interruption::new(istante(1_000), GapStart::LastContent(istante(5_000)));
        assert!(fatto.instants_disagree());

        let frase = as_sentence(&fatto, formatta);
        assert!(frase.contains("non concordano"));
        assert!(
            !frase.contains("non stava più guardando dal"),
            "con due orologi in disaccordo, «da quando» sarebbe preciso e falso"
        );
        assert!(
            frase.contains("è stato interrotto"),
            "l'interruzione resta un fatto anche quando gli istanti non tornano"
        );
    }

    /// Istanti uguali non sono un disaccordo.
    #[test]
    fn istanti_uguali_non_sono_un_disaccordo() {
        let fatto = Interruption::new(istante(1_000), GapStart::LastContent(istante(1_000)));
        assert!(!fatto.instants_disagree());
    }

    /// **Il dominio non conosce lo stato di una sessione.**
    ///
    /// L'interruzione è un fatto, non uno stato: se un giorno questo modulo
    /// nominasse `SessionState`, sarebbe il primo passo per farla diventare una
    /// variante — e la storia delle decisioni racconterebbe una cosa che nessuno
    /// ha deciso.
    #[test]
    fn il_dominio_non_conosce_lo_stato_di_una_sessione() {
        let codice = codice_di_produzione();
        for vietato in ["SessionState", "Stopped", "Running", "session::"] {
            assert!(
                !codice.contains(vietato),
                "il fatto dell'interruzione non deve nominare «{vietato}»"
            );
        }
    }
}
