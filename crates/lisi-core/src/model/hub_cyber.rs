//! I grappoli cyber dell'ufficio, come una postazione li vede
//! (TEAM-CYBER-01, ADR-0102).
//!
//! # Che cosa attraversa il filo
//!
//! **Perché** i contenuti stanno insieme, **quanti** sono, **quante fonti
//! distinte** li portano, i segnali di rilevanza per l'Italia, i settori in cui
//! il fatto ricadrebbe, gli **indicatori** nominati e che cosa una persona ha
//! deciso.
//!
//! # Che cosa non lo attraversa
//!
//! Il **testo dei messaggi**. Gli indicatori sono **vocabolario** — una CVE, un
//! dominio, un indirizzo — ed è già la ragione per cui l'esportazione STIX li
//! emette (DEC-292); il testo è contenuto monitorato, e si chiede uno per volta
//! (ADR-0094).
//!
//! # Due parole restano vietate
//!
//! **«confermato»** su un evento e **«indipendenti»** sulle fonti. In un
//! ufficio conta di più: la frase la legge chi non ha guardato i contenuti, e
//! non ha modo di accorgersi della differenza fra cinque testimoni e cinque
//! copie dello stesso messaggio.

use crate::{SessionId, Timestamp};

/// Grappoli al più in una pagina.
///
/// Venticinque: un grappolo si legge, non si scorre, e un tetto più alto
/// farebbe comporre all'Hub una risposta che nessuno guarda.
pub const MAX_SHARED_CYBER_PAGE: usize = 25;

/// Indicatori al più per grappolo, su una pagina.
///
/// Chi guarda un grappolo vuole vederne la forma, non caricarne l'archivio.
pub const MAX_INDICATORS_PER_EVENT: usize = 20;

/// Un indicatore, come una postazione lo vede.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SharedIndicator {
    /// Di che genere è: CVE, dominio, indirizzo, impronta, URL.
    pub kind: String,
    /// Il valore, che è **vocabolario** e non contenuto.
    pub value: String,
}

/// Un grappolo dell'ufficio, come una postazione lo vede.
///
/// È un **evento candidato**: non dice che un attacco sia avvenuto, non dice
/// che una fonte sia attendibile, e non dice che qualcuno abbia fatto qualcosa
/// (ADR-0035, decisione 6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SharedCyberEvent {
    /// Il posto che occupa nell'elenco della sua sessione.
    ///
    /// **Un grappolo non ha un identificativo conservato**: si ricostruisce
    /// dai contenuti ogni volta, e un numero che sembrasse stabile
    /// prometterebbe qualcosa che l'archivio non tiene.
    pub position: usize,
    /// In quale sessione si è formato.
    pub session_id: SessionId,
    /// **Perché** questi contenuti stanno insieme.
    pub reason: String,
    /// Quanti contenuti.
    pub contents: usize,
    /// Quante fonti **distinte**.
    ///
    /// Non è un conteggio di testimoni: cinque canali che ripubblicano lo
    /// stesso messaggio sono cinque copie.
    pub distinct_sources: usize,
    /// Quanti contenuti sembrano ripubblicazioni di un altro del grappolo.
    pub apparent_reposts: usize,
    /// I segnali di rilevanza per l'Italia, già in parole.
    ///
    /// Vuoto quando non ce ne sono: **l'assenza non è un segnale contrario**.
    pub italy: String,
    /// I settori in cui il fatto ricadrebbe **se fosse vero**, già in parole.
    ///
    /// Non alza la gravità: il livello lo decide il motore sui dizionari
    /// (ADR-0035, decisione 10).
    pub sectors: String,
    /// Gli indicatori nominati dai contenuti del grappolo.
    pub indicators: Vec<SharedIndicator>,
    /// Quanti contenuti hanno una decisione conclusa.
    pub decided: usize,
    /// Quanti sono stati presi in carico e non conclusi.
    pub in_progress: usize,
    /// Quanti non sono mai stati guardati.
    pub untouched: usize,
    /// Quando il primo e l'ultimo contenuto sono stati pubblicati.
    pub seen_between: Option<(Timestamp, Timestamp)>,
}

impl SharedCyberEvent {
    /// Il grappolo, in una frase.
    ///
    /// **La ragione viene prima del numero**: un numero senza una ragione è un
    /// numero che non si può contestare.
    #[must_use]
    pub fn as_sentence(&self) -> String {
        let mut testo = format!(
            "{} contenuti che {}, da {} fonti distinte",
            self.contents, self.reason, self.distinct_sources
        );
        if self.apparent_reposts > 0 {
            testo.push_str(&format!(
                ", di cui {} sembrano ripubblicazioni",
                self.apparent_reposts
            ));
        }
        testo.push('.');
        if !self.italy.is_empty() {
            testo.push(' ');
            testo.push_str(&self.italy);
        }
        testo
    }

    /// Che cosa l'ufficio ha già guardato di questo grappolo.
    #[must_use]
    pub fn review_sentence(&self) -> String {
        format!(
            "{} decisi, {} in esame, {} mai guardati.",
            self.decided, self.in_progress, self.untouched
        )
    }
}

#[cfg(test)]
mod tests {
    use super::{SharedCyberEvent, SharedIndicator};
    use crate::{SessionId, Timestamp};

    fn grappolo(reposts: usize) -> SharedCyberEvent {
        SharedCyberEvent {
            position: 0,
            session_id: SessionId::new(1),
            reason: String::from("nominano CVE-2026-1234"),
            contents: 5,
            distinct_sources: 3,
            apparent_reposts: reposts,
            italy: String::from("Due contenuti nominano un dominio .it."),
            sectors: String::new(),
            indicators: vec![SharedIndicator {
                kind: String::from("cve"),
                value: String::from("CVE-2026-1234"),
            }],
            decided: 1,
            in_progress: 1,
            untouched: 3,
            seen_between: Some((Timestamp::from_millis(0), Timestamp::from_millis(10))),
        }
    }

    #[test]
    fn la_ragione_viene_prima_del_numero() {
        let frase = grappolo(0).as_sentence();
        let Some(ragione) = frase.find("nominano CVE-2026-1234") else {
            panic!("la frase non dice perché i contenuti stanno insieme: «{frase}»");
        };
        let Some(fonti) = frase.find("fonti distinte") else {
            panic!("la frase non dice quante fonti: «{frase}»");
        };
        assert!(
            ragione < fonti,
            "il numero viene prima della ragione: «{frase}»"
        );
    }

    #[test]
    fn le_ripubblicazioni_si_dicono_quando_ci_sono() {
        assert!(grappolo(2).as_sentence().contains("ripubblicazioni"));
        assert!(!grappolo(0).as_sentence().contains("ripubblicazioni"));
    }

    /// **Le due parole vietate non compaiono, nemmeno qui.**
    ///
    /// «Confermato» su un evento e «indipendenti» sulle fonti: in un ufficio
    /// la frase la legge chi non ha guardato i contenuti.
    #[test]
    fn le_due_parole_vietate_non_compaiono() {
        const QUESTO_MODULO: &str = include_str!("hub_cyber.rs");
        let Some((produzione, _)) = QUESTO_MODULO.split_once("#[cfg(test)]\nmod tests {") else {
            panic!("il modulo deve avere un blocco di prove riconoscibile");
        };
        let codice: String = produzione
            .lines()
            .filter(|riga| {
                let pulita = riga.trim_start();
                !pulita.starts_with("//") && !pulita.starts_with("///")
            })
            .collect::<Vec<_>>()
            .join("\n");

        for vietata in ["confermato", "indipendenti"] {
            assert!(
                !codice.to_lowercase().contains(vietata),
                "il modulo dice «{vietata}»: un grappolo è un evento candidato, e cinque copie \
                 non sono cinque testimoni"
            );
        }
    }

    #[test]
    fn la_revisione_si_riassume_senza_giudicare() {
        let frase = grappolo(0).review_sentence();
        assert_eq!(frase, "1 decisi, 1 in esame, 3 mai guardati.");
    }
}
