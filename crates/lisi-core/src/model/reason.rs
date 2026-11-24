//! **Una ragione operativa documentata**, e una sola nozione per tutto il
//! prodotto (PERS-01).
//!
//! # Perché questo tipo vive qui e non dentro chi lo usa
//!
//! Perché più di un atto, nel prodotto, richiede che qualcuno abbia scritto
//! **perché**: comporre un elenco di persone (ADR-0024), aprire un soggetto
//! (PERS-01), e domani gli altri atti investigativi della Fase 6.
//!
//! Fino a PERS-01 la regola viveva come due costanti private dentro il servizio
//! dei partecipanti. Ricopiarla nel nuovo servizio avrebbe prodotto **due
//! nozioni di ragione**: due soglie, due messaggi, due punti in cui cambiarla il
//! giorno in cui si decidesse che venti caratteri sono pochi. Il giorno in cui
//! una delle due si muovesse senza l'altra, nessuno se ne accorgerebbe.
//!
//! È la stessa disciplina con cui BOOK-01 ha unificato il riferimento
//! all'archivio e NOTE-01 la risoluzione dei riferimenti.
//!
//! # Che cosa questa regola non è
//!
//! **Non è una misura di qualità.** Nessun numero lo è, e una ragione lunga
//! duecento caratteri può essere vuota di contenuto quanto una di due.
//!
//! Quello che esclude è il caso concreto: il campo riempito con «ok» per
//! superare il controllo. Chi custodisce un archivio di persone risponde di
//! averlo, e «l'ho fatto perché il programma lo permetteva» non è una risposta.
//! La soglia non rende una ragione buona: rende **visibile** che qualcuno non
//! ne ha scritta una.

use crate::error::{DomainError, DomainResult};

/// Lunghezza minima di una ragione operativa.
///
/// # Perché venti e non uno
///
/// Perché uno lascerebbe passare «x». Venti caratteri non fanno una buona
/// ragione, ma rendono visibile chi non ne sta scrivendo una — ed è tutto ciò
/// che un numero può fare.
pub const MIN_REASON_CHARS: usize = 20;

/// Lunghezza massima di una ragione operativa.
///
/// # Perché un tetto
///
/// Perché la ragione finisce nell'audit e accanto al soggetto, e senza un
/// limite quei due posti diventerebbero un archivio di testi lunghi che nessuno
/// rilegge.
pub const MAX_REASON_CHARS: usize = 500;

/// Una ragione operativa documentata.
///
/// # Perché un tipo e non una `String`
///
/// Perché il tipo garantisce ciò che una convalida sparsa non garantirebbe: che
/// **ogni** atto che ne richiede una l'abbia davvero. Una funzione che prende
/// `OperationalReason` non può essere chiamata senza, e il compilatore lo dice
/// prima che il codice giri.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperationalReason(String);

impl OperationalReason {
    /// Costruisce una ragione, se è una ragione.
    ///
    /// # Errori
    ///
    /// Restituisce [`DomainError::Empty`] se il testo, tolti gli spazi ai bordi,
    /// è più corto di [`MIN_REASON_CHARS`] o più lungo di
    /// [`MAX_REASON_CHARS`].
    pub fn try_new(raw: &str) -> DomainResult<Self> {
        let trimmed = raw.trim();
        let length = trimmed.chars().count();
        if !(MIN_REASON_CHARS..=MAX_REASON_CHARS).contains(&length) {
            return Err(DomainError::Empty { field: "reason" });
        }
        Ok(Self(trimmed.to_owned()))
    }

    /// Il testo, come è stato scritto.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::{MAX_REASON_CHARS, MIN_REASON_CHARS, OperationalReason};

    /// **«ok» non è una ragione.**
    ///
    /// # Il difetto che questa prova impedisce
    ///
    /// Il campo riempito per superare il controllo. Non rende buona una ragione
    /// lunga: rende **visibile** chi non ne sta scrivendo una.
    #[test]
    fn ok_non_e_una_ragione() {
        for troppo_corta in ["", "  ", "ok", "serve", "indagine in corso"] {
            assert!(
                OperationalReason::try_new(troppo_corta).is_err(),
                "«{troppo_corta}» non e' una ragione documentata"
            );
        }
        assert!(
            OperationalReason::try_new("richiesta della procura del 3 marzo, fascicolo 123/2026")
                .is_ok()
        );
    }

    /// **Gli spazi ai bordi non contano come ragione.**
    ///
    /// # Il difetto che questa prova impedisce
    ///
    /// Venti spazi. Passerebbero un controllo sulla lunghezza grezza, e
    /// nell'audit resterebbe una riga vuota che dice che qualcuno ha motivato.
    #[test]
    fn gli_spazi_non_contano() {
        let solo_spazi = " ".repeat(MIN_REASON_CHARS + 10);
        assert!(OperationalReason::try_new(&solo_spazi).is_err());

        let con_bordi = format!("   {}   ", "richiesta della procura del 3 marzo");
        let Ok(ragione) = OperationalReason::try_new(&con_bordi) else {
            panic!("una ragione con spazi ai bordi deve essere valida");
        };
        assert_eq!(ragione.as_str(), "richiesta della procura del 3 marzo");
    }

    /// **Una ragione troppo lunga non entra.**
    ///
    /// # Perché conta
    ///
    /// Perché finisce nell'audit e accanto al soggetto, e senza tetto quei due
    /// posti diventerebbero un archivio di testi che nessuno rilegge.
    #[test]
    fn una_ragione_troppo_lunga_non_entra() {
        let lunghissima = "a".repeat(MAX_REASON_CHARS + 1);
        assert!(OperationalReason::try_new(&lunghissima).is_err());

        let al_limite = "a".repeat(MAX_REASON_CHARS);
        assert!(OperationalReason::try_new(&al_limite).is_ok());
    }

    /// **La soglia si conta in caratteri, non in byte.**
    ///
    /// # Il difetto che questa prova impedisce
    ///
    /// Una ragione **troppo corta che passa** perché contiene accenti. In UTF-8
    /// «è» occupa due byte: dieci caratteri accentati fanno venti byte, e un
    /// controllo che contasse i byte li accetterebbe come se fossero venti
    /// caratteri.
    ///
    /// Il verso conta, e la prima versione di questa prova lo aveva sbagliato:
    /// contare i byte non rende la soglia **più severa** per chi scrive in
    /// italiano — la rende **più permissiva**, che è il difetto peggiore dei
    /// due. Una prova costruita sul verso sbagliato restava verde con entrambe
    /// le implementazioni, e il suo controllo negativo lo ha mostrato.
    #[test]
    fn la_soglia_si_conta_in_caratteri() {
        // META' DELLA SOGLIA IN CARATTERI, TUTTA LA SOGLIA IN BYTE.
        //
        // E' il caso che distingue le due implementazioni: contando i
        // caratteri e' troppo corta, contando i byte passerebbe.
        let meta = MIN_REASON_CHARS / 2;
        let corta_ma_pesante = "è".repeat(meta);
        assert_eq!(corta_ma_pesante.chars().count(), meta);
        assert!(
            corta_ma_pesante.len() >= MIN_REASON_CHARS,
            "in byte raggiunge la soglia"
        );
        assert!(
            OperationalReason::try_new(&corta_ma_pesante).is_err(),
            "dieci caratteri accentati non sono venti caratteri, e contarli in byte li \
             farebbe passare"
        );

        // E UNA RAGIONE ACCENTATA ABBASTANZA LUNGA PASSA, come deve.
        let accentata = "è".repeat(MIN_REASON_CHARS);
        assert!(OperationalReason::try_new(&accentata).is_ok());
    }
}
