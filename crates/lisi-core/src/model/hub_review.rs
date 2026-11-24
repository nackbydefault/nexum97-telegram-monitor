//! La revisione condivisa: che cosa l'elenco porta, e che cosa no
//! (TEAM-REVIEW-01, ADR-0094).
//!
//! # L'elenco si guarda, il contenuto si apre
//!
//! Un elemento della coda porta **metadati**: quale contenuto, da quale fonte,
//! con quale livello, quando, in quale stato e a quale **versione**. Non porta
//! il testo, e nemmeno un estratto: un elenco che mostrasse i testi sarebbe la
//! copia indiscriminata dell'archivio dell'Hub dalla porta di servizio (freeze
//! §7.10).
//!
//! Il contenuto si chiede **uno per volta**, e l'Hub registra chi lo ha chiesto
//! (ADR-0094, decisione 1).
//!
//! # La versione è il numero delle decisioni già prese
//!
//! Il registro delle revisioni è append-only: la versione di un contenuto è
//! **quante revisioni porta**. Una postazione che ne ha viste due scrive «mi
//! aspetto la versione 2»; se nel frattempo qualcun altro ha deciso, la
//! versione è 3 e il comando riceve un **conflitto** invece di sovrascrivere
//! (ADR-0089).

use crate::model::review::ReviewState;
use crate::text::{DisplayName, SourceIdentifier};
use crate::{ContentId, Timestamp};

/// Elementi al più in una pagina della coda di revisione.
///
/// Valore scelto da noi, **non misurato**: cinquanta righe sono più di quante
/// se ne guardino in una schermata, e un tetto più alto farebbe costruire
/// all'Hub una risposta che nessuno legge.
pub const MAX_REVIEW_QUEUE_PAGE: usize = 50;

/// Caratteri al più del testo di un contenuto consegnato per la revisione.
///
/// È lo stesso limite che il dominio impone al corpo di un contenuto: qui si
/// ripete perché ciò che arriva dalla rete **non è** ciò che abbiamo scritto
/// noi, e un frame ha comunque il proprio tetto in byte (ADR-0084).
pub const MAX_REVIEW_BODY_CHARS: usize = 8_192;

/// Un elemento della coda di revisione condivisa.
///
/// **Non porta il testo del contenuto.**
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReviewItem {
    /// Quale contenuto.
    pub content_id: ContentId,
    /// Da quale fonte, nella forma tecnica che due uffici leggono uguale.
    pub source: SourceIdentifier,
    /// Il livello attribuito dal motore, da 1 a 4.
    pub level: u8,
    /// Quando l'avviso è scattato.
    pub raised_at: Timestamp,
    /// Lo stato della revisione, se qualcuno ha già deciso.
    pub state: Option<ReviewState>,
    /// Quante revisioni sono già state registrate per questo contenuto.
    pub version: u64,
}

impl ReviewItem {
    /// Se nessuno ha ancora deciso.
    #[must_use]
    pub const fn is_untouched(&self) -> bool {
        self.state.is_none()
    }
}

/// Il contenuto consegnato per una revisione, con ciò che serve a capirlo.
///
/// Vive **in memoria**, per la durata della schermata: la postazione non lo
/// conserva (ADR-0094, decisione 1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReviewContent {
    /// Quale contenuto.
    pub content_id: ContentId,
    /// Da quale fonte.
    pub source: SourceIdentifier,
    /// Il nome leggibile della fonte, come l'ufficio l'ha chiamata.
    pub source_name: DisplayName,
    /// Quando il messaggio è stato pubblicato.
    pub published_at: Timestamp,
    /// Il testo, così com'è stato acquisito.
    pub body: String,
    /// Il livello attribuito dal motore.
    pub level: u8,
    /// Quante revisioni sono già state registrate.
    pub version: u64,
}

/// Come una postazione chiede la pagina successiva della coda.
///
/// Il cursore è l'identificativo dell'ultimo contenuto già visto: si procede in
/// avanti, e la stessa domanda dà la stessa risposta finché nulla cambia.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReviewQueueCursor {
    /// Il numero dopo il quale continuare. Zero per cominciare.
    pub after_content_id: i64,
    /// Quanti elementi al più.
    pub limit: usize,
}

impl ReviewQueueCursor {
    /// Il cursore d'inizio, con il tetto predefinito.
    #[must_use]
    pub const fn start() -> Self {
        Self {
            after_content_id: 0,
            limit: MAX_REVIEW_QUEUE_PAGE,
        }
    }

    /// Se il cursore è utilizzabile: nessun numero negativo, nessun tetto
    /// nullo, e mai oltre il tetto massimo.
    #[must_use]
    pub const fn is_usable(&self) -> bool {
        self.after_content_id >= 0 && self.limit > 0 && self.limit <= MAX_REVIEW_QUEUE_PAGE
    }

    /// Il cursore che continua dopo l'elemento indicato.
    #[must_use]
    pub const fn after(&self, content_id: i64) -> Self {
        Self {
            after_content_id: content_id,
            limit: self.limit,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{MAX_REVIEW_QUEUE_PAGE, ReviewItem, ReviewQueueCursor};
    use crate::ContentId;
    use crate::Timestamp;
    use crate::model::review::ReviewState;
    use crate::text::SourceIdentifier;

    fn elemento(state: Option<ReviewState>) -> ReviewItem {
        let Ok(source) = SourceIdentifier::try_new("@fonte") else {
            panic!("fonte");
        };
        ReviewItem {
            content_id: ContentId::new(7),
            source,
            level: 3,
            raised_at: Timestamp::from_millis(1_759_000_000_000),
            state,
            version: 0,
        }
    }

    #[test]
    fn an_item_without_a_decision_is_untouched() {
        assert!(elemento(None).is_untouched());
        assert!(!elemento(Some(ReviewState::Relevant)).is_untouched());
    }

    #[test]
    fn the_cursor_starts_at_zero_and_moves_forward() {
        let inizio = ReviewQueueCursor::start();
        assert_eq!(inizio.after_content_id, 0);
        assert_eq!(inizio.limit, MAX_REVIEW_QUEUE_PAGE);
        assert!(inizio.is_usable());

        let dopo = inizio.after(42);
        assert_eq!(dopo.after_content_id, 42);
        assert_eq!(dopo.limit, inizio.limit);
    }

    #[test]
    fn a_cursor_without_a_ceiling_is_refused() {
        let senza_tetto = ReviewQueueCursor {
            after_content_id: 0,
            limit: 0,
        };
        assert!(!senza_tetto.is_usable());

        let oltre_il_tetto = ReviewQueueCursor {
            after_content_id: 0,
            limit: MAX_REVIEW_QUEUE_PAGE + 1,
        };
        assert!(
            !oltre_il_tetto.is_usable(),
            "un client non decide quanto lavoro fa l'Hub"
        );

        let indietro = ReviewQueueCursor {
            after_content_id: -1,
            limit: 10,
        };
        assert!(!indietro.is_usable());
    }
}
