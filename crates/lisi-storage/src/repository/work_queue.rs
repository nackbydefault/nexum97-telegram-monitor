//! Che cosa aspetta una persona, letto in una interrogazione sola.
//!
//! # Perché una interrogazione e non una per sessione
//!
//! Perché la coda di lavoro attraversa **tutte** le sessioni: il lavoro non
//! fatto in una sessione chiusa è esattamente quello che si dimentica.
//! Comporla chiedendo gli alert sessione per sessione costerebbe
//! un'interrogazione per sessione, e crescerebbe con la storia dell'ufficio
//! invece che con il lavoro rimasto.
//!
//! # Che cosa questa riga NON contiene
//!
//! **Il corpo del contenuto.** La coda dice che cosa aspetta e perché; il testo
//! si legge aprendo il contenuto. Portarlo qui significherebbe caricare in
//! memoria tutti i corpi in attesa per mostrarne l'elenco.

use core::str::FromStr;

use lisi_core::model::ReviewState;
use lisi_core::{ContentId, SessionId, Timestamp};

use crate::database::Database;
use crate::error::StorageResult;
use crate::repository::instant;

/// Una riga della coda, come l'archivio la restituisce.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingWorkRow {
    /// Contenuto in attesa.
    pub content_id: ContentId,
    /// Sessione in cui è stato acquisito.
    pub session_id: SessionId,
    /// Etichetta della sessione, per chi legge.
    pub session_label: String,
    /// Nome della fonte, per chi legge.
    pub source_name: String,
    /// Livello dell'allarme, da 1 a 4.
    pub level: u8,
    /// Motivazione dell'allarme.
    pub reason: String,
    /// Quando l'allarme è stato generato.
    pub raised_at: Timestamp,
    /// Stato della revisione più recente, quando ce n'è una.
    ///
    /// `None` significa **mai toccato**, che non è la stessa cosa di
    /// [`ReviewState::New`] registrato da qualcuno.
    pub state: Option<ReviewState>,
    /// Il testo del contenuto, per mostrarne l'inizio nella coda: senza, la
    /// riga diceva fonte e livello e non di che cosa si trattasse
    /// (OPERATOR-UX-REMEDIATION-01, OS-10).
    pub body: String,
}

impl Database {
    /// Tutto ciò che ha generato un allarme, con lo stato della revisione.
    ///
    /// # Che cosa restituisce, e che cosa filtra
    ///
    /// Restituisce **tutte** le righe con un allarme, anche quelle già decise:
    /// il filtro è del dominio, non della persistenza. `ReviewState::is_decided`
    /// è l'unica autorità su che cosa sia concluso, e duplicarla in SQL
    /// significherebbe averne due che il giorno di un nuovo stato divergono.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce o se una riga contiene
    /// uno stato che il dominio non riconosce.
    pub fn pending_work(&self) -> StorageResult<Vec<PendingWorkRow>> {
        let mut statement = self.connection.prepare(
            "SELECT a.content_id,
                    c.session_id,
                    ses.label,
                    src.display_name,
                    a.level,
                    a.reason,
                    a.raised_at,
                    (SELECT r.state
                       FROM reviews r
                      WHERE r.content_id = a.content_id
                      ORDER BY r.decided_at DESC, r.id DESC
                      LIMIT 1),
                    c.body
             FROM alerts a
             JOIN contents c ON c.id = a.content_id
             JOIN sessions ses ON ses.id = c.session_id
             JOIN sources src ON src.id = c.source_id
             ORDER BY a.raised_at, a.id",
        )?;

        let rows = statement.query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, i64>(4)?,
                row.get::<_, String>(5)?,
                row.get::<_, i64>(6)?,
                row.get::<_, Option<String>>(7)?,
                row.get::<_, String>(8)?,
            ))
        })?;

        let mut pending = Vec::new();
        for row in rows {
            let (
                content_id,
                session_id,
                session_label,
                source_name,
                level,
                reason,
                raised,
                stato,
                body,
            ) = row?;

            // Lo stato si riconosce con la stessa funzione che lo riconosce
            // altrove: uno stato non riconosciuto è un errore di lettura, non
            // un valore da indovinare.
            let state = match stato {
                Some(valore) => Some(ReviewState::from_str(&valore)?),
                None => None,
            };

            pending.push(PendingWorkRow {
                content_id: ContentId::new(content_id),
                session_id: SessionId::new(session_id),
                session_label,
                source_name,
                level: u8::try_from(level).unwrap_or(0),
                reason,
                raised_at: instant(raised),
                state,
                body,
            });
        }
        Ok(pending)
    }
}

#[cfg(test)]
mod tests {
    use lisi_core::model::ReviewState;

    use crate::test_support::database;

    /// Senza allarmi la coda è vuota, e non è un errore.
    #[test]
    fn an_archive_without_alerts_has_nothing_waiting() {
        let db = database();
        let Ok(righe) = db.pending_work() else {
            panic!("la lettura deve riuscire");
        };
        assert!(righe.is_empty());
    }

    /// Lo stato assente non è `New`.
    ///
    /// «Nessuno lo ha mai toccato» e «qualcuno lo ha registrato come da
    /// esaminare» sono due fatti diversi, e la coda li ordina in modo diverso.
    #[test]
    fn a_never_touched_row_has_no_state_at_all() {
        let assente: Option<ReviewState> = None;
        assert_ne!(assente, Some(ReviewState::New));
    }
}
