//! Fotografie del contesto (CTX-06).
//!
//! # Perché la scrittura è una transazione
//!
//! Perché una fotografia è **un atto**, e le sue righe ne fanno parte. Un atto
//! registrato senza le sue righe non sarebbe una fotografia a metà: sarebbe una
//! fotografia che dichiara di aver visto qualcosa e non lo porta, con
//! un'impronta che non corrisponde a nulla.
//!
//! # Perché non esiste alcuna scrittura oltre l'inserimento
//!
//! Perché una fotografia è immutabile, e l'archivio lo impone con quattro
//! trigger. Una funzione di aggiornamento non fallirebbe qui: fallirebbe in
//! SQLite, con un messaggio che nessuno si aspetta. Non esistendo, non c'è
//! nulla da chiamare.

use std::collections::BTreeMap;

use lisi_core::digest::Sha256Digest;
use lisi_core::model::content_history::VersionChange;
use lisi_core::model::context_snapshot::{
    ContextSnapshot, NewContextSnapshot, SnapshotComparison, SnapshotMessage,
};
use lisi_core::model::context_state::Divergence;
use lisi_core::text::{Actor, Note};
use lisi_core::{ContentId, ContextSnapshotId, SessionId, SourceId};
use rusqlite::Row;

use crate::database::Database;
use crate::error::{StorageError, StorageResult};
use crate::repository::{instant, millis};

/// Come la relazione fra due testi si scrive nell'archivio.
///
/// # Perché un'etichetta e non l'indice della variante
///
/// Perché un indice cambia significato il giorno in cui qualcuno riordina
/// l'enumerazione, e le fotografie già scritte comincerebbero a dire un'altra
/// cosa senza che nulla cambi nell'archivio.
const fn change_label(change: VersionChange) -> &'static str {
    match change {
        VersionChange::Identical => "identico",
        VersionChange::Appended => "aggiunto",
        VersionChange::Truncated => "accorciato",
        VersionChange::Surrounded => "attorno",
        VersionChange::Rewritten => "riscritto",
    }
}

/// L'etichetta letta all'indietro.
fn change_from_label(raw: &str) -> StorageResult<VersionChange> {
    match raw {
        "identico" => Ok(VersionChange::Identical),
        "aggiunto" => Ok(VersionChange::Appended),
        "accorciato" => Ok(VersionChange::Truncated),
        "attorno" => Ok(VersionChange::Surrounded),
        "riscritto" => Ok(VersionChange::Rewritten),
        _ => Err(StorageError::CorruptedRow {
            detail: "una fotografia porta una relazione fra versioni che non \u{e8} \
                     riconoscibile",
        }),
    }
}

/// Come l'esito del confronto si scrive nell'archivio.
const fn divergence_label(divergence: Divergence) -> &'static str {
    match divergence {
        Divergence::None => "coincidono",
        Divergence::Declared { .. } => "differiscono-dichiarata",
        Divergence::Undeclared => "differiscono-non-dichiarata",
    }
}

/// Riga grezza della tabella `context_snapshots`.
struct SnapshotRow {
    id: i64,
    content_id: i64,
    source_id: i64,
    taken_by: String,
    reason: String,
    taken_at: i64,
    observed_at: i64,
    anchor_remote_message_id: String,
    anchor_digest: String,
    comparison_change: Option<String>,
    comparison_divergence: Option<String>,
    declared_edit_at: Option<i64>,
    integrity: String,
}

impl SnapshotRow {
    fn read(row: &Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            id: row.get(0)?,
            content_id: row.get(1)?,
            source_id: row.get(2)?,
            taken_by: row.get(3)?,
            reason: row.get(4)?,
            taken_at: row.get(5)?,
            observed_at: row.get(6)?,
            anchor_remote_message_id: row.get(7)?,
            anchor_digest: row.get(8)?,
            comparison_change: row.get(9)?,
            comparison_divergence: row.get(10)?,
            declared_edit_at: row.get(11)?,
            integrity: row.get(12)?,
        })
    }

    fn into_domain(self, messages: Vec<SnapshotMessage>) -> StorageResult<ContextSnapshot> {
        let declared = self.declared_edit_at.map(instant);

        // IL CONFRONTO SI RICOSTRUISCE, E NON SI RIFA'.
        //
        // Le due colonne sono NULL insieme o valorizzate insieme: una sola
        // valorizzata e' un archivio che non dice piu' che cosa fu osservato, e
        // indovinare l'altra meta' sarebbe scrivere un'osservazione che nessuno
        // fece.
        let comparison = match (self.comparison_change, self.comparison_divergence) {
            (None, None) => None,
            (Some(change), Some(divergence)) => {
                let divergence = match divergence.as_str() {
                    "coincidono" => Divergence::None,
                    "differiscono-non-dichiarata" => Divergence::Undeclared,
                    "differiscono-dichiarata" => match declared {
                        Some(at) => Divergence::Declared { at },
                        // Una modifica dichiarata senza il suo istante non e'
                        // ricostruibile: l'archivio dice una cosa a meta'.
                        None => {
                            return Err(StorageError::CorruptedRow {
                                detail: "una fotografia dichiara una modifica senza l'istante \
                                         in cui sarebbe avvenuta",
                            });
                        }
                    },
                    _ => {
                        return Err(StorageError::CorruptedRow {
                            detail: "una fotografia porta un esito del confronto che non \u{e8} \
                                     riconoscibile",
                        });
                    }
                };
                Some(SnapshotComparison {
                    change: change_from_label(&change)?,
                    divergence,
                })
            }
            _ => {
                return Err(StorageError::CorruptedRow {
                    detail: "una fotografia porta un confronto scritto a met\u{e0}: o entrambe \
                             le colonne sono assenti, o entrambe sono valorizzate",
                });
            }
        };

        Ok(ContextSnapshot {
            id: ContextSnapshotId::new(self.id),
            content_id: ContentId::new(self.content_id),
            source_id: SourceId::new(self.source_id),
            taken_by: Actor::try_new(&self.taken_by)?,
            reason: Note::try_new(&self.reason)?,
            taken_at: instant(self.taken_at),
            observed_at: instant(self.observed_at),
            anchor_remote_message_id: self.anchor_remote_message_id,
            anchor_digest: Sha256Digest::from_hex(&self.anchor_digest)?,
            comparison,
            declared_edit_at: declared,
            messages,
            integrity: Sha256Digest::from_hex(&self.integrity)?,
        })
    }
}

impl Database {
    /// Conserva una fotografia del contesto.
    ///
    /// L'atto e le sue righe entrano in **una transazione**: una fotografia
    /// senza le sue righe dichiarerebbe di aver visto qualcosa senza portarlo,
    /// e la sua impronta non corrisponderebbe a nulla.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la scrittura non riesce o se il contenuto o la
    /// fonte non esistono.
    pub fn insert_context_snapshot(
        &mut self,
        snapshot: &NewContextSnapshot,
    ) -> StorageResult<ContextSnapshotId> {
        let transazione = self.connection.transaction()?;

        let comparison = snapshot.comparison();
        transazione.execute(
            "INSERT INTO context_snapshots (
                 content_id, source_id, taken_by, reason, taken_at, observed_at,
                 anchor_remote_message_id, anchor_digest, comparison_change,
                 comparison_divergence, declared_edit_at, integrity
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            rusqlite::params![
                snapshot.content_id().get(),
                snapshot.source_id().get(),
                snapshot.taken_by().as_str(),
                snapshot.reason().as_str(),
                millis(snapshot.taken_at()),
                millis(snapshot.observed_at()),
                snapshot.anchor_remote_message_id(),
                snapshot.anchor_digest().as_str(),
                comparison.map(|confronto| change_label(confronto.change)),
                comparison.map(|confronto| divergence_label(confronto.divergence)),
                snapshot.declared_edit_at().map(millis),
                snapshot.integrity().as_str(),
            ],
        )?;

        let id = transazione.last_insert_rowid();

        for (posizione, messaggio) in snapshot.messages().iter().enumerate() {
            // La posizione e' l'ordine in cui i messaggi furono visti, e
            // l'ordine e' il discorso: conservarlo e' conservare cio' che si
            // stava leggendo.
            let posizione = i64::try_from(posizione).map_err(|_| StorageError::CorruptedRow {
                detail: "una fotografia porta pi\u{f9} messaggi di quanti se ne possano numerare",
            })?;
            transazione.execute(
                "INSERT INTO context_snapshot_messages (
                     snapshot_id, position, remote_message_id, published_at, body,
                     author_sentence, relations_sentence, is_anchor
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                rusqlite::params![
                    id,
                    posizione,
                    messaggio.remote_message_id,
                    millis(messaggio.published_at),
                    messaggio.body,
                    messaggio.author_sentence,
                    messaggio.relations_sentence,
                    i64::from(messaggio.is_anchor),
                ],
            )?;
        }

        transazione.commit()?;
        Ok(ContextSnapshotId::new(id))
    }

    /// Le fotografie prese di un contenuto, dalla più recente.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce.
    pub fn context_snapshots_of(
        &self,
        content_id: ContentId,
    ) -> StorageResult<Vec<ContextSnapshot>> {
        let mut statement = self.connection.prepare(
            "SELECT id, content_id, source_id, taken_by, reason, taken_at, observed_at,
                    anchor_remote_message_id, anchor_digest, comparison_change,
                    comparison_divergence, declared_edit_at, integrity
             FROM context_snapshots
             WHERE content_id = ?1
             ORDER BY taken_at DESC, id DESC",
        )?;
        let righe: Vec<SnapshotRow> = statement
            .query_map([content_id.get()], SnapshotRow::read)?
            .collect::<rusqlite::Result<Vec<_>>>()?;

        let mut fotografie = Vec::with_capacity(righe.len());
        for riga in righe {
            let messaggi = self.context_snapshot_messages(riga.id)?;
            fotografie.push(riga.into_domain(messaggi)?);
        }
        Ok(fotografie)
    }

    /// Quante fotografie ha ciascun contenuto di una sessione.
    ///
    /// # Perché i conteggi e non le fotografie
    ///
    /// Perché un documento rappresenta **tutti** i contenuti di una sessione, e
    /// la maggioranza non ha alcuna fotografia. Leggere le righe di tutti per
    /// scoprire che quasi nessuno ne ha costerebbe i corpi di ogni contorno per
    /// dire «niente» — lo stesso motivo per cui lo Storico legge i riassunti e
    /// i corpi solo quando un contenuto si apre (`session_content_history`).
    ///
    /// I contenuti senza fotografie **non compaiono**: una chiave significa che
    /// qualcosa c'è.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce.
    pub fn session_context_snapshot_counts(
        &self,
        session_id: SessionId,
    ) -> StorageResult<BTreeMap<i64, usize>> {
        let mut statement = self.connection.prepare(
            "SELECT s.content_id, COUNT(*)
             FROM context_snapshots s
             JOIN contents c ON c.id = s.content_id
             WHERE c.session_id = ?1
             GROUP BY s.content_id",
        )?;

        let righe = statement.query_map([session_id.get()], |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?))
        })?;

        let mut per_contenuto = BTreeMap::new();
        for riga in righe {
            let (content_id, quante) = riga?;
            per_contenuto.insert(content_id, usize::try_from(quante).unwrap_or(usize::MAX));
        }
        Ok(per_contenuto)
    }

    /// Le righe di una fotografia, nell'ordine in cui furono viste.
    fn context_snapshot_messages(&self, snapshot_id: i64) -> StorageResult<Vec<SnapshotMessage>> {
        let mut statement = self.connection.prepare(
            "SELECT remote_message_id, published_at, body, author_sentence,
                    relations_sentence, is_anchor
             FROM context_snapshot_messages
             WHERE snapshot_id = ?1
             ORDER BY position ASC",
        )?;
        let messaggi = statement
            .query_map([snapshot_id], |row| {
                Ok(SnapshotMessage {
                    remote_message_id: row.get(0)?,
                    published_at: instant(row.get::<_, i64>(1)?),
                    body: row.get(2)?,
                    author_sentence: row.get(3)?,
                    relations_sentence: row.get(4)?,
                    is_anchor: row.get::<_, i64>(5)? != 0,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(messaggi)
    }
}

#[cfg(test)]
mod tests {
    use lisi_core::Timestamp;
    use lisi_core::model::content_history::VersionChange;
    use lisi_core::model::context_snapshot::{
        NewContextSnapshot, SnapshotComparison, SnapshotMessage,
    };
    use lisi_core::model::context_state::Divergence;
    use lisi_core::text::Note;

    use crate::test_support::{actor, database_with_session, new_content};

    const ORA: i64 = 1_700_000_000_000;

    fn nota(testo: &str) -> Note {
        let Ok(nota) = Note::try_new(testo) else {
            panic!("la nota di prova deve essere valida");
        };
        nota
    }

    fn riga(id: &str, testo: &str, ancora: bool) -> SnapshotMessage {
        SnapshotMessage {
            remote_message_id: String::from(id),
            published_at: Timestamp::from_millis(ORA),
            body: String::from(testo),
            author_sentence: String::from("Scritto da qualcuno."),
            relations_sentence: if ancora {
                Some(String::from("In risposta al messaggio 499."))
            } else {
                None
            },
            is_anchor: ancora,
        }
    }

    /// Un archivio con un contenuto, e una fotografia pronta da conservare.
    fn archivio_e_fotografia() -> (crate::Database, NewContextSnapshot) {
        let (mut database, source_id, session_id) = database_with_session();
        let Ok(inserimento) =
            database.insert_content(&new_content(session_id, source_id, "500", "il testo"))
        else {
            panic!("il contenuto deve potersi registrare");
        };

        let Ok(fotografia) = NewContextSnapshot::prepare(
            inserimento.content_id(),
            source_id,
            &actor("operatore.prova"),
            &nota("serve al fascicolo"),
            Timestamp::from_millis(ORA + 90_000),
            Timestamp::from_millis(ORA + 30_000),
            "500",
            "il testo",
            Some(SnapshotComparison {
                change: VersionChange::Appended,
                divergence: Divergence::Undeclared,
            }),
            None,
            vec![
                riga("499", "prima", false),
                riga("500", "il testo, e altro", true),
            ],
        ) else {
            panic!("la fotografia deve potersi preparare");
        };

        (database, fotografia)
    }

    /// **Una fotografia scritta si rilegge identica.**
    #[test]
    fn una_fotografia_si_rilegge_identica() {
        let (mut database, fotografia) = archivio_e_fotografia();
        let Ok(id) = database.insert_context_snapshot(&fotografia) else {
            panic!("la fotografia deve potersi scrivere");
        };

        let Ok(rilette) = database.context_snapshots_of(fotografia.content_id()) else {
            panic!("le fotografie devono potersi rileggere");
        };
        assert_eq!(rilette.len(), 1);

        let riletta = &rilette[0];
        assert_eq!(riletta.id, id);
        assert_eq!(riletta.taken_by.as_str(), "operatore.prova");
        assert_eq!(riletta.reason.as_str(), "serve al fascicolo");
        assert_eq!(riletta.anchor_remote_message_id, "500");
        assert_eq!(riletta.taken_at.as_millis(), ORA + 90_000);
        assert_eq!(riletta.observed_at.as_millis(), ORA + 30_000);
        assert_eq!(riletta.integrity, *fotografia.integrity());

        // L'ordine e' quello in cui i messaggi furono visti.
        assert_eq!(riletta.messages.len(), 2);
        assert_eq!(riletta.messages[0].remote_message_id, "499");
        assert_eq!(riletta.messages[1].remote_message_id, "500");
        assert!(riletta.messages[1].is_anchor);
        assert_eq!(
            riletta.messages[1].relations_sentence.as_deref(),
            Some("In risposta al messaggio 499.")
        );
        assert_eq!(riletta.messages[0].relations_sentence, None);

        // Il confronto torna quello che fu osservato.
        let Some(confronto) = riletta.comparison else {
            panic!("il confronto deve essere conservato");
        };
        assert_eq!(confronto.change, VersionChange::Appended);
        assert_eq!(confronto.divergence, Divergence::Undeclared);

        // E si verifica.
        assert!(riletta.verify());
    }

    /// **Una fotografia è immutabile: l'archivio rifiuta.**
    ///
    /// # Il difetto che questa prova impedisce
    ///
    /// Che una fotografia modificabile dica domani ciò che si vuole che dica, e
    /// che l'impronta registrata non valga più niente. Non è una convenzione da
    /// ricordare: è l'archivio che rifiuta.
    #[test]
    fn una_fotografia_conservata_non_si_modifica_ne_si_cancella() {
        let (mut database, fotografia) = archivio_e_fotografia();
        let Ok(id) = database.insert_context_snapshot(&fotografia) else {
            panic!("la fotografia deve potersi scrivere");
        };

        let modifica = database.connection.execute(
            "UPDATE context_snapshots SET reason = 'altra' WHERE id = ?1",
            [id.get()],
        );
        assert!(modifica.is_err(), "l'archivio deve rifiutare la modifica");

        let cancellazione = database
            .connection
            .execute("DELETE FROM context_snapshots WHERE id = ?1", [id.get()]);
        assert!(
            cancellazione.is_err(),
            "l'archivio deve rifiutare la cancellazione"
        );

        let modifica_riga = database.connection.execute(
            "UPDATE context_snapshot_messages SET body = 'altro' WHERE snapshot_id = ?1",
            [id.get()],
        );
        assert!(
            modifica_riga.is_err(),
            "anche le righe di una fotografia sono immutabili"
        );

        let cancellazione_riga = database.connection.execute(
            "DELETE FROM context_snapshot_messages WHERE snapshot_id = ?1",
            [id.get()],
        );
        assert!(
            cancellazione_riga.is_err(),
            "anche le righe di una fotografia non si cancellano"
        );
    }

    /// **Una fotografia senza confronto si rilegge senza confronto.**
    ///
    /// «Non confrontato» e «confrontato e coincidevano» sono due esiti diversi,
    /// e devono restare tali anche dopo un giro nell'archivio (ADR-0053).
    #[test]
    fn un_confronto_assente_torna_assente() {
        let (mut database, _) = archivio_e_fotografia();
        let (source_id, session_id) = {
            let Ok(fonti) = database.sources() else {
                panic!("le fonti devono potersi leggere");
            };
            let Ok(sessioni) = database.sessions() else {
                panic!("le sessioni devono potersi leggere");
            };
            (fonti[0].id, sessioni[0].id)
        };
        let Ok(inserimento) =
            database.insert_content(&new_content(session_id, source_id, "600", "altro"))
        else {
            panic!("il contenuto deve potersi registrare");
        };

        let Ok(senza_confronto) = NewContextSnapshot::prepare(
            inserimento.content_id(),
            source_id,
            &actor("operatore.prova"),
            &nota("l'ancora non era tornata"),
            Timestamp::from_millis(ORA),
            Timestamp::from_millis(ORA),
            "600",
            "altro",
            None,
            None,
            vec![riga("599", "prima", false)],
        ) else {
            panic!("la fotografia deve potersi preparare");
        };

        let Ok(_) = database.insert_context_snapshot(&senza_confronto) else {
            panic!("la fotografia deve potersi scrivere");
        };
        let Ok(rilette) = database.context_snapshots_of(inserimento.content_id()) else {
            panic!("le fotografie devono potersi rileggere");
        };
        assert_eq!(rilette[0].comparison, None);
        assert!(rilette[0].verify());
    }

    /// **Un contenuto senza fotografie non ne restituisce nessuna.**
    #[test]
    fn un_contenuto_senza_fotografie_ne_ha_zero() {
        let (mut database, source_id, session_id) = database_with_session();
        let Ok(inserimento) =
            database.insert_content(&new_content(session_id, source_id, "700", "niente"))
        else {
            panic!("il contenuto deve potersi registrare");
        };
        let Ok(rilette) = database.context_snapshots_of(inserimento.content_id()) else {
            panic!("la lettura deve riuscire");
        };
        assert!(rilette.is_empty());
    }
}
