//! Riscontri del dizionario.
//!
//! Il nome del modulo termina con un trattino basso perché `match` è una parola
//! chiave del linguaggio; la tabella si chiama `matches`.

use std::collections::BTreeMap;

use lisi_core::model::{AnalysisLevel, ContentMatch, MatchRange, NewMatch};
use lisi_core::text::{MatchedText, RuleCategory, RuleId};
use lisi_core::{ContentId, DomainError, MatchId, SessionId, Timestamp};
use rusqlite::Row;

use crate::database::Database;
use crate::error::{ConstraintKind, StorageError, StorageResult, constraint_kind};
use crate::repository::{instant, millis};

/// Riga grezza della tabella `matches`.
struct MatchRow {
    id: i64,
    content_id: i64,
    rule_id: String,
    rule_category: String,
    matched_text: String,
    start_offset: i64,
    end_offset: i64,
    level: i64,
    created_at: i64,
}

impl MatchRow {
    fn read(row: &Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            id: row.get(0)?,
            content_id: row.get(1)?,
            rule_id: row.get(2)?,
            rule_category: row.get(3)?,
            matched_text: row.get(4)?,
            start_offset: row.get(5)?,
            end_offset: row.get(6)?,
            level: row.get(7)?,
            created_at: row.get(8)?,
        })
    }

    fn into_domain(self) -> StorageResult<ContentMatch> {
        let (Ok(start), Ok(end)) = (
            usize::try_from(self.start_offset),
            usize::try_from(self.end_offset),
        ) else {
            return Err(StorageError::CorruptedValue(
                DomainError::InvalidMatchRange { start: 0, end: 0 },
            ));
        };

        let level =
            u8::try_from(self.level).map_err(|_| DomainError::InvalidAnalysisLevel(u8::MAX))?;

        Ok(ContentMatch {
            id: MatchId::new(self.id),
            content_id: ContentId::new(self.content_id),
            rule_id: RuleId::try_new(&self.rule_id)?,
            rule_category: RuleCategory::try_new(&self.rule_category)?,
            matched_text: MatchedText::try_new(&self.matched_text)?,
            range: MatchRange::try_new(start, end)?,
            level: AnalysisLevel::try_new(level)?,
            created_at: instant(self.created_at),
        })
    }
}

impl Database {
    /// Registra un riscontro su un contenuto.
    ///
    /// # Errori
    ///
    /// Restituisce [`StorageError::NotFound`] se il contenuto non esiste.
    pub fn insert_match(&self, entry: &NewMatch, now: Timestamp) -> StorageResult<MatchId> {
        let (Ok(start), Ok(end)) = (
            i64::try_from(entry.range.start()),
            i64::try_from(entry.range.end()),
        ) else {
            return Err(StorageError::CorruptedValue(
                DomainError::InvalidMatchRange {
                    start: entry.range.start(),
                    end: entry.range.end(),
                },
            ));
        };

        let id: i64 = self
            .connection
            .query_row(
                "INSERT INTO matches (
                     content_id, rule_id, rule_category, matched_text,
                     start_offset, end_offset, level, created_at
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
                 RETURNING id",
                rusqlite::params![
                    entry.content_id.get(),
                    entry.rule_id.as_str(),
                    entry.rule_category.as_str(),
                    entry.matched_text.as_str(),
                    start,
                    end,
                    i64::from(entry.level.get()),
                    millis(now),
                ],
                |row| row.get(0),
            )
            .map_err(|error| {
                if constraint_kind(&error) == Some(ConstraintKind::ForeignKey) {
                    StorageError::NotFound {
                        entity: "contenuto",
                        id: entry.content_id.get(),
                    }
                } else {
                    StorageError::Sqlite(error)
                }
            })?;

        Ok(MatchId::new(id))
    }

    /// Registra tutti i riscontri di un contenuto in **una** transazione.
    ///
    /// I riscontri di un contenuto sono un insieme: o ci sono tutti o nessuno.
    /// Inserirli in un ciclo di istruzioni separate lascerebbe, dopo un crash a
    /// metà, un contenuto con riscontri parziali che una ripresa non
    /// completerebbe più (li vedrebbe «già presenti»). La transazione lo
    /// impedisce.
    ///
    /// # Errori
    ///
    /// Restituisce [`StorageError::NotFound`] se il contenuto non esiste, o un
    /// errore se la scrittura non riesce. In caso di errore la transazione è
    /// annullata e nessun riscontro resta.
    pub fn insert_matches(&mut self, entries: &[NewMatch], now: Timestamp) -> StorageResult<()> {
        let transaction = self.connection.transaction()?;

        for entry in entries {
            let (Ok(start), Ok(end)) = (
                i64::try_from(entry.range.start()),
                i64::try_from(entry.range.end()),
            ) else {
                return Err(StorageError::CorruptedValue(
                    DomainError::InvalidMatchRange {
                        start: entry.range.start(),
                        end: entry.range.end(),
                    },
                ));
            };

            transaction
                .execute(
                    "INSERT INTO matches (
                         content_id, rule_id, rule_category, matched_text,
                         start_offset, end_offset, level, created_at
                     ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                    rusqlite::params![
                        entry.content_id.get(),
                        entry.rule_id.as_str(),
                        entry.rule_category.as_str(),
                        entry.matched_text.as_str(),
                        start,
                        end,
                        i64::from(entry.level.get()),
                        millis(now),
                    ],
                )
                .map_err(|error| {
                    if constraint_kind(&error) == Some(ConstraintKind::ForeignKey) {
                        StorageError::NotFound {
                            entity: "contenuto",
                            id: entry.content_id.get(),
                        }
                    } else {
                        StorageError::Sqlite(error)
                    }
                })?;
        }

        transaction.commit()?;
        Ok(())
    }

    /// Riscontri di un contenuto, in ordine di posizione nel testo.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce o se una riga contiene un
    /// valore non conforme al dominio.
    pub fn content_matches(&self, content_id: ContentId) -> StorageResult<Vec<ContentMatch>> {
        let mut statement = self.connection.prepare(
            "SELECT id, content_id, rule_id, rule_category, matched_text,
                    start_offset, end_offset, level, created_at
             FROM matches
             WHERE content_id = ?1
             ORDER BY start_offset, id",
        )?;

        let rows = statement.query_map([content_id.get()], MatchRow::read)?;

        let mut matches = Vec::new();
        for row in rows {
            matches.push(row?.into_domain()?);
        }
        Ok(matches)
    }

    /// Tutti i riscontri di una sessione, raggruppati per contenuto.
    ///
    /// # Perché in blocco e non uno per contenuto
    ///
    /// Perché il registro e l'allegato descrivono **ogni** contenuto
    /// monitorato, e chiedere i riscontri contenuto per contenuto sarebbe una
    /// interrogazione per riga: su una sessione con centinaia di contenuti è la
    /// differenza fra una lettura e centinaia.
    ///
    /// È la stessa scelta di [`Self::session_content_history`], e la stessa
    /// ragione.
    ///
    /// I contenuti senza alcun riscontro **non compaiono** nel risultato:
    /// l'assenza di una chiave significa «nessun termine trovato», che è
    /// esattamente ciò che il chiamante deve sapere.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce o se una riga contiene un
    /// valore non conforme al dominio.
    pub fn session_matches(
        &self,
        session_id: SessionId,
    ) -> StorageResult<BTreeMap<i64, Vec<ContentMatch>>> {
        let mut statement = self.connection.prepare(
            "SELECT m.id, m.content_id, m.rule_id, m.rule_category, m.matched_text,
                    m.start_offset, m.end_offset, m.level, m.created_at
             FROM matches m
             JOIN contents c ON c.id = m.content_id
             WHERE c.session_id = ?1
             ORDER BY m.content_id, m.start_offset, m.id",
        )?;

        let rows = statement.query_map([session_id.get()], MatchRow::read)?;

        let mut per_contenuto: BTreeMap<i64, Vec<ContentMatch>> = BTreeMap::new();
        for row in rows {
            let entry = row?.into_domain()?;
            per_contenuto
                .entry(entry.content_id.get())
                .or_default()
                .push(entry);
        }
        Ok(per_contenuto)
    }
}

#[cfg(test)]
mod tests {
    use lisi_core::ContentId;
    use lisi_core::model::{MatchRange, NewMatch};
    use lisi_core::text::{MatchedText, RuleCategory, RuleId};

    use crate::error::StorageError;
    use crate::test_support::{database_with_session, level, new_content, now};

    fn new_match(content_id: ContentId, start: usize, end: usize) -> NewMatch {
        let (Ok(rule_id), Ok(rule_category), Ok(matched_text), Ok(range)) = (
            RuleId::try_new("R-001"),
            RuleCategory::try_new("mobilitazione"),
            MatchedText::try_new("parola"),
            MatchRange::try_new(start, end),
        ) else {
            panic!("i valori di prova devono essere validi");
        };

        NewMatch {
            content_id,
            rule_id,
            rule_category,
            matched_text,
            range,
            level: level(2),
        }
    }

    #[test]
    fn a_match_is_written_and_read_back_unchanged() {
        let (mut database, source_id, session_id) = database_with_session();
        let Ok(insertion) = database.insert_content(&new_content(
            session_id,
            source_id,
            "1",
            "una parola sospetta",
        )) else {
            panic!("il contenuto deve potersi registrare");
        };
        let content_id = insertion.content_id();

        let Ok(id) = database.insert_match(&new_match(content_id, 4, 10), now()) else {
            panic!("il riscontro deve potersi registrare");
        };

        let Ok(matches) = database.content_matches(content_id) else {
            panic!("i riscontri devono potersi leggere");
        };
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].id, id);
        assert_eq!(matches[0].content_id, content_id);
        assert_eq!(matches[0].range.start(), 4);
        assert_eq!(matches[0].range.end(), 10);
        assert_eq!(matches[0].level.get(), 2);
        assert_eq!(matches[0].rule_id.as_str(), "R-001");
        assert_eq!(matches[0].created_at, now());
    }

    #[test]
    fn matches_are_returned_in_the_order_they_appear_in_the_text() {
        let (mut database, source_id, session_id) = database_with_session();
        let Ok(insertion) =
            database.insert_content(&new_content(session_id, source_id, "1", "testo"))
        else {
            panic!("il contenuto deve potersi registrare");
        };
        let content_id = insertion.content_id();

        for (start, end) in [(20, 25), (0, 5), (10, 12)] {
            let Ok(_) = database.insert_match(&new_match(content_id, start, end), now()) else {
                panic!("il riscontro deve potersi registrare");
            };
        }

        let Ok(matches) = database.content_matches(content_id) else {
            panic!("i riscontri devono potersi leggere");
        };
        let starts: Vec<usize> = matches.iter().map(|entry| entry.range.start()).collect();
        assert_eq!(starts, [0, 10, 20]);
    }

    #[test]
    fn a_match_on_a_missing_content_is_refused() {
        let (database, _source_id, _session_id) = database_with_session();
        assert!(matches!(
            database.insert_match(&new_match(ContentId::new(404), 0, 3), now()),
            Err(StorageError::NotFound {
                entity: "contenuto",
                id: 404
            })
        ));
    }

    #[test]
    fn a_content_without_matches_has_an_empty_list() {
        let (mut database, source_id, session_id) = database_with_session();
        let Ok(insertion) =
            database.insert_content(&new_content(session_id, source_id, "1", "testo"))
        else {
            panic!("il contenuto deve potersi registrare");
        };

        assert_eq!(
            database
                .content_matches(insertion.content_id())
                .map(|found| found.len())
                .ok(),
            Some(0)
        );
    }

    #[test]
    fn i_riscontri_di_una_sessione_si_leggono_in_blocco_raggruppati_per_contenuto() {
        let (mut database, source_id, session_id) = database_with_session();

        let mut identificativi = Vec::new();
        for (remote, testo) in [("1", "primo testo"), ("2", "secondo testo"), ("3", "terzo")] {
            let Ok(insertion) =
                database.insert_content(&new_content(session_id, source_id, remote, testo))
            else {
                panic!("il contenuto deve potersi registrare");
            };
            identificativi.push(insertion.content_id());
        }

        // Due riscontri sul primo, uno sul secondo, nessuno sul terzo.
        for (indice, start, end) in [(0_usize, 0_usize, 5_usize), (0, 6, 11), (1, 0, 7)] {
            let Ok(_) =
                database.insert_match(&new_match(identificativi[indice], start, end), now())
            else {
                panic!("il riscontro deve potersi registrare");
            };
        }

        let Ok(per_contenuto) = database.session_matches(session_id) else {
            panic!("i riscontri della sessione devono potersi leggere");
        };

        // Il terzo contenuto NON compare: l'assenza della chiave significa
        // «nessun termine trovato», ed e' esattamente cio' che il chiamante
        // deve sapere.
        assert_eq!(per_contenuto.len(), 2);
        assert_eq!(per_contenuto[&identificativi[0].get()].len(), 2);
        assert_eq!(per_contenuto[&identificativi[1].get()].len(), 1);
        assert!(!per_contenuto.contains_key(&identificativi[2].get()));
    }

    #[test]
    fn la_lettura_in_blocco_e_quella_per_contenuto_dicono_la_stessa_cosa() {
        // Sono due percorsi verso lo stesso fatto — uno per il pannello, uno
        // per i documenti — e due percorsi che divergono sono un difetto che
        // nessuna delle due prove da sola vedrebbe.
        let (mut database, source_id, session_id) = database_with_session();

        let mut identificativi = Vec::new();
        for (remote, testo) in [("1", "primo testo"), ("2", "secondo testo")] {
            let Ok(insertion) =
                database.insert_content(&new_content(session_id, source_id, remote, testo))
            else {
                panic!("il contenuto deve potersi registrare");
            };
            identificativi.push(insertion.content_id());
        }

        for (indice, start, end) in [(0_usize, 0_usize, 5_usize), (0, 6, 11), (1, 0, 7)] {
            let Ok(_) =
                database.insert_match(&new_match(identificativi[indice], start, end), now())
            else {
                panic!("il riscontro deve potersi registrare");
            };
        }

        let Ok(in_blocco) = database.session_matches(session_id) else {
            panic!("i riscontri della sessione devono potersi leggere");
        };

        for content_id in &identificativi {
            let Ok(uno_per_uno) = database.content_matches(*content_id) else {
                panic!("i riscontri del contenuto devono potersi leggere");
            };
            let dal_blocco = in_blocco
                .get(&content_id.get())
                .cloned()
                .unwrap_or_default();
            assert_eq!(
                uno_per_uno,
                dal_blocco,
                "le due letture devono dire la stessa cosa per il contenuto {}",
                content_id.get()
            );
        }
    }

    #[test]
    fn i_riscontri_di_un_altra_sessione_non_entrano_nel_blocco() {
        let (mut database, source_id, session_id) = database_with_session();

        let Ok(insertion) =
            database.insert_content(&new_content(session_id, source_id, "1", "primo testo"))
        else {
            panic!("il contenuto deve potersi registrare");
        };
        let content_id = insertion.content_id();
        let Ok(_) = database.insert_match(&new_match(content_id, 0, 5), now()) else {
            panic!("il riscontro deve potersi registrare");
        };

        // Una seconda sessione, con un contenuto e un riscontro propri.
        let Ok(altra_sessione) =
            database.insert_session(&crate::test_support::new_session(vec![source_id]), now())
        else {
            panic!("la seconda sessione deve potersi creare");
        };
        let Ok(altra) =
            database.insert_content(&new_content(altra_sessione, source_id, "9", "altro testo"))
        else {
            panic!("il contenuto deve potersi registrare");
        };
        let Ok(_) = database.insert_match(&new_match(altra.content_id(), 0, 5), now()) else {
            panic!("il riscontro deve potersi registrare");
        };

        let Ok(per_contenuto) = database.session_matches(session_id) else {
            panic!("i riscontri della sessione devono potersi leggere");
        };

        assert_eq!(per_contenuto.len(), 1);
        assert!(per_contenuto.contains_key(&content_id.get()));
        assert!(!per_contenuto.contains_key(&altra.content_id().get()));
    }
}
