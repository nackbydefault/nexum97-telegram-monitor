//! I contenuti di una sessione, nella forma che il confronto di somiglianza usa.
//!
//! # Che cosa questo modulo legge, e che cosa non calcola
//!
//! Legge **corpi, istanti e indicatori**. Non confronta e non misura: il
//! confronto sta in `lisi_services::similarity`, che non conosce l'archivio ed
//! è provato da solo.
//!
//! # Perché due letture e non una per contenuto
//!
//! Perché gli indicatori di una sessione si prendono in una volta: chiederli
//! contenuto per contenuto sarebbe un'interrogazione per riga, e su una
//! sessione da cinquecento contenuti è la differenza fra due letture e
//! cinquecentouno.

use std::collections::BTreeMap;

use lisi_core::{ContentId, SessionId, Timestamp};
use rusqlite::Row;

use crate::database::Database;
use crate::error::StorageResult;
use crate::repository::instant;

/// Un contenuto, come il confronto di somiglianza lo vede.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComparableRow {
    /// Quale contenuto.
    pub content_id: ContentId,
    /// Il corpo, immutato.
    pub body: String,
    /// Istante di pubblicazione dichiarato dalla fonte.
    pub published_at: Timestamp,
}

impl ComparableRow {
    fn read(row: &Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            content_id: ContentId::new(row.get(0)?),
            body: row.get(1)?,
            published_at: instant(row.get(2)?),
        })
    }
}

impl Database {
    /// I contenuti di una sessione, con corpo e istante di pubblicazione.
    ///
    /// Vengono restituite **al più `limit + 1`** righe: la riga in più è il
    /// modo con cui chi chiama scopre che il limite è stato superato, e a quel
    /// punto rifiuta il confronto invece di eseguirlo su una parte.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce.
    pub fn session_comparable_contents(
        &self,
        session_id: SessionId,
        limit: u32,
    ) -> StorageResult<Vec<ComparableRow>> {
        let mut statement = self.connection.prepare(
            "SELECT id, body, published_at
               FROM contents
              WHERE session_id = ?1
              ORDER BY published_at, id
              LIMIT ?2",
        )?;

        let rows = statement.query_map(
            rusqlite::params![session_id.get(), i64::from(limit) + 1],
            ComparableRow::read,
        )?;

        let mut contenuti = Vec::new();
        for row in rows {
            contenuti.push(row?);
        }
        Ok(contenuti)
    }

    /// Gli indicatori di tutti i contenuti di una sessione, in una lettura.
    ///
    /// I contenuti senza indicatori **non compaiono**: l'assenza di una chiave
    /// significa «nessun indicatore», che è esattamente ciò che il chiamante
    /// deve sapere.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce.
    pub fn session_indicators(
        &self,
        session_id: SessionId,
    ) -> StorageResult<BTreeMap<i64, Vec<(String, String)>>> {
        let mut statement = self.connection.prepare(
            "SELECT ci.content_id, ci.kind, ci.value
               FROM content_indicators ci
               JOIN contents c ON c.id = ci.content_id
              WHERE c.session_id = ?1
              ORDER BY ci.content_id, ci.kind, ci.value",
        )?;

        let rows = statement.query_map([session_id.get()], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
            ))
        })?;

        let mut per_contenuto: BTreeMap<i64, Vec<(String, String)>> = BTreeMap::new();
        for row in rows {
            let (content_id, kind, value) = row?;
            per_contenuto
                .entry(content_id)
                .or_default()
                .push((kind, value));
        }
        Ok(per_contenuto)
    }
}

#[cfg(test)]
mod tests {
    use lisi_core::model::{CyberIndicator, IndicatorKind};
    use lisi_core::{SessionId, SourceId, Timestamp};

    use crate::Database;
    use crate::test_support::{database_with_session, new_content};

    const ORA_ZERO: i64 = 1_700_000_000_000;

    fn istante(millis: i64) -> Timestamp {
        Timestamp::from_millis(millis)
    }

    /// Inserisce un contenuto pubblicato all'istante indicato.
    fn contenuto(
        database: &mut Database,
        session_id: SessionId,
        source_id: SourceId,
        remote: &str,
        corpo: &str,
        pubblicato: i64,
        indicatori: &[(IndicatorKind, &str)],
    ) {
        let mut bozza = new_content(session_id, source_id, remote, corpo);
        bozza.published_at = istante(pubblicato);
        bozza.acquired_at = istante(pubblicato);

        let Ok(inserimento) = database.insert_content(&bozza) else {
            panic!("il contenuto deve potersi registrare");
        };

        if !indicatori.is_empty() {
            let voci: Vec<CyberIndicator> = indicatori
                .iter()
                .map(|(kind, value)| CyberIndicator {
                    kind: *kind,
                    value: (*value).to_owned(),
                })
                .collect();
            let Ok(_) = database.insert_content_indicators(inserimento.content_id(), &voci) else {
                panic!("gli indicatori devono potersi registrare");
            };
        }
    }

    #[test]
    fn i_contenuti_arrivano_in_ordine_di_pubblicazione() {
        let (mut database, source, session) = database_with_session();
        contenuto(
            &mut database,
            session,
            source,
            "m1",
            "il secondo per data",
            ORA_ZERO + 1_000,
            &[],
        );
        contenuto(
            &mut database,
            session,
            source,
            "m2",
            "il primo per data",
            ORA_ZERO,
            &[],
        );

        let Ok(righe) = database.session_comparable_contents(session, 100) else {
            panic!("la lettura deve riuscire");
        };

        assert_eq!(righe.len(), 2);
        assert_eq!(righe[0].body, "il primo per data");
        assert_eq!(righe[0].published_at, istante(ORA_ZERO));
    }

    /// **Superato il limite si restituisce una riga in più**, così chi chiama
    /// sa di non avere tutto e rifiuta il confronto.
    #[test]
    fn oltre_il_limite_si_restituisce_una_riga_in_piu() {
        let (mut database, source, session) = database_with_session();
        for i in 0..5 {
            contenuto(
                &mut database,
                session,
                source,
                &format!("m{i}"),
                "un corpo qualunque",
                ORA_ZERO + i64::from(i),
                &[],
            );
        }

        let Ok(righe) = database.session_comparable_contents(session, 3) else {
            panic!("la lettura deve riuscire");
        };

        assert_eq!(righe.len(), 4, "tre righe piu' quella che rivela il taglio");
    }

    /// Gli indicatori arrivano raggruppati per contenuto, in una lettura.
    #[test]
    fn gli_indicatori_arrivano_raggruppati_per_contenuto() {
        let (mut database, source, session) = database_with_session();
        contenuto(
            &mut database,
            session,
            source,
            "m1",
            "con due indicatori",
            ORA_ZERO,
            &[
                (IndicatorKind::Cve, "cve-2026-1234"),
                (IndicatorKind::Domain, "a.example"),
            ],
        );
        contenuto(
            &mut database,
            session,
            source,
            "m2",
            "senza indicatori",
            ORA_ZERO + 1,
            &[],
        );

        let Ok(per_contenuto) = database.session_indicators(session) else {
            panic!("la lettura deve riuscire");
        };

        assert_eq!(
            per_contenuto.len(),
            1,
            "il contenuto senza indicatori non compare"
        );
        let Some(voci) = per_contenuto.values().next() else {
            panic!("il contenuto con indicatori deve esserci");
        };
        assert_eq!(voci.len(), 2);
    }

    /// Una sessione senza contenuti non ha indicatori, e non è un errore.
    #[test]
    fn una_sessione_vuota_non_ha_indicatori() {
        let (database, _, session) = database_with_session();

        assert_eq!(
            database.session_indicators(session).map(|m| m.len()).ok(),
            Some(0)
        );
        assert_eq!(
            database
                .session_comparable_contents(session, 10)
                .map(|righe| righe.len())
                .ok(),
            Some(0)
        );
    }
}
